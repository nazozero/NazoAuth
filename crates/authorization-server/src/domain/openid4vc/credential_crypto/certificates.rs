use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialTrustError, VcIssuerTrustPolicy,
};
use nazo_key_management::{KeyManager, Openid4vcCertificates, Openid4vcSigningLease};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::super::crypto_helpers::{parse_pem_certificates, parse_x509, verify_openid4vc_chain};
use super::Openid4vcCredentialCrypto;

const MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS: usize = 4;

/// Project metadata only after the format verifier authenticates this issuer
/// chain. Do not append loaded anchors or perform a second signature check.
pub(super) fn issuer_authority_key_identifiers(
    certificates: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, CredentialTrustError> {
    let mut identifiers: Vec<Vec<u8>> = Vec::new();
    for der in certificates {
        let (_, certificate) = parse_x509(der, "credential issuer certificate")
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        append_authority_key_identifiers(&certificate, &mut identifiers);
    }
    Ok(identifiers)
}

pub(super) fn append_authority_key_identifiers(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    identifiers: &mut Vec<Vec<u8>>,
) {
    for extension in certificate.extensions() {
        if let x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(authority) =
            extension.parsed_extension()
            && let Some(identifier) = authority.key_identifier.as_ref()
            && !identifiers
                .iter()
                .any(|existing| existing.as_slice() == identifier.0)
        {
            identifiers.push(identifier.0.to_vec());
        }
    }
}

pub fn parse_scoped_credential_trust_anchors(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let certificates = parse_pem_certificates(pem.as_bytes())?;
    if certificates.is_empty() || certificates.len() > MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS {
        anyhow::bail!(
            "OpenID4VC scoped credential trust must contain 1 through {MAX_SCOPED_CREDENTIAL_TRUST_ANCHORS} certificates"
        );
    }
    let now = x509_parser::time::ASN1Time::from_timestamp(jiff::Timestamp::now().as_second())?;
    let mut anchors = Vec::with_capacity(certificates.len());
    for der in certificates {
        let (remainder, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|error| {
            anyhow::anyhow!("failed to parse OpenID4VC scoped credential trust anchor: {error}")
        })?;
        if !remainder.is_empty() || !parsed.is_ca() || !parsed.validity().is_valid_at(now) {
            anyhow::bail!(
                "OpenID4VC scoped credential trust anchors must be currently valid CA certificates"
            );
        }
        if anchors.contains(&der) {
            anyhow::bail!("OpenID4VC scoped credential trust anchors must be unique");
        }
        anchors.push(der);
    }
    Ok(anchors)
}

/// Request-local certificate projection, tied to the exact signing generation.
/// Prepare after dependency I/O and consume at the signing boundary.
pub(crate) struct Openid4vcSigningMaterial {
    pub(super) lease: Openid4vcSigningLease,
    certificate_chain_len: usize,
    trust_anchor_index: usize,
}

impl Openid4vcCredentialCrypto {
    pub fn new_with_policies(
        keyset: KeyManager,
        issuer_trust_policy: VcIssuerTrustPolicy,
        revocation_policy: crate::policy::Openid4vcRevocationPolicy,
    ) -> anyhow::Result<Self> {
        let material = keyset.openid4vc_certificates().ok_or_else(|| {
            anyhow::anyhow!("OpenID4VC managed certificate material is unavailable")
        })?;
        verify_openid4vc_chain(
            material.certificate_chain_der(),
            material.trust_anchors_der(),
        )?;
        Ok(Self {
            keyset,
            issuer_trust_policy,
            revocation_policy,
            mdoc_status_issuance: super::MdocStatusIssuancePolicy::Disabled,
            status_resolver: None,
        })
    }

    pub(crate) fn prepare_signing(&self) -> anyhow::Result<Openid4vcSigningLease> {
        self.keyset.prepare_openid4vc_signing()
    }

    pub(crate) fn signing_material(
        &self,
        lease: Openid4vcSigningLease,
    ) -> anyhow::Result<Openid4vcSigningMaterial> {
        signing_material(lease)
    }

    pub(super) fn credential_trust_material(
        &self,
        additional: &[Vec<u8>],
    ) -> Result<Arc<Openid4vcCertificates>, CredentialTrustError> {
        let material = self
            .keyset
            .openid4vc_certificates()
            .ok_or(CredentialTrustError::UntrustedIssuer)?;
        if material.trust_anchors_der().is_empty() {
            return Err(CredentialTrustError::UntrustedIssuer);
        }
        for anchor in additional {
            let (_, certificate) = x509_parser::parse_x509_certificate(anchor)
                .map_err(|_| CredentialTrustError::InvalidEncoding)?;
            if !certificate.is_ca() {
                return Err(CredentialTrustError::UntrustedIssuer);
            }
        }
        Ok(material)
    }

    pub(super) fn current_revocation_policy(&self) -> CertificateRevocationPolicy {
        match self.revocation_policy {
            crate::policy::Openid4vcRevocationPolicy::Disabled => {
                CertificateRevocationPolicy::disabled()
            }
            mode => self
                .keyset
                .openid4vc_revocation_snapshot()
                .map(|snapshot| match mode {
                    crate::policy::Openid4vcRevocationPolicy::Optional => {
                        CertificateRevocationPolicy::optional_prepared(snapshot)
                    }
                    crate::policy::Openid4vcRevocationPolicy::Required => {
                        CertificateRevocationPolicy::required_prepared(snapshot)
                    }
                    crate::policy::Openid4vcRevocationPolicy::Disabled => unreachable!(),
                })
                .unwrap_or_else(CertificateRevocationPolicy::required_without_snapshot),
        }
    }
}

impl Openid4vcSigningMaterial {
    pub(super) fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.lease.certificates().certificate_chain_der()[..self.certificate_chain_len]
    }

    pub(super) fn leaf_der(&self) -> &[u8] {
        &self.certificate_chain_der()[0]
    }

    pub(super) fn trust_anchor_der(&self) -> &[u8] {
        &self.lease.certificates().trust_anchors_der()[self.trust_anchor_index]
    }

    pub(super) fn x5c(&self) -> Vec<String> {
        self.certificate_chain_der()
            .iter()
            .map(|certificate| STANDARD.encode(certificate))
            .collect()
    }

    pub(crate) fn x509_hash_client_id(&self) -> String {
        format!(
            "x509_hash:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(self.leaf_der()))
        )
    }

    pub(crate) fn x509_san_dns_client_id(&self) -> anyhow::Result<String> {
        let (_, certificate) = parse_x509(self.leaf_der(), "OpenID4VC signing leaf")?;
        let dns_name = certificate
            .subject_alternative_name()?
            .into_iter()
            .flat_map(|extension| extension.value.general_names.iter())
            .find_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(name) => Some(*name),
                _ => None,
            })
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("OpenID4VP signing certificate has no DNS SAN"))?;
        Ok(format!("x509_san_dns:{dns_name}"))
    }
}

fn signing_material(lease: Openid4vcSigningLease) -> anyhow::Result<Openid4vcSigningMaterial> {
    let certificates = lease.certificates().certificate_chain_der();
    if certificates.is_empty() {
        anyhow::bail!("OpenID4VC signing certificate chain is empty");
    }
    let trust_anchors = lease.certificates().trust_anchors_der();
    let authenticated = verify_openid4vc_chain(certificates, trust_anchors)?;
    let anchor_index = trust_anchors
        .iter()
        .position(|anchor| anchor.as_slice() == authenticated)
        .expect("verified path returns an explicit loaded trust anchor");
    // The path verifier rejects every presented configured anchor except its
    // authenticated terminal root. Exclude that root from the wire chain.
    let certificate_chain_len = certificates.len()
        - usize::from(
            certificates
                .last()
                .is_some_and(|der| der.as_slice() == authenticated),
        );
    Ok(Openid4vcSigningMaterial {
        lease,
        certificate_chain_len,
        trust_anchor_index: anchor_index,
    })
}
