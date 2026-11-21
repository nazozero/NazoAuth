//! Offline-signed CRLs are public deployment artifacts. Every response binds
//! them to the latest persisted authority; the Worker never signs with an IACA.
use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context as _, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use jiff::Timestamp;
use nazo_crypto::certificate::{verify_crl_signature, verify_signature};
use nazo_digital_credentials::{CertificateRevocationStatus, certificate_identity};
use nazo_key_management::{
    KeyManager, MdocCrlNumber, MdocCrlPublication, MdocCrlPublicationStore, Openid4vcPublicMaterial,
};
use nazo_mdoc::certificate::{
    check_document_signer_profile, check_iaca_profile, check_issuer_binding,
};
use sha2::{Digest as _, Sha256};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
};

use crate::config::WorkerMdocCrl;

struct PublishedCrl {
    der: Bytes,
    der_sha256: [u8; 32],
    public_material_hash: blake3::Hash,
}

pub(crate) struct PresignedMdocCrls {
    keys: KeyManager,
    store: Arc<dyn MdocCrlPublicationStore>,
    tenant_id: uuid::Uuid,
    issuer: String,
    publications: BTreeMap<String, PublishedCrl>,
}

impl PresignedMdocCrls {
    pub(crate) fn new(
        keys: KeyManager,
        store: Arc<dyn MdocCrlPublicationStore>,
        tenant_id: uuid::Uuid,
        issuer: &str,
        configured: &BTreeMap<String, WorkerMdocCrl>,
    ) -> anyhow::Result<Arc<Self>> {
        let publications = configured
            .iter()
            .map(|(id, value)| {
                ensure!(
                    hex_identifier(id),
                    "invalid mdoc CRL publication identifier"
                );
                ensure!(
                    hex_identifier(&value.public_material_blake3),
                    "invalid mdoc CRL authority digest"
                );
                let der = STANDARD
                    .decode(&value.der_base64)
                    .context("invalid mdoc CRL base64")?;
                ensure!(
                    !der.is_empty() && der.len() <= 128 * 1024,
                    "mdoc CRL exceeds its document bound"
                );
                Ok((
                    id.clone(),
                    PublishedCrl {
                        der_sha256: Sha256::digest(&der).into(),
                        der: der.into(),
                        public_material_hash: blake3::Hash::from_hex(
                            &value.public_material_blake3,
                        )?,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Arc::new(Self {
            keys,
            store,
            tenant_id,
            issuer: issuer.trim_end_matches('/').to_owned(),
            publications,
        }))
    }
}

impl nazoauth::capabilities::MdocCrlProvider for PresignedMdocCrls {
    fn signed_crl<'a>(
        &'a self,
        issuer_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Option<Bytes>>> + Send + 'a>,
    > {
        Box::pin(async move {
            let Some(publication) = self.publications.get(issuer_id) else {
                return Ok(None);
            };
            // Read the authoritative D1 generation on every request. An isolate's
            // prepared signing snapshot must not hide a subsequent revocation.
            let state = self.keys.database_openid4vc_state().await?;
            let material = state
                .material
                .context("mdoc authority material is absent")?;
            let verified = validate_publication(
                &material.public,
                &self.issuer,
                issuer_id,
                publication,
                Timestamp::now(),
            )?;
            let mut issuer_key_id = [0_u8; 32];
            hex::decode_to_slice(issuer_id, &mut issuer_key_id)?;
            self.store
                .accept_verified_publication(&MdocCrlPublication {
                    tenant_id: self.tenant_id,
                    issuer_id: issuer_key_id,
                    issuer: self.issuer.clone(),
                    number: verified.number,
                    der_sha256: publication.der_sha256,
                    authority: material.public,
                    this_update: verified.this_update,
                    next_update: verified.next_update,
                })
                .await?;
            Ok(Some(publication.der.clone()))
        })
    }
}

fn hex_identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn certificates(text: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    pem::parse_many(text)?
        .into_iter()
        .map(|block| {
            ensure!(
                block.tag() == "CERTIFICATE",
                "public certificate PEM is invalid"
            );
            let der = block.into_contents();
            let (remaining, _) = x509_parser::parse_x509_certificate(&der)
                .map_err(|_| anyhow::anyhow!("invalid public certificate DER"))?;
            ensure!(
                remaining.is_empty(),
                "public certificate has trailing bytes"
            );
            Ok(der)
        })
        .collect()
}

fn has_crl_uri(certificate: &X509Certificate<'_>, uri: &str) -> anyhow::Result<bool> {
    let extension = certificate
        .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))?
        .context("mdoc certificate has no CRL distribution point")?;
    let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
        anyhow::bail!("mdoc CRL distribution point is invalid");
    };
    Ok(points.points.iter().any(|point| {
        matches!(&point.distribution_point, Some(DistributionPointName::FullName(names))
            if names.iter().any(|name| matches!(name, GeneralName::URI(value) if *value == uri)))
    }))
}

fn issuer_name_matches(certificate: &X509Certificate<'_>, issuer: &str) -> anyhow::Result<bool> {
    let extension = certificate
        .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.18))?
        .context("mdoc certificate has no issuer alternative name")?;
    let ParsedExtension::IssuerAlternativeName(names) = extension.parsed_extension() else {
        anyhow::bail!("mdoc issuer alternative name is invalid");
    };
    Ok(names
        .general_names
        .iter()
        .any(|name| matches!(name, GeneralName::URI(value) if *value == issuer)))
}

struct VerifiedPublication {
    number: MdocCrlNumber,
    this_update: Timestamp,
    next_update: Timestamp,
}

fn publication_number(encoded: &[u8]) -> anyhow::Result<MdocCrlNumber> {
    use x509_parser::asn1_rs::{FromDer as _, Integer, ToDer as _};

    // Extension parsing may discard a remainder. Decode this complete value
    // again and require canonical DER, including its universal primitive tag
    // and shortest length. The positive sign octet counts toward RFC 5280's
    // twenty-content-octet bound; BigUint alone loses that information.
    let (remaining, integer) = Integer::from_der(encoded)
        .map_err(|_| anyhow::anyhow!("mdoc CRL number is not a DER integer"))?;
    ensure!(
        remaining.is_empty()
            && integer.any().as_bytes().len() <= 20
            && integer.to_der_vec()?.as_slice() == encoded,
        "mdoc CRL number must use complete canonical DER of at most 20 content octets"
    );
    let value = integer.any();
    let content = value.as_bytes();
    ensure!(
        content.first().is_some_and(|byte| byte & 0x80 == 0),
        "mdoc CRL number must be positive"
    );
    // Canonical DER permits one leading zero only when it is needed to keep
    // the next octet positive. The shared magnitude type also rejects zero.
    MdocCrlNumber::from_big_endian(content.strip_prefix(&[0]).unwrap_or(content))
}

fn validate_publication(
    public: &Openid4vcPublicMaterial,
    issuer: &str,
    issuer_id: &str,
    publication: &PublishedCrl,
    now: Timestamp,
) -> anyhow::Result<VerifiedPublication> {
    // Hash the typed public projection, including its canonical timestamp
    // serialization. Re-encoding through serde_json::Value changes field order.
    ensure!(
        blake3::hash(&serde_json::to_vec(public)?) == publication.public_material_hash,
        "mdoc CRL authority generation changed"
    );
    let snapshot = public
        .revocation_snapshot
        .as_ref()
        .context("mdoc authority has no revocation snapshot")?;
    snapshot.validate_freshness_at(now)?;
    let chain = certificates(&public.certificate_chain_pem)?;
    ensure!(
        chain.len() == 2,
        "mdoc CRL requires the current DS and IACA pair"
    );
    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0])
        .map_err(|_| anyhow::anyhow!("invalid mdoc document signer"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(&chain[1])
        .map_err(|_| anyhow::anyhow!("invalid mdoc IACA"))?;
    ensure!(
        certificates(&public.trust_anchors_pem)?.contains(&chain[1]),
        "mdoc IACA is not an authority trust anchor"
    );
    check_document_signer_profile(&leaf)?;
    check_iaca_profile(&ca)?;
    check_issuer_binding(&leaf, &ca)?;
    verify_signature(&leaf, ca.public_key())?;
    verify_signature(&ca, ca.public_key())?;
    let mut identifier = Sha256::new();
    identifier.update(b"NazoAuth mdoc CRL publication v1\0");
    identifier.update(ca.public_key().subject_public_key.data.as_ref());
    let identifier = hex::encode(identifier.finalize());
    let uri = format!("{issuer}/.well-known/mdoc/{issuer_id}.crl");
    ensure!(
        identifier == issuer_id
            && has_crl_uri(&leaf, &uri)?
            && has_crl_uri(&ca, &uri)?
            && issuer_name_matches(&leaf, issuer)?
            && issuer_name_matches(&ca, issuer)?,
        "mdoc CRL publication does not match its issuer and certificates"
    );
    let (remaining, crl) = x509_parser::parse_x509_crl(&publication.der)
        .map_err(|_| anyhow::anyhow!("invalid mdoc CRL DER"))?;
    ensure!(
        remaining.is_empty()
            && crl.version() == Some(x509_parser::x509::X509Version::V2)
            && crl.issuer() == ca.subject()
            && crl.signature_algorithm == crl.tbs_cert_list.signature
            && crl.signature_value.unused_bits == 0,
        "mdoc CRL issuer or signed structure is invalid"
    );
    verify_crl_signature(&crl, ca.public_key())?;
    let this_update = Timestamp::from_second(crl.last_update().timestamp())?;
    let next_update = Timestamp::from_second(
        crl.next_update()
            .context("mdoc CRL has no next update")?
            .timestamp(),
    )?;
    ensure!(
        this_update <= now
            && now < next_update
            && snapshot.this_update <= this_update
            && next_update <= snapshot.next_update
            && this_update.as_second() >= ca.validity().not_before.timestamp()
            && next_update.as_second() <= ca.validity().not_after.timestamp(),
        "mdoc CRL is outside its authoritative validity window"
    );
    let extensions = crl.tbs_cert_list.extensions_map()?;
    ensure!(
        extensions.len() == 2,
        "mdoc CRL must contain only its full-list authority and number"
    );
    let subject_key = ca
        .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.14))?
        .context("mdoc IACA has no subject key identifier")?;
    let ParsedExtension::SubjectKeyIdentifier(subject_key) = subject_key.parsed_extension() else {
        anyhow::bail!("mdoc IACA subject key identifier is invalid");
    };
    let authority_key = extensions
        .get(&x509_parser::der_parser::oid!(2.5.29.35))
        .context("mdoc CRL has no authority key identifier")?;
    let ParsedExtension::AuthorityKeyIdentifier(authority_key) = authority_key.parsed_extension()
    else {
        anyhow::bail!("mdoc CRL authority key identifier is invalid");
    };
    ensure!(
        authority_key.key_identifier.as_ref() == Some(subject_key)
            && authority_key.authority_cert_issuer.is_none()
            && authority_key.authority_cert_serial.is_none()
            && crl.extensions().iter().all(|extension| !extension.critical),
        "mdoc CRL authority key does not match the IACA"
    );
    let number_extension = extensions
        .get(&x509_parser::der_parser::oid!(2.5.29.20))
        .context("mdoc CRL has no publication number")?;
    let number = publication_number(number_extension.value)?;
    let identity = certificate_identity(&chain[0]);
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.issuer == issuer && entry.certificate == identity)
        .context("mdoc snapshot has no current document signer status")?;
    let revoked = &crl.tbs_cert_list.revoked_certificates;
    match entry.status {
        CertificateRevocationStatus::Good => ensure!(
            revoked.is_empty() && entry.revoked_at.is_none(),
            "mdoc CRL does not match the current good document signer"
        ),
        CertificateRevocationStatus::Revoked => {
            let revoked_at = entry
                .revoked_at
                .context("revoked document signer has no revocation time")?;
            ensure!(
                revoked.len() == 1
                    && revoked[0].user_certificate == leaf.tbs_certificate.serial
                    && revoked[0].revocation_date.timestamp() == revoked_at.as_second()
                    && revoked[0].extensions().is_empty()
                    && revoked_at <= this_update,
                "mdoc CRL does not match the document signer revocation"
            );
        }
    }
    Ok(VerifiedPublication {
        number,
        this_update,
        next_update,
    })
}

#[cfg(test)]
#[path = "../tests/unit/mdoc_crls.rs"]
mod tests;
