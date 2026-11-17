//! OpenID4VC authority material lifecycle: certificate profiles, managed
//! IACA/DS generation, mdoc revocation state, and CRL issuance.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use nazo_auth::SigningPurpose;
use nazo_crypto::certificate::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DistinguishedName, DnType, DnValue, IsCa, KeyIdMethod, KeyUsagePurpose,
    PrintableString, RevokedCertParams, SerialNumber,
};
use nazo_digital_credentials::mdoc_certificate::{
    check_mdoc_document_signer_profile, check_mdoc_iaca_profile, check_mdoc_issuer_binding,
};
use nazo_key_management::{KeyManager, Openid4vcMaterial, Openid4vcPublicMaterial};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use url::{Host, Url};
use yasna::{Tag, models::ObjectIdentifier};

use crate::{config::ConfigSource, settings::Settings};

use super::{GenerateLocalKeyOptions, database_key_manager_for_tenant, parse_generate_local};

#[derive(Debug)]
pub(super) struct Openid4vcCertificateProfile {
    hostname: String,
    mdoc_profile: Option<MdocCertificateProfile>,
}

#[derive(Clone, Debug)]
struct MdocCertificateProfile {
    issuing_country: String,
    issuer_contact_uri: String,
    crl_distribution_uri: String,
}

struct Openid4vcCertificateBundle {
    chain_pem: String,
    ca_pem: String,
    mdoc_material: Option<MdocCertificateMaterial>,
}

struct MdocCertificateMaterial {
    leaf_der: Vec<u8>,
    // CRL publication address, never an identity used to establish trust.
    issuer_id: String,
    issuer_material_pem: String,
}

#[derive(Clone)]
pub(crate) struct MdocCrlSource {
    keyset: KeyManager,
    issuer_contact_uri: String,
}

impl MdocCrlSource {
    pub(crate) fn from_settings(settings: &Settings, keyset: KeyManager) -> Option<Self> {
        (settings.modules.enable_openid4vci_issuer || settings.modules.enable_openid4vp_verifier)
            .then(|| Self {
                keyset,
                issuer_contact_uri: settings
                    .endpoint
                    .issuer
                    .as_str()
                    .trim_end_matches('/')
                    .to_owned(),
            })
    }
}

pub(crate) async fn signed_mdoc_crl(
    source: &MdocCrlSource,
    issuer_id: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    if issuer_id.len() != 64
        || !issuer_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(None);
    }
    // Revocation facts are read from the authority, not an instance-local cache.
    let Some(material) = source.keyset.database_mdoc_crl_material(issuer_id).await? else {
        return Ok(None);
    };
    let issuer_material = &material.issuer_private_material;
    let snapshot = &material.revocation_snapshot;
    let certificates = &material.certificate_chain_der;
    if certificates.len() != 2 {
        bail!("OpenID4VC certificate bundle must contain a DS and IACA");
    }
    let (leaf_remainder, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC DS certificate: {error}"))?;
    let (ca_remainder, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .map_err(|error| anyhow::anyhow!("failed to parse OpenID4VC IACA certificate: {error}"))?;
    if !leaf_remainder.is_empty() || !ca_remainder.is_empty() {
        bail!("OpenID4VC certificate contains trailing data");
    }
    let crl_base = format!("{}/.well-known/mdoc", source.issuer_contact_uri);
    if mdoc_crl_record_id(&leaf, &ca, &crl_base, true).as_deref() != Some(issuer_id) {
        bail!("mdoc issuer material does not match its CRL publication address");
    }
    if check_mdoc_document_signer_profile(&leaf).is_err()
        || check_mdoc_issuer_binding(&leaf, &ca).is_err()
    {
        return Ok(None);
    }
    let identity = nazo_digital_credentials::certificate_identity(certificates[0].as_ref());
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.issuer == source.issuer_contact_uri && entry.certificate == identity)
        .context("mdoc revocation snapshot has no status for the current DS certificate")?;
    // sign_crl matches and signs with the same prepared private key. The CA's
    // public key supplies the identifier after the exact issuer binding above.
    let issuer_public_key = ca.public_key().subject_public_key.data.as_ref();
    let this_update = time::OffsetDateTime::from_unix_timestamp(material.this_update.timestamp())
        .context("CRL publication this_update is out of range")?;
    let next_update = time::OffsetDateTime::from_unix_timestamp(material.next_update.timestamp())
        .context("CRL publication next_update is out of range")?;
    let number_bytes = material.crl_number.to_be_bytes();
    let number_start = number_bytes
        .iter()
        .position(|byte| *byte != 0)
        .context("CRL publication number must be positive")?;
    let revoked_certs = match entry.status {
        nazo_digital_credentials::CertificateRevocationStatus::Good => Vec::new(),
        nazo_digital_credentials::CertificateRevocationStatus::Revoked => vec![RevokedCertParams {
            serial_number: SerialNumber::from(leaf.raw_serial().to_vec()),
            revocation_time: time::OffsetDateTime::from_unix_timestamp(
                entry
                    .revoked_at
                    .context("revoked DS has no recorded revocation time")?
                    .timestamp(),
            )
            .context("DS revocation time is out of range")?,
            reason_code: None,
            invalidity_date: None,
        }],
    };
    let crl_params = CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(number_bytes[number_start..].to_vec()),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::PreSpecified(subject_key_identifier_from_public_key(
            issuer_public_key,
        )),
    };
    let crl =
        nazo_crypto::certificate::sign_crl(crl_params, certificates[1].as_ref(), issuer_material)
            .context("failed to sign mdoc CRL")?;
    Ok(Some(crl))
}

fn mdoc_certificate_profile(
    config: &ConfigSource,
    issuer: &Url,
) -> anyhow::Result<Option<MdocCertificateProfile>> {
    let configurations = crate::settings::credential_configurations_from_config(config)?;
    let Some(issuing_country) =
        crate::settings::mdoc_issuing_country_from_config(config, &configurations)?
    else {
        return Ok(None);
    };
    let issuer_contact_uri = issuer.as_str().trim_end_matches('/').to_owned();
    Ok(Some(MdocCertificateProfile {
        issuing_country,
        crl_distribution_uri: format!("{issuer_contact_uri}/.well-known/mdoc"),
        issuer_contact_uri,
    }))
}

fn mdoc_certificate_profile_matches(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    ca: &x509_parser::certificate::X509Certificate<'_>,
    profile: &MdocCertificateProfile,
) -> bool {
    let country_matches = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate
            .subject()
            .iter_country()
            .map(|country| country.as_str().ok())
            .eq([Some(profile.issuing_country.as_str())])
    };
    let has_ian = |certificate: &x509_parser::certificate::X509Certificate<'_>| {
        certificate.extensions().iter().any(|extension| {
            matches!(
                &extension.parsed_extension(),
                x509_parser::extensions::ParsedExtension::IssuerAlternativeName(names)
                    if names.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::URI(uri) if *uri == profile.issuer_contact_uri))
            )
        })
    };
    check_mdoc_document_signer_profile(leaf).is_ok()
        && check_mdoc_iaca_profile(ca).is_ok()
        && check_mdoc_issuer_binding(leaf, ca).is_ok()
        && country_matches(leaf)
        && has_ian(leaf)
        && has_ian(ca)
        && mdoc_crl_record_id(leaf, ca, &profile.crl_distribution_uri, false).is_some()
}

/// A stable address known before the root is signed. Certificate DER cannot be
/// hashed into its own CRL URI without creating a circular dependency.
fn mdoc_crl_publication_id(public_key: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"NazoAuth mdoc CRL publication v1\0");
    digest.update(public_key);
    hex::encode(digest.finalize())
}

fn has_crl_uri(certificate: &x509_parser::certificate::X509Certificate<'_>, uri: &str) -> bool {
    use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};

    let Ok(Some(extension)) =
        certificate.get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))
    else {
        return false;
    };
    let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
        return false;
    };
    !extension.critical
        && !points.points.is_empty()
        && points.points.iter().all(|point| {
            point.reasons.is_none()
                && point.crl_issuer.is_none()
                && matches!(&point.distribution_point, Some(DistributionPointName::FullName(names))
                    if names.iter().any(|name| matches!(name, GeneralName::URI(_))))
        })
        && points.points.iter().any(|point| {
            matches!(&point.distribution_point, Some(DistributionPointName::FullName(names))
                if names.iter().any(|name| matches!(name, GeneralName::URI(value) if *value == uri)))
        })
}

/// Bind the stored record and URL to the actual certificate pair. Historical
/// DER-addressed records retain their published URLs, without private-key
/// aliases. Only new records can be selected as the active issuing generation.
fn mdoc_crl_record_id(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    ca: &x509_parser::certificate::X509Certificate<'_>,
    crl_base: &str,
    allow_legacy: bool,
) -> Option<String> {
    let id = mdoc_crl_publication_id(ca.public_key().subject_public_key.data.as_ref());
    let uri = format!("{crl_base}/{id}.crl");
    if has_crl_uri(leaf, &uri) && has_crl_uri(ca, &uri) {
        return Some(id);
    }
    // Older roots omitted CRLDistributionPoints. Accept this shape only to
    // retain the already published DS CRL, never to authorize new issuance.
    if allow_legacy
        && ca
            .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))
            .is_ok_and(|extension| extension.is_none())
    {
        let id = sha256_hex(ca.as_ref());
        if has_crl_uri(leaf, &format!("{crl_base}/{id}.crl")) {
            return Some(id);
        }
    }
    None
}

fn subject_key_identifier_from_public_key(public_key: &[u8]) -> Vec<u8> {
    Sha1::digest(public_key).to_vec()
}

fn build_openid4vc_certificate_bundle(
    signing_key_pem: &str,
    hostname: &str,
    mdoc_profile: Option<&MdocCertificateProfile>,
    now: time::OffsetDateTime,
) -> anyhow::Result<Openid4vcCertificateBundle> {
    // MSO issuance claims use UTC days. Locally managed mdoc certificates
    // must cover that same boundary, including a newly generated signer.
    // Anchor both ends so rounding never lengthens the certificate lifetime.
    // Imported certificates retain their authority's original validity.
    let not_before = if mdoc_profile.is_some() {
        now.date().midnight().assume_utc()
    } else {
        now
    };
    let ca_not_after = not_before + time::Duration::days(3650);
    let ca_key_pem = nazo_crypto::certificate::generate_p256_private_key_pem()?;
    let ca_public_key = mdoc_profile
        .map(|_| nazo_crypto::certificate::public_key_from_pem(&ca_key_pem))
        .transpose()?;
    let issuer_id = ca_public_key.as_deref().map(mdoc_crl_publication_id);
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "NazoAuth OpenID4VC Local CA");
    if let Some(profile) = mdoc_profile {
        ca_params.distinguished_name.push(
            DnType::CountryName,
            printable_country_name(&profile.issuing_country)?,
        );
        ca_params
            .custom_extensions
            .push(issuer_alternative_name(&profile.issuer_contact_uri));
        ca_params.key_identifier_method =
            KeyIdMethod::PreSpecified(subject_key_identifier_from_public_key(
                ca_public_key.as_deref().expect("mdoc IACA public key"),
            ));
        ca_params
            .crl_distribution_points
            .push(CrlDistributionPoint {
                uris: vec![format!(
                    "{}/{}.crl",
                    profile.crl_distribution_uri,
                    issuer_id.as_ref().expect("mdoc CRL publication address")
                )],
            });
    }
    ca_params.is_ca = IsCa::Ca(if mdoc_profile.is_some() {
        BasicConstraints::Constrained(0)
    } else {
        BasicConstraints::Unconstrained
    });
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = ca_not_after;
    ca_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    let ca_der = nazo_crypto::certificate::self_signed(ca_params, &ca_key_pem)?;

    let mut leaf_params = CertificateParams::new(vec![hostname.to_owned()])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    if let Some(profile) = mdoc_profile {
        leaf_params.distinguished_name.push(
            DnType::CountryName,
            printable_country_name(&profile.issuing_country)?,
        );
        leaf_params
            .custom_extensions
            .push(document_signing_extended_key_usage());
        leaf_params
            .custom_extensions
            .push(subject_key_identifier_extension(
                &nazo_crypto::certificate::public_key_from_pem(signing_key_pem)?,
            ));
        leaf_params
            .custom_extensions
            .push(issuer_alternative_name(&profile.issuer_contact_uri));
        leaf_params
            .crl_distribution_points
            .push(CrlDistributionPoint {
                uris: vec![format!(
                    "{}/{}.crl",
                    profile.crl_distribution_uri,
                    issuer_id.as_ref().expect("mdoc CRL publication address")
                )],
            });
    }
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = not_before;
    leaf_params.not_after = if mdoc_profile.is_some() {
        not_before + time::Duration::days(457)
    } else {
        ca_not_after
    };
    leaf_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    leaf_params.use_authority_key_identifier_extension = mdoc_profile.is_some();
    let leaf_der =
        nazo_crypto::certificate::sign(leaf_params, signing_key_pem, &ca_der, &ca_key_pem)?;
    let leaf_pem = pem_certificate(&leaf_der);
    let ca_pem = pem_certificate(&ca_der);

    let chain_pem = format!("{leaf_pem}{ca_pem}");
    let mdoc_material = issuer_id.map(|issuer_id| MdocCertificateMaterial {
        leaf_der,
        issuer_id,
        // One immutable IACA record owns its key and sole DS. Retaining it
        // keeps the certificate's CRL address valid across key rotation.
        issuer_material_pem: format!("{ca_key_pem}{leaf_pem}{ca_pem}"),
    });
    Ok(Openid4vcCertificateBundle {
        chain_pem,
        ca_pem,
        mdoc_material,
    })
}

fn subject_key_identifier_extension(public_key: &[u8]) -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_bytes(&subject_key_identifier_from_public_key(public_key));
    });
    CustomExtension::from_oid_content(&[2, 5, 29, 14], content)
}

fn printable_country_name(country: &str) -> anyhow::Result<DnValue> {
    Ok(DnValue::PrintableString(
        PrintableString::try_from(country)
            .context("mDoc issuing country is not PrintableString")?,
    ))
}

fn document_signing_extended_key_usage() -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_oid(&ObjectIdentifier::from_slice(&[1, 0, 18013, 5, 1, 2]));
        });
    });
    let mut extension = CustomExtension::from_oid_content(&[2, 5, 29, 37], content);
    extension.set_criticality(true);
    extension
}

fn issuer_alternative_name(uri: &str) -> CustomExtension {
    let content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer
                .next()
                .write_tagged_implicit(Tag::context(6), |writer| writer.write_ia5_string(uri));
        });
    });
    CustomExtension::from_oid_content(&[2, 5, 29, 18], content)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn database_certificate_profile(
    binding: &nazo_identity::TenantDirectoryBinding,
    config: &ConfigSource,
    options: &GenerateLocalKeyOptions,
) -> anyhow::Result<Option<Openid4vcCertificateProfile>> {
    let both = [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect();
    if options.purposes != both {
        return Ok(None);
    }
    if options.alg != nazo_crypto::jwt::Algorithm::ES256 {
        bail!("OpenID4VC certificates require ES256");
    }
    let issuer = Url::parse(&binding.issuer)?;
    let Host::Domain(hostname) = issuer
        .host()
        .context("tenant issuer must include a DNS hostname")?
    else {
        bail!("tenant issuer must include a DNS hostname");
    };
    Ok(Some(Openid4vcCertificateProfile {
        hostname: hostname.to_owned(),
        mdoc_profile: mdoc_certificate_profile(config, &issuer)?,
    }))
}

pub(super) async fn generate_local_with_database_manager(
    manager: &KeyManager,
    profile: Option<&Openid4vcCertificateProfile>,
    options: GenerateLocalKeyOptions,
) -> anyhow::Result<(String, String, Option<String>)> {
    let Some(profile) = profile else {
        let (kid, revision) = manager
            .database_register_local_with_revision(nazo_key_management::LocalKeyRegistration {
                algorithm: options.alg,
                purposes: options.purposes,
            })
            .await?;
        return Ok((kid, revision, None));
    };
    let state = manager.database_openid4vc_state().await?;
    if let Some(material) = state.material {
        validate_managed_profile(&material, profile)?;
        return Ok((
            material.public.signing_kid,
            state.revision.to_string(),
            Some(material.public.certificate_chain_pem),
        ));
    }
    let snapshot = manager.snapshot();
    if snapshot
        .signing_verification_key(
            SigningPurpose::Credential,
            nazo_crypto::jwt::Algorithm::ES256,
        )
        .is_some()
        || snapshot
            .signing_verification_key(
                SigningPurpose::PresentationRequest,
                nazo_crypto::jwt::Algorithm::ES256,
            )
            .is_some()
    {
        bail!("existing OpenID4VC key requires explicit mdoc-import before use");
    }
    let signing_key_pem = nazo_crypto::certificate::generate_p256_private_key_pem()?;
    let material = build_managed_material(&signing_key_pem, profile, None)?;
    match manager
        .database_commit_openid4vc(state.revision, material, Some(signing_key_pem))
        .await
    {
        Ok(committed) => {
            let material = committed
                .material
                .context("committed OpenID4VC generation has no material")?;
            Ok((
                material.public.signing_kid,
                committed.revision.to_string(),
                Some(material.public.certificate_chain_pem),
            ))
        }
        Err(error) => {
            // Concurrent bootstrap may already have committed a complete generation.
            let winner = manager.database_openid4vc_state().await?;
            if winner.revision != state.revision
                && let Some(material) = winner.material
            {
                validate_managed_profile(&material, profile)?;
                manager.refresh().await?;
                return Ok((
                    material.public.signing_kid,
                    winner.revision.to_string(),
                    Some(material.public.certificate_chain_pem),
                ));
            }
            Err(error)
        }
    }
}

fn build_managed_material(
    signing_key_pem: &str,
    profile: &Openid4vcCertificateProfile,
    previous: Option<Openid4vcMaterial>,
) -> anyhow::Result<Openid4vcMaterial> {
    let bundle = build_openid4vc_certificate_bundle(
        signing_key_pem,
        &profile.hostname,
        profile.mdoc_profile.as_ref(),
        time::OffsetDateTime::now_utc(),
    )?;
    let (mut anchors, mut iacas, mut revocation_snapshot) = match previous {
        Some(previous) => (
            previous.public.trust_anchors_pem,
            previous.iaca_private_materials,
            previous.public.revocation_snapshot,
        ),
        None => (String::new(), BTreeMap::new(), None),
    };
    // Historical roots and IACA keys are needed by credentials already issued.
    // This root was just generated with a new private key.
    anchors.push_str(&bundle.ca_pem);
    let now = chrono::Utc::now();
    let snapshot = revocation_snapshot.get_or_insert_with(|| {
        nazo_digital_credentials::CertificateRevocationSnapshot {
            version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
            this_update: now,
            next_update: now + chrono::Duration::hours(24),
            entries: Vec::new(),
        }
    });
    snapshot.this_update = now;
    snapshot.next_update = now + chrono::Duration::hours(24);
    if let Some(material) = bundle.mdoc_material {
        if iacas.contains_key(&material.issuer_id) {
            bail!("mdoc CRL publication address is already assigned");
        }
        for pem in iacas.values() {
            let certificates =
                CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            let issuer = certificates
                .get(1)
                .context("stored IACA record has no issuer")?;
            let (remainder, ca) = x509_parser::parse_x509_certificate(issuer.as_ref())
                .map_err(|error| anyhow::anyhow!("invalid stored IACA certificate: {error}"))?;
            if !remainder.is_empty()
                || mdoc_crl_publication_id(ca.public_key().subject_public_key.data.as_ref())
                    == material.issuer_id
            {
                bail!("an IACA publication key cannot own multiple certificate records");
            }
        }
        iacas.insert(material.issuer_id, material.issuer_material_pem);
        snapshot
            .entries
            .push(nazo_digital_credentials::CertificateRevocationEntry {
                issuer: profile
                    .mdoc_profile
                    .as_ref()
                    .expect("mdoc profile")
                    .issuer_contact_uri
                    .clone(),
                certificate: nazo_digital_credentials::certificate_identity(&material.leaf_der),
                status: nazo_digital_credentials::CertificateRevocationStatus::Good,
                revoked_at: None,
            });
    }
    Ok(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: format!("es256-{}", uuid::Uuid::now_v7()),
            certificate_chain_pem: bundle.chain_pem,
            trust_anchors_pem: anchors,
            revocation_snapshot,
        },
        iaca_private_materials: iacas,
    })
}

fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn validate_managed_profile(
    material: &Openid4vcMaterial,
    profile: &Openid4vcCertificateProfile,
) -> anyhow::Result<()> {
    let certificates =
        CertificateDer::pem_slice_iter(material.public.certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
    if certificates.len() != 2 {
        bail!("managed OpenID4VC chain must contain DS and CA");
    }
    let (leaf_remainder, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .map_err(|e| anyhow::anyhow!("invalid signing certificate: {e}"))?;
    let (ca_remainder, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .map_err(|e| anyhow::anyhow!("invalid CA certificate: {e}"))?;
    let dns_matches = leaf.subject_alternative_name()?.is_some_and(|san| san.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == profile.hostname)));
    let profile_matches = match &profile.mdoc_profile {
        Some(profile) => mdoc_certificate_profile_matches(&leaf, &ca, profile),
        None => !leaf.is_ca() && ca.is_ca() && ca.subject().as_raw() == ca.issuer().as_raw(),
    };
    if !leaf_remainder.is_empty()
        || !ca_remainder.is_empty()
        || !dns_matches
        || !profile_matches
        || leaf.issuer().as_raw() != ca.subject().as_raw()
        || nazo_crypto::certificate::verify_signature(&ca, ca.public_key()).is_err()
        || nazo_crypto::certificate::verify_signature(&leaf, ca.public_key()).is_err()
        || !leaf.validity().is_valid()
        || !ca.validity().is_valid()
    {
        bail!(
            "managed certificate no longer matches tenant profile; explicit mdoc rotation is required"
        );
    }
    Ok(())
}

/// One-time administrator import. Runtime startup never reads this directory.
async fn import_mdoc_directory(
    manager: &KeyManager,
    profile: &Openid4vcCertificateProfile,
    source: &Path,
) -> anyhow::Result<String> {
    let state = manager.database_openid4vc_state().await?;
    if state.material.is_some() {
        bail!("managed OpenID4VC material already exists; import cannot overwrite it");
    }
    let snapshot = manager.snapshot();
    let key = snapshot
        .signing_verification_key(
            SigningPurpose::Credential,
            nazo_crypto::jwt::Algorithm::ES256,
        )
        .context("import requires the existing credential signing key in the database")?;
    let chain = tokio::fs::read_to_string(source.join("certificate-bundle.pem"))
        .await
        .context("failed to read import certificate-bundle.pem")?;
    let mut anchors = String::new();
    let mut iacas = BTreeMap::new();
    let revocation_snapshot = if let Some(mdoc_profile) = &profile.mdoc_profile {
        let bytes = tokio::fs::read(source.join("revocation-snapshot.json"))
            .await
            .context("failed to read import revocation-snapshot.json")?;
        let snapshot = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid imported revocation state: {e}"))?;
        if snapshot.entries.iter().any(|entry| {
            entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked
                && entry.revoked_at.is_none()
        }) {
            bail!("imported revoked DS status is missing its revocation time");
        }
        let mut owned_certificates = BTreeSet::new();
        let mut publication_keys = BTreeSet::new();
        let mut directory = tokio::fs::read_dir(source.join("iaca-keys"))
            .await
            .context("failed to read import iaca-keys directory")?;
        while let Some(entry) = directory.next_entry().await? {
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "pem")
            {
                continue;
            }
            let pem = tokio::fs::read_to_string(entry.path()).await?;
            let certificates =
                CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            if certificates.len() != 2 {
                bail!("imported IACA record must contain its DS and IACA certificates");
            }
            let (leaf_remainder, leaf) =
                x509_parser::parse_x509_certificate(certificates[0].as_ref())
                    .map_err(|e| anyhow::anyhow!("invalid imported DS: {e}"))?;
            let (ca_remainder, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
                .map_err(|e| anyhow::anyhow!("invalid imported IACA: {e}"))?;
            let private_public_key = nazo_crypto::certificate::public_key_from_pem(&pem)?;
            if !leaf_remainder.is_empty()
                || !ca_remainder.is_empty()
                || leaf.issuer().as_raw() != ca.subject().as_raw()
                || private_public_key != ca.public_key().subject_public_key.data.as_ref()
                || nazo_crypto::certificate::verify_signature(&ca, ca.public_key()).is_err()
                || nazo_crypto::certificate::verify_signature(&leaf, ca.public_key()).is_err()
                || check_mdoc_document_signer_profile(&leaf).is_err()
                || check_mdoc_issuer_binding(&leaf, &ca).is_err()
            {
                bail!("imported IACA key and certificate chain do not match");
            }
            let id = mdoc_crl_record_id(&leaf, &ca, &mdoc_profile.crl_distribution_uri, true)
                .context("imported IACA record has no bound CRL publication address")?;
            let publication_key =
                mdoc_crl_publication_id(ca.public_key().subject_public_key.data.as_ref());
            if id == publication_key {
                check_mdoc_iaca_profile(&ca).context(
                    "new imported IACA does not match the mdoc root certificate profile",
                )?;
            } else if !ca.is_ca() || ca.subject().as_raw() != ca.issuer().as_raw() {
                // Legacy records retain their original root without a CRLDP.
                // Their key, signatures and exact old DS URL remain checked.
                bail!("historical imported IACA is not a self-issued CA");
            }
            if entry.file_name().to_str() != Some(format!("{id}.pem").as_str()) {
                bail!("imported IACA filename does not match its CRL publication address");
            }
            if !publication_keys.insert(publication_key) {
                bail!("an IACA publication key cannot own multiple certificate records");
            }
            let issuer = &mdoc_profile.issuer_contact_uri;
            let identity = nazo_digital_credentials::certificate_identity(certificates[0].as_ref());
            if !snapshot
                .entries
                .iter()
                .any(|entry| entry.issuer == *issuer && entry.certificate == identity)
            {
                bail!("imported revocation state is missing an IACA's DS status");
            }
            owned_certificates.insert(identity);
            anchors.push_str(&pem_certificate(certificates[1].as_ref()));
            iacas.insert(id, pem);
        }
        if iacas.is_empty() {
            bail!("mdoc import requires IACA private material");
        }
        if snapshot.entries.iter().any(|entry| {
            entry.issuer != mdoc_profile.issuer_contact_uri
                || !owned_certificates.contains(&entry.certificate)
        }) {
            bail!("mdoc import accepts revocation facts only for its owned IACA records");
        }
        Some(snapshot)
    } else {
        let now = chrono::Utc::now();
        Some(nazo_digital_credentials::CertificateRevocationSnapshot {
            version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
            this_update: now,
            next_update: now + chrono::Duration::hours(24),
            entries: Vec::new(),
        })
    };
    let certificates =
        CertificateDer::pem_slice_iter(chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certificates.len() != 2 {
        bail!("imported signing chain must contain DS and CA");
    }
    let active_ca = pem_certificate(certificates[1].as_ref());
    if let Some(mdoc_profile) = &profile.mdoc_profile {
        let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
            .map_err(|error| anyhow::anyhow!("invalid active imported DS: {error}"))?;
        let (_, ca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
            .map_err(|error| anyhow::anyhow!("invalid active imported IACA: {error}"))?;
        let id = mdoc_crl_record_id(&leaf, &ca, &mdoc_profile.crl_distribution_uri, false)
            .context("active imported IACA requires a root CRL address; rotate legacy material before use")?;
        let iaca = iacas
            .get(&id)
            .context("import is missing the active IACA private material")?;
        let owned_chain =
            CertificateDer::pem_slice_iter(iaca.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        if owned_chain != certificates {
            bail!("active signing chain does not match its IACA publication record");
        }
    }
    if !anchors.contains(&active_ca) {
        anchors.push_str(&active_ca);
    }
    let material = Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: key.kid.clone(),
            certificate_chain_pem: chain,
            trust_anchors_pem: anchors,
            revocation_snapshot,
        },
        iaca_private_materials: iacas,
    };
    validate_managed_profile(&material, profile)?;
    let committed = manager
        .database_commit_openid4vc(state.revision, material, None)
        .await?;
    Ok(committed.revision.to_string())
}

async fn rotate_managed_material(
    manager: &KeyManager,
    profile: &Openid4vcCertificateProfile,
) -> anyhow::Result<String> {
    let state = manager.database_openid4vc_state().await?;
    let previous = state
        .material
        .context("rotation requires initialized OpenID4VC material")?;
    let key_pem = nazo_crypto::certificate::generate_p256_private_key_pem()?;
    let material = build_managed_material(&key_pem, profile, Some(previous))?;
    let committed = manager
        .database_commit_openid4vc(state.revision, material, Some(key_pem))
        .await?;
    Ok(committed.revision.to_string())
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MdocManagementAction {
    Import(PathBuf),
    Rotate,
    Revoke { issuer_id: String },
}

pub(crate) async fn operator_manage_mdoc(
    config: &ConfigSource,
    binding: &nazo_identity::TenantDirectoryBinding,
    persistence: &dyn crate::operator_task::OperatorPersistence,
    action: MdocManagementAction,
) -> anyhow::Result<String> {
    let settings = Settings::from_directory_binding(config, binding)?;
    let manager =
        database_key_manager_for_tenant(config, &settings, binding.tenant.tenant_id, persistence)
            .await?;
    let options = parse_generate_local(
        "ES256",
        &["credential".into(), "presentation_request".into()],
    )?;
    let profile =
        database_certificate_profile(binding, config, &options)?.expect("OpenID4VC purposes");
    match action {
        MdocManagementAction::Import(source) => {
            import_mdoc_directory(&manager, &profile, &source).await
        }
        MdocManagementAction::Rotate => rotate_managed_material(&manager, &profile).await,
        MdocManagementAction::Revoke { issuer_id } => {
            let state = manager.database_openid4vc_state().await?;
            let mut material = state
                .material
                .context("revocation requires initialized mdoc material")?;
            let pem = material
                .iaca_private_materials
                .get(&issuer_id)
                .context("unknown IACA CRL publication address")?;
            let certificates =
                CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
            let identity = nazo_digital_credentials::certificate_identity(
                certificates
                    .first()
                    .context("IACA record has no DS certificate")?
                    .as_ref(),
            );
            let snapshot = material
                .public
                .revocation_snapshot
                .as_mut()
                .context("mdoc revocation state is missing")?;
            let issuer = profile
                .mdoc_profile
                .as_ref()
                .context("mdoc profile is not configured")?
                .issuer_contact_uri
                .as_str();
            let entry = snapshot
                .entries
                .iter_mut()
                .find(|entry| entry.issuer == issuer && entry.certificate == identity)
                .context("DS revocation status is missing")?;
            if entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked {
                return Ok(state.revision.to_string());
            }
            entry.status = nazo_digital_credentials::CertificateRevocationStatus::Revoked;
            entry.revoked_at = Some(chrono::Utc::now());
            snapshot.this_update = chrono::Utc::now();
            snapshot.next_update = snapshot.this_update + chrono::Duration::hours(24);
            let committed = manager
                .database_commit_openid4vc(state.revision, material, None)
                .await?;
            Ok(committed.revision.to_string())
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/keyctl/openid4vc_material.rs"]
mod tests;

impl nazoauth::capabilities::MdocCrlProvider for MdocCrlSource {
    fn signed_crl<'a>(
        &'a self,
        issuer_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Option<bytes::Bytes>>> + Send + 'a>,
    > {
        Box::pin(async move {
            signed_mdoc_crl(self, issuer_id)
                .await
                .map(|body| body.map(Into::into))
        })
    }
}
