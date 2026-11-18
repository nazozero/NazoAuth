use std::sync::{Arc, OnceLock};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_key_management::{
    KeySettings, LocalKeyRegistration, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyWrappingKeyRing,
};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use uuid::Uuid;
use x509_parser::der_parser::asn1_rs::Tag;

use super::*;

use super::super::shared::{
    MemoryOperatorPersistence, MemorySigningKeyRepository, temporary_directory, tenant_binding,
};

fn test_wrapping_key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(rand::random)
}

fn mdoc_database_config(data_dir: &Path) -> ConfigSource {
    ConfigSource::from_owned_pairs_for_test([
        ("DATA_DIR".to_owned(), data_dir.display().to_string()),
        (
            "SIGNING_KEY_ENCRYPTION_KEY".to_owned(),
            URL_SAFE_NO_PAD.encode(test_wrapping_key()),
        ),
        (
            "SIGNING_KEY_ENCRYPTION_KEY_ID".to_owned(),
            "keyctl-test-root".to_owned(),
        ),
        ("TRANSPORT_MODE".to_owned(), "trusted-proxy".to_owned()),
        ("MTLS_CERTIFICATE_SOURCE".to_owned(), "rfc9440".to_owned()),
        (
            "TRUSTED_PROXY_CIDRS".to_owned(),
            "127.0.0.1/32".to_owned(),
        ),
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON".to_owned(),
            r#"{"mdl":{"format":"mso_mdoc","scope":"mdl","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"doctype":"org.iso.18013.5.1.mDL"}}"#.to_owned(),
        ),
        (
            "OPENID4VC_MDOC_ISSUING_COUNTRY".to_owned(),
            "US".to_owned(),
        ),
    ])
}

fn database_key_settings() -> KeySettings {
    KeySettings {
        rotation_interval: jiff::SignedDuration::from_hours((90) * 24),
        prepublish_window: jiff::SignedDuration::from_hours(24),
        verification_grace: jiff::SignedDuration::from_hours(1),
    }
}

fn all_openid4vc_purposes() -> std::collections::BTreeSet<SigningPurpose> {
    [
        SigningPurpose::Credential,
        SigningPurpose::PresentationRequest,
    ]
    .into_iter()
    .collect()
}

fn managed_options() -> GenerateLocalKeyOptions {
    parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .expect("managed OpenID4VC options")
}

fn managed_profile(hostname: &str) -> Openid4vcCertificateProfile {
    Openid4vcCertificateProfile {
        hostname: hostname.to_owned(),
        mdoc_profile: Some(MdocCertificateProfile {
            issuing_country: "US".to_owned(),
            issuer_contact_uri: format!("https://{hostname}"),
            crl_distribution_uri: format!("https://{hostname}/.well-known/mdoc"),
        }),
    }
}

// Reproduce the historical native shape: the root has no CRLDP and the DS
// points to SHA-256(root DER). This is independently signed test material,
// not a damaged or re-encoded instance of the new certificate profile.
fn legacy_mdoc_material(
    signing_key: &KeyPair,
    ca_key: &KeyPair,
    profile: &Openid4vcCertificateProfile,
) -> Openid4vcMaterial {
    let mdoc = profile.mdoc_profile.as_ref().unwrap();
    let now = time::OffsetDateTime::now_utc()
        .date()
        .midnight()
        .assume_utc();
    let ca_pem = ca_key.serialize_pem();
    let ca_public_key = nazo_crypto::certificate::public_key_from_pem(&ca_pem).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Historical IACA");
    ca_params.distinguished_name.push(
        DnType::CountryName,
        printable_country_name(&mdoc.issuing_country).unwrap(),
    );
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha1::digest(&ca_public_key).to_vec());
    ca_params
        .custom_extensions
        .push(issuer_alternative_name(&mdoc.issuer_contact_uri));
    ca_params.not_before = now;
    ca_params.not_after = now + time::Duration::days(3650);
    ca_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    let ca_der = nazo_crypto::certificate::self_signed(ca_params, &ca_pem).unwrap();
    let id = hex::encode(Sha256::digest(&ca_der));

    let signing_pem = signing_key.serialize_pem();
    let mut leaf_params = CertificateParams::new(vec![profile.hostname.clone()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, profile.hostname.clone());
    leaf_params.distinguished_name.push(
        DnType::CountryName,
        printable_country_name(&mdoc.issuing_country).unwrap(),
    );
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.custom_extensions = vec![
        document_signing_extended_key_usage(),
        subject_key_identifier_extension(
            &nazo_crypto::certificate::public_key_from_pem(&signing_pem).unwrap(),
        ),
        issuer_alternative_name(&mdoc.issuer_contact_uri),
    ];
    leaf_params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!("{}/{}.crl", mdoc.crl_distribution_uri, id)],
    }];
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.not_before = now;
    leaf_params.not_after = now + time::Duration::days(457);
    leaf_params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    let leaf_der =
        nazo_crypto::certificate::sign(leaf_params, &signing_pem, &ca_der, &ca_pem).unwrap();
    let root_pem = pem_certificate(&ca_der);
    let chain_pem = format!("{}{}", pem_certificate(&leaf_der), root_pem);
    let now = jiff::Timestamp::now();
    Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: "historical-test-kid".to_owned(),
            certificate_chain_pem: chain_pem.clone(),
            trust_anchors_pem: root_pem,
            revocation_snapshot: Some(nazo_digital_credentials::CertificateRevocationSnapshot {
                version: nazo_digital_credentials::CertificateRevocationSnapshot::VERSION,
                this_update: now,
                next_update: now + jiff::SignedDuration::from_hours(24),
                entries: vec![nazo_digital_credentials::CertificateRevocationEntry {
                    issuer: mdoc.issuer_contact_uri.clone(),
                    certificate: nazo_digital_credentials::certificate_identity(&leaf_der),
                    status: nazo_digital_credentials::CertificateRevocationStatus::Good,
                    revoked_at: None,
                }],
            }),
        },
        iaca_private_materials: [(id, format!("{ca_pem}{chain_pem}"))].into(),
    }
}

fn reissue_test_iaca(
    pem: &str,
    original: &x509_parser::certificate::X509Certificate<'_>,
    profile: &MdocCertificateProfile,
    id: &str,
    change: impl FnOnce(&mut CertificateParams),
) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "NazoAuth OpenID4VC Local CA");
    params.distinguished_name.push(
        DnType::CountryName,
        printable_country_name(&profile.issuing_country).unwrap(),
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = KeyIdMethod::PreSpecified(
        Sha1::digest(original.public_key().subject_public_key.data.as_ref()).to_vec(),
    );
    params
        .custom_extensions
        .push(issuer_alternative_name(&profile.issuer_contact_uri));
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!("{}/{}.crl", profile.crl_distribution_uri, id)],
    }];
    params.not_before =
        time::OffsetDateTime::from_unix_timestamp(original.validity().not_before.timestamp())
            .unwrap();
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(original.validity().not_after.timestamp())
            .unwrap();
    params.serial_number = Some(SerialNumber::from(rand::random::<[u8; 19]>().to_vec()));
    change(&mut params);
    nazo_crypto::certificate::self_signed(params, pem).unwrap()
}

fn certificate_crl_uri(certificate: &x509_parser::certificate::X509Certificate<'_>) -> String {
    use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
    let extension = certificate
        .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))
        .unwrap()
        .expect("certificate CRLDistributionPoints");
    assert!(!extension.critical);
    let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() else {
        panic!("parsed CRLDistributionPoints");
    };
    assert_eq!(points.points.len(), 1);
    let point = &points.points[0];
    assert!(point.reasons.is_none());
    assert!(point.crl_issuer.is_none());
    let Some(DistributionPointName::FullName(names)) = &point.distribution_point else {
        panic!("fullName distribution point");
    };
    let [GeneralName::URI(uri)] = names.as_slice() else {
        panic!("one URI distribution point");
    };
    (*uri).to_owned()
}

fn der_sequence_fields(encoded: &[u8]) -> Vec<&[u8]> {
    use x509_parser::der_parser::asn1_rs::{Any, FromDer};
    let (remaining, sequence) = Any::from_der(encoded).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(sequence.tag(), Tag::Sequence);
    let mut content = sequence.data;
    let mut fields = Vec::new();
    while !content.is_empty() {
        let (next, _) = Any::from_der(content).unwrap();
        fields.push(&content[..content.len() - next.len()]);
        content = next;
    }
    fields
}

fn parse_certificates(pem: &str) -> Vec<CertificateDer<'_>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM")
}

fn iaca_certificates<'a>(
    material: &'a Openid4vcMaterial,
    issuer_id: &str,
) -> Vec<CertificateDer<'a>> {
    parse_certificates(
        material
            .iaca_private_materials
            .get(issuer_id)
            .expect("IACA material"),
    )
}

fn assert_complete_managed_material(material: &Openid4vcMaterial) {
    assert!(!material.public.signing_kid.is_empty());
    assert_eq!(
        parse_certificates(&material.public.certificate_chain_pem).len(),
        2
    );
    assert!(!material.public.trust_anchors_pem.is_empty());
    assert!(!material.iaca_private_materials.is_empty());
    let snapshot = material
        .public
        .revocation_snapshot
        .as_ref()
        .expect("managed revocation snapshot");
    assert!(!snapshot.entries.is_empty());
    for pem in material.iaca_private_materials.values() {
        assert_eq!(parse_certificates(pem).len(), 2);
    }
    assert_iso_mdoc_certificate_profile(material);
}

fn assert_iso_mdoc_certificate_profile(material: &Openid4vcMaterial) {
    let certificates = parse_certificates(&material.public.certificate_chain_pem);
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
        .expect("parse managed DS certificate");
    let (_, iaca) = x509_parser::parse_x509_certificate(certificates[1].as_ref())
        .expect("parse managed IACA certificate");

    for certificate in [&leaf, &iaca] {
        let country = certificate
            .subject()
            .iter_country()
            .next()
            .expect("managed mDoc certificate countryName");
        assert_eq!(country.attr_value().tag(), Tag::PrintableString);
    }

    let extended_key_usage = leaf
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(usage) => {
                Some((extension.critical, usage))
            }
            _ => None,
        })
        .expect("managed DS extended key usage");
    assert!(extended_key_usage.0);
    assert_eq!(extended_key_usage.1.other.len(), 1);
    assert_eq!(
        extended_key_usage.1.other[0].to_id_string(),
        "1.0.18013.5.1.2"
    );
    assert!(
        leaf.basic_constraints()
            .expect("parse managed DS basic constraints")
            .is_none()
    );

    let basic_constraints = iaca
        .basic_constraints()
        .expect("parse managed IACA basic constraints")
        .expect("managed IACA basic constraints");
    assert!(basic_constraints.critical);
    assert!(basic_constraints.value.ca);
    assert_eq!(basic_constraints.value.path_len_constraint, Some(0));

    let root_uri = certificate_crl_uri(&iaca);
    assert_eq!(certificate_crl_uri(&leaf), root_uri);
    let id = root_uri
        .rsplit('/')
        .next()
        .unwrap()
        .strip_suffix(".crl")
        .unwrap();
    assert!(material.iaca_private_materials.contains_key(id));
    assert_ne!(id, hex::encode(Sha256::digest(certificates[1].as_ref())));
    // The address is derived from the raw public key before the root exists.
    let mut address_input = b"NazoAuth mdoc CRL publication v1\0".to_vec();
    address_input.extend_from_slice(iaca.public_key().subject_public_key.data.as_ref());
    assert_eq!(id, hex::encode(Sha256::digest(address_input)));
}

fn assert_same_material(left: &Openid4vcMaterial, right: &Openid4vcMaterial) {
    assert_eq!(left.public.signing_kid, right.public.signing_kid);
    assert_eq!(
        left.public.certificate_chain_pem,
        right.public.certificate_chain_pem
    );
    assert_eq!(
        left.public.trust_anchors_pem,
        right.public.trust_anchors_pem
    );
    assert_eq!(
        left.public.revocation_snapshot,
        right.public.revocation_snapshot
    );
    assert_eq!(left.iaca_private_materials, right.iaca_private_materials);
}

fn assert_same_persisted_record(left: &PersistedSigningKeyset, right: &PersistedSigningKeyset) {
    assert_eq!(left.revision, right.revision);
    assert_eq!(left.public_metadata, right.public_metadata);
    assert_eq!(
        left.encrypted_private_material,
        right.encrypted_private_material
    );
    assert_eq!(left.wrapping_key_id, right.wrapping_key_id);
}

async fn database_manager(
    repository: Arc<MemorySigningKeyRepository>,
    tenant_id: Uuid,
) -> KeyManager {
    KeyManager::load_or_create_database(
        database_key_settings(),
        None,
        tenant_id,
        repository,
        SigningKeyWrappingKeyRing::new("keyctl-test-root", test_wrapping_key(), None)
            .expect("wrapping key ring"),
    )
    .await
    .expect("database key manager")
}

async fn database_manager_with_mdoc_key(
    repository: Arc<MemorySigningKeyRepository>,
    tenant_id: Uuid,
) -> (KeyManager, String, KeyPair) {
    let manager = database_manager(repository, tenant_id).await;
    let kid = manager
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: all_openid4vc_purposes(),
        })
        .await
        .expect("database mdoc signing key");
    let key = KeyPair::from_pem(
        &manager
            .database_local_private_key_pem(&kid)
            .expect("database mdoc signing key material"),
    )
    .expect("database mdoc signing key PEM");
    (manager, kid, key)
}

async fn write_mdoc_import_fixture(
    source: &Path,
    active_key: &KeyPair,
    profile: &Openid4vcCertificateProfile,
    include_iaca_directory: bool,
) -> anyhow::Result<Openid4vcMaterial> {
    let active = build_managed_material(&active_key.serialize_pem(), profile, None)?;
    tokio::fs::create_dir_all(source).await?;
    tokio::fs::write(
        source.join("certificate-bundle.pem"),
        &active.public.certificate_chain_pem,
    )
    .await?;
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(
            active
                .public
                .revocation_snapshot
                .as_ref()
                .expect("snapshot"),
        )?,
    )
    .await?;
    if include_iaca_directory {
        let iaca_directory = source.join("iaca-keys");
        tokio::fs::create_dir_all(&iaca_directory).await?;
        for (issuer_id, pem) in &active.iaca_private_materials {
            tokio::fs::write(iaca_directory.join(format!("{issuer_id}.pem")), pem).await?;
        }
    }
    Ok(active)
}

#[test]
fn database_certificate_profile_requires_the_managed_shape() {
    let config = ConfigSource::from_pairs_for_test([]);
    let binding = tenant_binding("https://tenant.example");
    let single_purpose = parse_generate_local("ES256", &["credential".to_owned()]).unwrap();
    assert!(
        database_certificate_profile(&binding, &config, &single_purpose)
            .unwrap()
            .is_none()
    );

    let managed = managed_options();
    let profile = database_certificate_profile(&binding, &config, &managed)
        .unwrap()
        .expect("managed certificate profile");
    assert_eq!(profile.hostname, "tenant.example");
    assert!(profile.mdoc_profile.is_none());

    let unsupported = parse_generate_local(
        "EdDSA",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert!(database_certificate_profile(&binding, &config, &unsupported).is_err());

    let ip_binding = tenant_binding("https://127.0.0.1");
    let error = database_certificate_profile(&ip_binding, &config, &managed).unwrap_err();
    assert!(error.to_string().contains("DNS hostname"));

    let mdoc = ConfigSource::from_owned_pairs_for_test([
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON".to_owned(),
            r#"{"mdl":{"format":"mso_mdoc","scope":"mdl","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"doctype":"org.iso.18013.5.1.mDL"}}"#.to_owned(),
        ),
        (
            "OPENID4VC_MDOC_ISSUING_COUNTRY".to_owned(),
            "US".to_owned(),
        ),
    ]);
    let profile = database_certificate_profile(&binding, &mdoc, &managed)
        .unwrap()
        .expect("mDoc certificate profile");
    let mdoc_profile = profile.mdoc_profile.expect("mDoc profile details");
    assert_eq!(mdoc_profile.issuing_country, "US");
    assert_eq!(mdoc_profile.issuer_contact_uri, "https://tenant.example");
    assert_eq!(
        mdoc_profile.crl_distribution_uri,
        "https://tenant.example/.well-known/mdoc"
    );
}

#[tokio::test]
async fn managed_generation_is_idempotent() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let manager = database_manager(repository, Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");

    let (first_kid, first_revision, first_chain) =
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect("managed generation");
    let first_state = manager
        .database_openid4vc_state()
        .await
        .expect("managed state");
    let first_material = first_state.material.expect("managed material");
    assert_eq!(first_kid, first_material.public.signing_kid);
    assert_eq!(first_revision, first_state.revision.to_string());
    assert_eq!(
        first_chain.as_deref(),
        Some(first_material.public.certificate_chain_pem.as_str())
    );
    assert_complete_managed_material(&first_material);

    let (second_kid, second_revision, second_chain) =
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect("idempotent managed generation");
    let second_state = manager
        .database_openid4vc_state()
        .await
        .expect("reloaded managed state");
    let second_material = second_state.material.expect("retained managed material");
    assert_eq!(second_kid, first_kid);
    assert_eq!(second_revision, first_revision);
    assert_eq!(second_chain, first_chain);
    assert_eq!(second_state.revision, first_state.revision);
    assert_same_material(&first_material, &second_material);
}

#[tokio::test]
async fn concurrent_managed_initialization_converges_on_one_complete_generation() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let first = database_manager(repository.clone(), tenant_id).await;
    let second = database_manager(repository.clone(), tenant_id).await;
    let third = database_manager(repository.clone(), tenant_id).await;
    let fourth = database_manager(repository.clone(), tenant_id).await;
    let profile = managed_profile("tenant.example");

    let (first_kid, second_kid, third_kid, fourth_kid) = tokio::join!(
        generate_local_with_database_manager(&first, Some(&profile), managed_options()),
        generate_local_with_database_manager(&second, Some(&profile), managed_options()),
        generate_local_with_database_manager(&third, Some(&profile), managed_options()),
        generate_local_with_database_manager(&fourth, Some(&profile), managed_options()),
    );
    let first_kid = first_kid.expect("first concurrent initialization");
    let second_kid = second_kid.expect("second concurrent initialization");
    let third_kid = third_kid.expect("third concurrent initialization");
    let fourth_kid = fourth_kid.expect("fourth concurrent initialization");
    assert_eq!(first_kid, second_kid);
    assert_eq!(first_kid, third_kid);
    assert_eq!(first_kid, fourth_kid);

    let winner = database_manager(repository, tenant_id).await;
    let state = winner
        .database_openid4vc_state()
        .await
        .expect("concurrent managed state");
    let material = state.material.expect("complete concurrent material");
    assert_eq!(material.public.signing_kid, first_kid.0);
    assert_eq!(state.revision.to_string(), first_kid.1);
    assert_eq!(
        Some(material.public.certificate_chain_pem.clone()),
        first_kid.2
    );
    assert_complete_managed_material(&material);
}

#[tokio::test]
async fn operator_generation_result_stays_on_its_applied_generation_after_concurrent_rotation() {
    let config = mdoc_database_config(&temporary_directory("generation-result-race"));
    let binding = tenant_binding("https://tenant.example");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };
    let barrier = repository.pause_next_openid4vc_commit();
    let purposes = ["credential".to_owned(), "presentation_request".to_owned()];
    let (generated, observed) = tokio::join!(
        super::super::operator_generate_local_database_for_tenant(
            &config,
            &binding,
            &persistence,
            "ES256",
            &purposes,
        ),
        async {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                barrier.applied.notified(),
            )
            .await
            .expect("generation reached the applied CAS barrier");
            let rotator =
                database_manager(repository.clone(), binding.tenant.tenant_id.as_uuid()).await;
            let first = rotator.database_openid4vc_state().await.unwrap();
            rotate_managed_material(&rotator, &managed_profile("tenant.example"))
                .await
                .unwrap();
            let second = rotator.database_openid4vc_state().await.unwrap();
            barrier.release.notify_one();
            (first, second)
        },
    );
    let (kid, revision, chain) = generated.expect("generation result");
    let (first, second) = observed;
    let first_material = first.material.unwrap();
    let second_material = second.material.unwrap();
    assert!(second.revision > first.revision);
    assert_ne!(
        first_material.public.signing_kid,
        second_material.public.signing_kid
    );
    assert_eq!(kid, first_material.public.signing_kid);
    assert_eq!(revision, first.revision.to_string());
    assert_eq!(chain, Some(first_material.public.certificate_chain_pem));
}

#[tokio::test]
async fn rotation_returns_its_committed_revision_after_a_concurrent_rotation() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .unwrap();
    let barrier = repository.pause_next_openid4vc_commit();
    let (result, revisions) = tokio::join!(rotate_managed_material(&manager, &profile), async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            barrier.applied.notified(),
        )
        .await
        .expect("rotation reached the applied CAS barrier");
        let concurrent = database_manager(repository.clone(), tenant_id).await;
        let applied = concurrent
            .database_openid4vc_state()
            .await
            .unwrap()
            .revision;
        let newer = rotate_managed_material(&concurrent, &profile)
            .await
            .unwrap();
        barrier.release.notify_one();
        (applied, newer)
    });
    assert_eq!(result.unwrap(), revisions.0.to_string());
    assert!(revisions.1.parse::<i64>().unwrap() > revisions.0);
}

#[tokio::test]
async fn failed_managed_cas_does_not_leave_partial_material() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let manager = database_manager(repository.clone(), Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");

    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("initial managed generation");
    let initial_state = manager
        .database_openid4vc_state()
        .await
        .expect("initial managed state");
    let stale_revision = initial_state.revision;
    rotate_managed_material(&manager, &profile)
        .await
        .expect("winning managed rotation");
    let winner_state = manager
        .database_openid4vc_state()
        .await
        .expect("rotated managed state");
    assert!(winner_state.revision > stale_revision);
    let winner_material = winner_state.material.clone().expect("rotated material");
    let before = repository
        .load()
        .await
        .expect("repository before stale CAS")
        .expect("record before stale CAS");

    let rejected_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let rejected_material = build_managed_material(
        &rejected_key.serialize_pem(),
        &profile,
        Some(winner_material.clone()),
    )
    .expect("candidate managed material");
    assert!(
        manager
            .database_commit_openid4vc(
                stale_revision,
                rejected_material,
                Some(rejected_key.serialize_pem()),
            )
            .await
            .is_err()
    );

    let after = repository
        .load()
        .await
        .expect("repository after stale CAS")
        .expect("record after stale CAS");
    assert_same_persisted_record(&before, &after);
    let state_after = manager
        .database_openid4vc_state()
        .await
        .expect("state after stale CAS");
    assert_same_material(
        &winner_material,
        state_after.material.as_ref().expect("winner retained"),
    );
}

#[tokio::test]
async fn restart_with_a_different_key_manager_still_serves_database_backed_crl() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("managed generation");
    let state = manager
        .database_openid4vc_state()
        .await
        .expect("managed state");
    let material = state.material.expect("managed material");
    let issuer_id = material
        .iaca_private_materials
        .keys()
        .next()
        .expect("IACA issuer")
        .clone();
    let iaca = iaca_certificates(&material, &issuer_id);

    let restarted = database_manager(repository, tenant_id).await;
    let source = MdocCrlSource {
        keyset: restarted,
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    let crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .expect("database-backed CRL")
        .expect("CRL for persisted IACA");
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).expect("parse CRL");
    let (_, ca) = x509_parser::parse_x509_certificate(iaca[1].as_ref()).expect("parse IACA");
    assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());
    assert_eq!(parsed_crl.iter_revoked_certificates().count(), 0);
    let root_uri = certificate_crl_uri(&ca);
    let (_, ds) = x509_parser::parse_x509_certificate(iaca[0].as_ref()).unwrap();
    assert_eq!(certificate_crl_uri(&ds), root_uri);
    assert_eq!(
        root_uri,
        format!("https://tenant.example/.well-known/mdoc/{issuer_id}.crl")
    );
    // Use the address actually embedded in the root, through the real HTTP
    // response handler, then verify the returned CRL with that root's key.
    let address = Url::parse(&root_uri).unwrap();
    let requested_id = address
        .path_segments()
        .unwrap()
        .next_back()
        .unwrap()
        .strip_suffix(".crl")
        .unwrap();
    let response = nazoauth::test_support::well_known::mdoc_crl(Some(&source), requested_id).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/pkix-crl"
    );
    let (remaining, returned_crl) = x509_parser::parse_x509_crl(response.body()).unwrap();
    assert!(remaining.is_empty());
    returned_crl.verify_signature(ca.public_key()).unwrap();
    assert_eq!(returned_crl.iter_revoked_certificates().count(), 0);
    assert_eq!(returned_crl.crl_number(), parsed_crl.crl_number());
    assert_eq!(returned_crl.last_update(), parsed_crl.last_update());
    assert_eq!(returned_crl.next_update(), parsed_crl.next_update());
    assert_eq!(
        returned_crl.tbs_cert_list.as_ref(),
        parsed_crl.tbs_cert_list.as_ref()
    );
    assert_eq!(returned_crl.crl_number().unwrap().to_bytes_be().len(), 9);
    let fingerprint = hex::encode(Sha256::digest(iaca[1].as_ref()));
    assert_eq!(
        nazoauth::test_support::well_known::mdoc_crl(Some(&source), &fingerprint)
            .await
            .status(),
        http::StatusCode::NOT_FOUND,
        "new material has one publication record, not a second private-key alias"
    );
}

#[tokio::test]
async fn mdoc_import_binds_publication_filename_and_certificate_uri() {
    for wrong_filename in [true, false] {
        let source = temporary_directory("mdoc-import-address-binding");
        let repository = Arc::new(MemorySigningKeyRepository::default());
        let (manager, _, signing_key) =
            database_manager_with_mdoc_key(repository.clone(), Uuid::now_v7()).await;
        let profile = managed_profile("tenant.example");
        let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
            .await
            .unwrap();
        let id = active.iaca_private_materials.keys().next().unwrap();
        let selected_path = source.join("iaca-keys").join(format!("{id}.pem"));
        if wrong_filename {
            let certificates = iaca_certificates(&active, id);
            let fingerprint = hex::encode(Sha256::digest(certificates[1].as_ref()));
            tokio::fs::rename(
                selected_path,
                source.join("iaca-keys").join(format!("{fingerprint}.pem")),
            )
            .await
            .unwrap();
        } else {
            // A correctly signed pair with a different issuer's URL must not
            // acquire a working local address just by being copied here.
            let foreign = build_managed_material(
                &signing_key.serialize_pem(),
                &managed_profile("different.example"),
                None,
            )
            .unwrap();
            tokio::fs::write(
                selected_path,
                foreign.iaca_private_materials.values().next().unwrap(),
            )
            .await
            .unwrap();
        }
        let before = repository.load().await.unwrap().unwrap();
        let error = import_mdoc_directory(&manager, &profile, &source)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(if wrong_filename {
                "filename does not match its CRL publication address"
            } else {
                "no bound CRL publication address"
            }),
            "{error:#}"
        );
        assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());
        tokio::fs::remove_dir_all(source).await.unwrap();
    }
}

#[tokio::test]
async fn mdoc_import_binds_the_active_root_and_enforces_its_profile() {
    let source = temporary_directory("mdoc-import-active-root-binding");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let (manager, _, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");
    let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .unwrap();
    let (id, pem) = active.iaca_private_materials.iter().next().unwrap();
    let chain = iaca_certificates(&active, id);
    let (_, original_ca) = x509_parser::parse_x509_certificate(chain[1].as_ref()).unwrap();
    let mdoc = profile.mdoc_profile.as_ref().unwrap();

    // A second valid root with the same key has the same publication ID but
    // different certificate identity. It must not replace the root captured
    // together with the DS in the immutable publication record.
    let replacement_der = reissue_test_iaca(pem, &original_ca, mdoc, id, |_| {});
    assert_ne!(replacement_der, chain[1].as_ref());
    let (_, replacement) = x509_parser::parse_x509_certificate(&replacement_der).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    nazo_crypto::certificate::verify_signature(&replacement, replacement.public_key()).unwrap();
    nazo_crypto::certificate::verify_signature(&leaf, replacement.public_key()).unwrap();
    assert_eq!(replacement.subject(), leaf.issuer());
    tokio::fs::write(
        source.join("certificate-bundle.pem"),
        format!(
            "{}{}",
            pem_certificate(chain[0].as_ref()),
            pem_certificate(&replacement_der),
        ),
    )
    .await
    .unwrap();

    let before = repository.load().await.unwrap().unwrap();
    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("active signing chain does not match its IACA publication record"),
        "{error:#}"
    );
    assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());

    // Even an exactly matched active/publication pair is refused when the
    // newly imported root exceeds the allowed certificate lifetime.
    let overlong_der = reissue_test_iaca(pem, &original_ca, mdoc, id, |params| {
        params.not_after = params.not_before + time::Duration::days(8_000);
    });
    let (_, overlong) = x509_parser::parse_x509_certificate(&overlong_der).unwrap();
    nazo_crypto::certificate::verify_signature(&overlong, overlong.public_key()).unwrap();
    nazo_crypto::certificate::verify_signature(&leaf, overlong.public_key()).unwrap();
    let active_chain = format!(
        "{}{}",
        pem_certificate(chain[0].as_ref()),
        pem_certificate(&overlong_der)
    );
    tokio::fs::write(source.join("certificate-bundle.pem"), &active_chain)
        .await
        .unwrap();
    let private_pem = &pem[..pem.find("-----BEGIN CERTIFICATE-----").unwrap()];
    tokio::fs::write(
        source.join("iaca-keys").join(format!("{id}.pem")),
        format!("{private_pem}{active_chain}"),
    )
    .await
    .unwrap();
    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("new imported IACA does not match the mdoc root certificate profile"),
        "{error:#}"
    );
    assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());
    tokio::fs::remove_dir_all(source).await.unwrap();
}

#[tokio::test]
async fn mdoc_import_rejects_fractional_iaca_validity_without_truncating_the_bound() {
    let source = temporary_directory("mdoc-import-fractional-validity");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let (manager, _, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");
    let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .unwrap();
    let (id, pem) = active.iaca_private_materials.iter().next().unwrap();
    let chain = iaca_certificates(&active, id);
    let (_, original_ca) = x509_parser::parse_x509_certificate(chain[1].as_ref()).unwrap();
    let start =
        jiff::Timestamp::from_second(original_ca.validity().not_before.timestamp()).unwrap();
    let limit = jiff::tz::Offset::UTC
        .to_datetime(start)
        .checked_add(jiff::Span::new().years(20))
        .unwrap();
    let limit = jiff::tz::Offset::UTC.to_timestamp(limit).unwrap();
    let excessive = time::OffsetDateTime::from_unix_timestamp(limit.as_second()).unwrap()
        + time::Duration::milliseconds(1);

    // rcgen emits whole-second certificate validity. Use existing ASN.1 readers
    // and writers to construct a DER-valid fractional GeneralizedTime, then
    // actually sign that new TBS with the original IACA key.
    let outer = der_sequence_fields(chain[1].as_ref());
    let fields = der_sequence_fields(outer[0]);
    let validity_fields = der_sequence_fields(fields[4]);
    let validity = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_der(validity_fields[0]);
            writer
                .next()
                .write_generalized_time(&yasna::models::GeneralizedTime::from_datetime(excessive));
        })
    });
    let tbs = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            for (index, field) in fields.iter().enumerate() {
                writer
                    .next()
                    .write_der(if index == 4 { &validity } else { field });
            }
        })
    });
    let ca_key = KeyPair::from_pem(pem).unwrap();
    let signature = rcgen::SigningKey::sign(&ca_key, &tbs).unwrap();
    let fractional_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_der(&tbs);
            writer.next().write_der(outer[1]);
            writer
                .next()
                .write_bitvec_bytes(&signature, signature.len() * 8);
        })
    });
    let (_, fractional_ca) = x509_parser::parse_x509_certificate(&fractional_der).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    assert_eq!(
        fractional_ca
            .validity()
            .not_after
            .to_datetime()
            .nanosecond(),
        1_000_000
    );
    assert_eq!(
        fractional_ca.validity().not_after.timestamp(),
        limit.as_second()
    );
    assert!(fractional_ca.validity().is_valid());
    nazo_crypto::certificate::verify_signature(&fractional_ca, fractional_ca.public_key()).unwrap();
    nazo_crypto::certificate::verify_signature(&leaf, fractional_ca.public_key()).unwrap();
    let active_chain = format!(
        "{}{}",
        pem_certificate(chain[0].as_ref()),
        pem_certificate(&fractional_der)
    );
    tokio::fs::write(source.join("certificate-bundle.pem"), &active_chain)
        .await
        .unwrap();
    let private_pem = &pem[..pem.find("-----BEGIN CERTIFICATE-----").unwrap()];
    tokio::fs::write(
        source.join("iaca-keys").join(format!("{id}.pem")),
        format!("{private_pem}{active_chain}"),
    )
    .await
    .unwrap();

    let before = repository.load().await.unwrap().unwrap();
    import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect_err("fractional IACA validity cannot be admitted by truncating to whole seconds");
    assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());
    tokio::fs::remove_dir_all(source).await.unwrap();
}

#[tokio::test]
async fn mdoc_import_rejects_distinct_records_owning_the_same_iaca_key() {
    let source = temporary_directory("mdoc-import-iaca-key-conflict");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let (manager, _, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), Uuid::now_v7()).await;
    let profile = managed_profile("tenant.example");
    let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .unwrap();
    let mut snapshot = active.public.revocation_snapshot.unwrap();
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let ds_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let historical = legacy_mdoc_material(&ds_key, &ca_key, &profile);
        snapshot
            .entries
            .extend(historical.public.revocation_snapshot.unwrap().entries);
        let (id, pem) = historical
            .iaca_private_materials
            .into_iter()
            .next()
            .unwrap();
        tokio::fs::write(source.join("iaca-keys").join(format!("{id}.pem")), pem)
            .await
            .unwrap();
        ids.push(id);
    }
    assert_ne!(
        ids[0], ids[1],
        "distinct valid root certificates share one key"
    );
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(&snapshot).unwrap(),
    )
    .await
    .unwrap();
    let before = repository.load().await.unwrap().unwrap();
    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("publication key cannot own multiple certificate records"),
        "{error:#}"
    );
    assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());
    tokio::fs::remove_dir_all(source).await.unwrap();
}

#[tokio::test]
async fn legacy_active_material_requires_explicit_rotation_and_keeps_its_crl() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let binding = tenant_binding("https://tenant.example");
    let data_dir = temporary_directory("legacy-mdoc-operator-rotation");
    let config = mdoc_database_config(&data_dir);
    let (manager, kid, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), binding.tenant.tenant_id.as_uuid())
            .await;
    let profile = managed_profile("tenant.example");
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut legacy = legacy_mdoc_material(&signing_key, &ca_key, &profile);
    legacy.public.signing_kid = kid;
    let old_id = legacy.iaca_private_materials.keys().next().unwrap().clone();
    let old_chain = iaca_certificates(&legacy, &old_id);
    let (_, old_ca) = x509_parser::parse_x509_certificate(old_chain[1].as_ref()).unwrap();
    let state = manager.database_openid4vc_state().await.unwrap();
    manager
        .database_commit_openid4vc(state.revision, legacy.clone(), None)
        .await
        .unwrap();
    let before = repository.load().await.unwrap().unwrap();
    let error = generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("explicit mdoc rotation is required")
    );
    assert_same_persisted_record(&before, &repository.load().await.unwrap().unwrap());

    operator_manage_mdoc(
        &config,
        &binding,
        &MemoryOperatorPersistence {
            repository: repository.clone(),
        },
        MdocManagementAction::Rotate,
    )
    .await
    .expect("the real operator rotation path can recover a legacy active root");
    let rotated = manager
        .database_openid4vc_state()
        .await
        .unwrap()
        .material
        .unwrap();
    assert_complete_managed_material(&rotated);
    assert_eq!(rotated.iaca_private_materials.len(), 2);
    assert_eq!(
        rotated.iaca_private_materials[&old_id],
        legacy.iaca_private_materials[&old_id]
    );
    let source = MdocCrlSource {
        keyset: manager,
        issuer_contact_uri: profile.mdoc_profile.unwrap().issuer_contact_uri,
    };
    let response = nazoauth::test_support::well_known::mdoc_crl(Some(&source), &old_id).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let (_, crl) = x509_parser::parse_x509_crl(response.body()).unwrap();
    crl.verify_signature(old_ca.public_key()).unwrap();
}

#[tokio::test]
async fn mdoc_import_preserves_kid_iaca_history_and_rejects_overwrite() {
    let source = temporary_directory("mdoc-import-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let profile = managed_profile("tenant.example");
    let (manager, kid, signing_key) =
        database_manager_with_mdoc_key(repository.clone(), tenant_id).await;

    let active = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .expect("active import fixture");
    let historical_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let historical_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let historical = legacy_mdoc_material(&historical_key, &historical_ca_key, &profile);
    let historical_id = historical
        .iaca_private_materials
        .keys()
        .next()
        .expect("historical IACA")
        .clone();
    let historical_entry = historical
        .public
        .revocation_snapshot
        .as_ref()
        .expect("historical snapshot")
        .entries
        .first()
        .expect("historical status")
        .clone();
    let mut imported_snapshot = active
        .public
        .revocation_snapshot
        .clone()
        .expect("active snapshot");
    imported_snapshot.this_update -= jiff::SignedDuration::from_hours(1);
    let mut revoked_historical_entry = historical_entry;
    revoked_historical_entry.status =
        nazo_digital_credentials::CertificateRevocationStatus::Revoked;
    revoked_historical_entry.revoked_at = Some(imported_snapshot.this_update);
    let revoked_historical_certificate = revoked_historical_entry.certificate.clone();
    imported_snapshot.entries.push(revoked_historical_entry);
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(&imported_snapshot).unwrap(),
    )
    .await
    .unwrap();
    let historical_pem = historical
        .iaca_private_materials
        .get(&historical_id)
        .expect("historical IACA material");
    tokio::fs::write(
        source
            .join("iaca-keys")
            .join(format!("{historical_id}.pem")),
        historical_pem,
    )
    .await
    .unwrap();

    let imported_revision = import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect("explicit mDoc import");
    assert!(!imported_revision.is_empty());
    let imported_state = manager
        .database_openid4vc_state()
        .await
        .expect("imported state");
    let imported = imported_state.material.expect("imported material");
    assert_eq!(imported.public.signing_kid, kid);
    assert_eq!(imported.iaca_private_materials.len(), 2);
    assert!(imported.iaca_private_materials.contains_key(&historical_id));
    assert_complete_managed_material(&imported);
    assert!(
        imported
            .public
            .revocation_snapshot
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .any(|entry| entry.certificate == revoked_historical_certificate
                && entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked)
    );

    let historical_certs = iaca_certificates(&imported, &historical_id);
    let source_after_import = MdocCrlSource {
        keyset: manager.clone(),
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    let historical_crl = signed_mdoc_crl(&source_after_import, &historical_id)
        .await
        .expect("historical CRL")
        .expect("historical CRL present");
    let (_, parsed_historical_crl) =
        x509_parser::parse_x509_crl(&historical_crl).expect("parse historical CRL");
    let (_, historical_ca) =
        x509_parser::parse_x509_certificate(historical_certs[1].as_ref()).expect("historical CA");
    assert_eq!(
        historical_id,
        hex::encode(Sha256::digest(historical_certs[1].as_ref()))
    );
    assert!(
        historical_ca
            .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))
            .unwrap()
            .is_none()
    );
    assert!(
        parsed_historical_crl
            .verify_signature(historical_ca.public_key())
            .is_ok()
    );
    assert_eq!(parsed_historical_crl.iter_revoked_certificates().count(), 1);
    let expected_revocation_time = imported_snapshot.this_update.as_second();
    assert_eq!(
        parsed_historical_crl
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .revocation_date
            .timestamp(),
        expected_revocation_time
    );
    rotate_managed_material(&manager, &profile)
        .await
        .expect("rotation after imported revocation");
    let refreshed_crl = signed_mdoc_crl(&source_after_import, &historical_id)
        .await
        .unwrap()
        .unwrap();
    let (_, refreshed) = x509_parser::parse_x509_crl(&refreshed_crl).unwrap();
    refreshed
        .verify_signature(historical_ca.public_key())
        .unwrap();
    assert_eq!(
        refreshed
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .revocation_date
            .timestamp(),
        expected_revocation_time
    );
    let response =
        nazoauth::test_support::well_known::mdoc_crl(Some(&source_after_import), &historical_id)
            .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let (_, served) = x509_parser::parse_x509_crl(response.body()).unwrap();
    served.verify_signature(historical_ca.public_key()).unwrap();
    assert_eq!(served.iter_revoked_certificates().count(), 1);

    assert!(
        import_mdoc_directory(&manager, &profile, &source)
            .await
            .expect_err("managed import must not overwrite")
            .to_string()
            .contains("already exists")
    );

    tokio::fs::remove_dir_all(source)
        .await
        .expect("mDoc import fixture cleanup");
}

#[tokio::test]
async fn mdoc_import_fails_explicitly_when_iaca_material_is_missing() {
    let source = temporary_directory("mdoc-import-missing-iaca-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let profile = managed_profile("tenant.example");
    let (manager, _kid, signing_key) = database_manager_with_mdoc_key(repository, tenant_id).await;
    write_mdoc_import_fixture(&source, &signing_key, &profile, false)
        .await
        .expect("missing-IACA import fixture");

    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect_err("missing IACA must fail");
    assert!(error.to_string().contains("iaca-keys"));
    let state = manager
        .database_openid4vc_state()
        .await
        .expect("state after rejected import");
    assert!(state.material.is_none());
    assert!(
        generate_local_with_database_manager(&manager, Some(&profile), managed_options())
            .await
            .expect_err("failed import must not silently regenerate")
            .to_string()
            .contains("explicit mdoc-import")
    );

    tokio::fs::remove_dir_all(source)
        .await
        .expect("missing-IACA fixture cleanup");
}

#[tokio::test]
async fn mdoc_import_rejects_revoked_status_without_timestamp_without_writing_keyset() {
    let source = temporary_directory("mdoc-import-missing-revocation-time-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let profile = managed_profile("tenant.example");
    let (manager, _, signing_key) = database_manager_with_mdoc_key(repository, tenant_id).await;
    let imported = write_mdoc_import_fixture(&source, &signing_key, &profile, true)
        .await
        .expect("complete import fixture");
    let mut snapshot = imported
        .public
        .revocation_snapshot
        .expect("complete import fixture snapshot");
    let entry = snapshot
        .entries
        .first_mut()
        .expect("complete import fixture DS status");
    entry.status = nazo_digital_credentials::CertificateRevocationStatus::Revoked;
    entry.revoked_at = None;
    tokio::fs::write(
        source.join("revocation-snapshot.json"),
        serde_json::to_vec(&snapshot).expect("invalid legacy revocation fixture"),
    )
    .await
    .expect("write legacy revocation fixture");

    let before = manager
        .database_openid4vc_state()
        .await
        .expect("keyset state before rejected import");
    let error = import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect_err("revoked DS without a timestamp must be rejected");
    assert!(
        error
            .to_string()
            .contains("revoked DS status is missing its revocation time")
    );
    assert_eq!(
        manager
            .database_openid4vc_state()
            .await
            .expect("keyset state after rejected import"),
        before,
        "rejected legacy revocation data must not write the keyset"
    );

    tokio::fs::remove_dir_all(source)
        .await
        .expect("missing-revocation-time fixture cleanup");
}

#[tokio::test]
async fn rotation_retains_old_and_new_ca_crls_and_trust_anchors() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .expect("initial managed generation");
    let before = manager
        .database_openid4vc_state()
        .await
        .expect("pre-rotation state");
    let old_material = before.material.expect("pre-rotation material");
    let old_issuer_id = old_material
        .iaca_private_materials
        .keys()
        .next()
        .expect("old IACA")
        .clone();
    let old_iaca = iaca_certificates(&old_material, &old_issuer_id);
    let old_ca_pem = pem_certificate(old_iaca[1].as_ref());

    rotate_managed_material(&manager, &profile)
        .await
        .expect("managed rotation");
    let after = manager
        .database_openid4vc_state()
        .await
        .expect("post-rotation state");
    assert!(after.revision > before.revision);
    let new_material = after.material.expect("post-rotation material");
    assert_complete_managed_material(&new_material);
    assert_ne!(
        old_material.public.signing_kid,
        new_material.public.signing_kid
    );
    assert!(
        new_material
            .iaca_private_materials
            .contains_key(&old_issuer_id)
    );
    assert!(new_material.public.trust_anchors_pem.contains(&old_ca_pem));

    let new_issuer_id = new_material
        .iaca_private_materials
        .keys()
        .find(|issuer_id| *issuer_id != &old_issuer_id)
        .expect("new IACA")
        .clone();
    let new_iaca = iaca_certificates(&new_material, &new_issuer_id);
    let new_ca_pem = pem_certificate(new_iaca[1].as_ref());
    assert!(new_material.public.trust_anchors_pem.contains(&new_ca_pem));

    let restarted = database_manager(repository, tenant_id).await;
    let source = MdocCrlSource {
        keyset: restarted,
        issuer_contact_uri: profile
            .mdoc_profile
            .as_ref()
            .expect("mDoc profile")
            .issuer_contact_uri
            .clone(),
    };
    for (issuer_id, ca) in [
        (&old_issuer_id, &old_iaca[1]),
        (&new_issuer_id, &new_iaca[1]),
    ] {
        let crl = signed_mdoc_crl(&source, issuer_id)
            .await
            .expect("rotated CRL")
            .expect("retained CRL");
        let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).expect("parse rotated CRL");
        let (_, ca) = x509_parser::parse_x509_certificate(ca.as_ref()).expect("parse rotated CA");
        assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());
        assert_eq!(parsed_crl.iter_revoked_certificates().count(), 0);
    }
}

#[tokio::test]
async fn operator_mdoc_management_imports_rotates_and_revokes_persisted_material() {
    let data_dir = temporary_directory("operator-mdoc-management");
    let source = temporary_directory("operator-mdoc-import");
    let config = mdoc_database_config(&data_dir);
    let binding = tenant_binding("https://tenant.example");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };
    let (manager, _, active_key) =
        database_manager_with_mdoc_key(repository.clone(), binding.tenant.tenant_id.as_uuid())
            .await;
    write_mdoc_import_fixture(
        &source,
        &active_key,
        &managed_profile("tenant.example"),
        true,
    )
    .await
    .expect("mDoc import fixture");
    tokio::fs::write(source.join("iaca-keys").join("README.txt"), b"ignored")
        .await
        .expect("non-PEM import fixture");

    let imported_revision = operator_manage_mdoc(
        &config,
        &binding,
        &persistence,
        MdocManagementAction::Import(source.clone()),
    )
    .await
    .expect("operator mDoc import");
    let imported = manager
        .database_openid4vc_state()
        .await
        .expect("imported mDoc state");
    assert_eq!(imported_revision, imported.revision.to_string());

    let rotated_revision = operator_manage_mdoc(
        &config,
        &binding,
        &persistence,
        MdocManagementAction::Rotate,
    )
    .await
    .expect("operator mDoc rotation");
    manager.refresh().await.expect("refresh rotated mDoc state");
    let rotated = manager
        .database_openid4vc_state()
        .await
        .expect("rotated mDoc state");
    assert_eq!(rotated_revision, rotated.revision.to_string());
    assert!(rotated.revision > imported.revision);
    let material = rotated.material.expect("rotated mDoc material");
    let active_certificate = parse_certificates(&material.public.certificate_chain_pem)
        .into_iter()
        .next()
        .expect("active DS certificate");
    let active_issuer_id = material
        .iaca_private_materials
        .iter()
        .find_map(|(issuer_id, pem)| {
            (parse_certificates(pem).first() == Some(&active_certificate))
                .then(|| issuer_id.clone())
        })
        .expect("active IACA CRL publication address");

    let revoked_revision = operator_manage_mdoc(
        &config,
        &binding,
        &persistence,
        MdocManagementAction::Revoke {
            issuer_id: active_issuer_id.clone(),
        },
    )
    .await
    .expect("operator mDoc revocation");
    let revoked = manager
        .database_openid4vc_state()
        .await
        .expect("revoked mDoc state");
    assert_eq!(revoked_revision, revoked.revision.to_string());
    let entry = revoked
        .material
        .as_ref()
        .and_then(|material| material.public.revocation_snapshot.as_ref())
        .and_then(|snapshot| {
            snapshot.entries.iter().find(|entry| {
                entry.status == nazo_digital_credentials::CertificateRevocationStatus::Revoked
            })
        })
        .expect("revoked DS entry");
    assert!(entry.revoked_at.is_some());

    let unchanged_revision = operator_manage_mdoc(
        &config,
        &binding,
        &persistence,
        MdocManagementAction::Revoke {
            issuer_id: active_issuer_id,
        },
    )
    .await
    .expect("repeated mDoc revocation");
    assert_eq!(unchanged_revision, revoked_revision);
    assert!(
        operator_manage_mdoc(
            &config,
            &binding,
            &persistence,
            MdocManagementAction::Revoke {
                issuer_id: "unknown-iaca".to_owned(),
            },
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("unknown IACA CRL publication address")
    );

    tokio::fs::remove_dir_all(source)
        .await
        .expect("mDoc import fixture cleanup");
}

#[tokio::test]
async fn certificate_import_without_mdoc_keeps_an_empty_revocation_snapshot() {
    let source = temporary_directory("certificate-import-source");
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let (manager, _, active_key) = database_manager_with_mdoc_key(repository, tenant_id).await;
    let profile = Openid4vcCertificateProfile {
        hostname: "tenant.example".to_owned(),
        mdoc_profile: None,
    };
    let material = build_managed_material(&active_key.serialize_pem(), &profile, None)
        .expect("certificate import material");
    tokio::fs::create_dir_all(&source)
        .await
        .expect("certificate import directory");
    tokio::fs::write(
        source.join("certificate-bundle.pem"),
        &material.public.certificate_chain_pem,
    )
    .await
    .expect("certificate import bundle");

    import_mdoc_directory(&manager, &profile, &source)
        .await
        .expect("certificate import without mDoc state");
    let imported = manager
        .database_openid4vc_state()
        .await
        .expect("imported certificate state")
        .material
        .expect("imported certificate material");
    assert!(imported.iaca_private_materials.is_empty());
    assert!(
        imported
            .public
            .revocation_snapshot
            .expect("empty revocation snapshot")
            .entries
            .is_empty()
    );

    tokio::fs::remove_dir_all(source)
        .await
        .expect("certificate import fixture cleanup");
}

async fn crl_fixture() -> (
    Arc<MemorySigningKeyRepository>,
    Uuid,
    KeyManager,
    String,
    MdocCrlSource,
) {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let tenant_id = Uuid::now_v7();
    let manager = database_manager(repository.clone(), tenant_id).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .unwrap();
    let material = manager
        .database_openid4vc_state()
        .await
        .unwrap()
        .material
        .unwrap();
    let issuer = material
        .iaca_private_materials
        .keys()
        .next()
        .unwrap()
        .clone();
    let source = MdocCrlSource {
        keyset: manager.clone(),
        issuer_contact_uri: profile.mdoc_profile.unwrap().issuer_contact_uri,
    };
    (repository, tenant_id, manager, issuer, source)
}

async fn replace_only_sealed_private_payload(
    repository: &MemorySigningKeyRepository,
    tenant_id: Uuid,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut record = repository.load().await.unwrap().unwrap();
    let expected = record.revision;
    let ring =
        SigningKeyWrappingKeyRing::new("keyctl-test-root", test_wrapping_key(), None).unwrap();

    let mut payload: serde_json::Value = serde_json::from_slice(
        ring.open_generation(tenant_id, &mut record.clone())
            .unwrap(),
    )
    .unwrap();
    mutate(&mut payload);
    record.revision += 1;
    record.encrypted_private_material = ring
        .seal_generation(
            tenant_id,
            record.revision,
            &record.public_metadata,
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        repository.compare_and_swap(expected, record).await.unwrap(),
        nazo_key_management::SigningKeysetCompareAndSwapResult::Applied(_)
    ));
}

#[tokio::test]
async fn mdoc_crl_ignores_unrelated_private_rsa_preparation() {
    let (repository, tenant_id, manager, issuer, source) = crl_fixture().await;
    let material = manager
        .database_openid4vc_state()
        .await
        .unwrap()
        .material
        .unwrap();
    let chain = iaca_certificates(&material, &issuer);
    replace_only_sealed_private_payload(&repository, tenant_id, |payload| {
        payload["request_object_private_pem"] = serde_json::json!("not-rsa-pem");
        let mut rsa_keys = 0;
        for key in payload["keys"].as_array_mut().unwrap() {
            if matches!(key["alg"].as_str(), Some("RS256" | "PS256")) {
                key["private_pkcs8_der"] = serde_json::json!("not-rsa-der");
                rsa_keys += 1;
            }
        }
        assert!(rsa_keys > 0);
    })
    .await;
    assert!(
        manager.database_openid4vc_state().await.is_err(),
        "whole-generation diagnostics still reject unrelated invalid private keys"
    );
    let der = signed_mdoc_crl(&source, &issuer).await.unwrap().unwrap();
    let (_, crl) = x509_parser::parse_x509_crl(&der).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(chain[1].as_ref()).unwrap();
    crl.verify_signature(ca.public_key()).unwrap();
    assert_eq!(crl.iter_revoked_certificates().count(), 0);
    assert!(
        signed_mdoc_crl(&source, &"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    assert!(signed_mdoc_crl(&source, "invalid").await.unwrap().is_none());
}

#[tokio::test]
async fn mdoc_crl_rejects_selected_iaca_private_key_mismatch() {
    let (repository, tenant_id, _, issuer, source) = crl_fixture().await;
    let wrong_key = nazo_crypto::certificate::generate_p256_private_key_pem().unwrap();
    replace_only_sealed_private_payload(&repository, tenant_id, |payload| {
        let pem = payload["openid4vc"]["iaca_private_materials"][&issuer]
            .as_str()
            .unwrap();
        let certificate_start = pem.find("-----BEGIN CERTIFICATE-----").unwrap();
        payload["openid4vc"]["iaca_private_materials"][&issuer] =
            serde_json::json!(format!("{}{}", wrong_key, &pem[certificate_start..]));
    })
    .await;
    assert!(signed_mdoc_crl(&source, &issuer).await.is_err());
}

#[tokio::test]
async fn mdoc_crl_pins_captured_revocation_and_next_read_observes_concurrent_revoke() {
    let repository = Arc::new(MemorySigningKeyRepository::default());
    let binding = tenant_binding("https://tenant.example");
    let config = mdoc_database_config(&temporary_directory("crl-concurrent-revoke"));
    let manager = database_manager(repository.clone(), binding.tenant.tenant_id.as_uuid()).await;
    let profile = managed_profile("tenant.example");
    generate_local_with_database_manager(&manager, Some(&profile), managed_options())
        .await
        .unwrap();
    let material = manager
        .database_openid4vc_state()
        .await
        .unwrap()
        .material
        .unwrap();
    let issuer = material
        .iaca_private_materials
        .keys()
        .next()
        .unwrap()
        .clone();
    let chain = iaca_certificates(&material, &issuer);
    let source = MdocCrlSource {
        keyset: manager,
        issuer_contact_uri: profile.mdoc_profile.unwrap().issuer_contact_uri,
    };
    let persistence = MemoryOperatorPersistence {
        repository: repository.clone(),
    };
    // Establish the published generation before pausing an authoritative read.
    // A first-publication CAS that races revocation must instead retry against
    // the winning facts; only an already published version may be returned
    // from the earlier captured read.
    signed_mdoc_crl(&source, &issuer).await.unwrap().unwrap();
    let barrier = repository.pause_next_load();
    let (captured, ()) = tokio::join!(signed_mdoc_crl(&source, &issuer), async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            barrier.captured.notified(),
        )
        .await
        .expect("captured generation");
        operator_manage_mdoc(
            &config,
            &binding,
            &persistence,
            MdocManagementAction::Revoke {
                issuer_id: issuer.clone(),
            },
        )
        .await
        .unwrap();
        barrier.release.notify_one();
    });
    let captured = captured.unwrap().unwrap();
    let (_, old_crl) = x509_parser::parse_x509_crl(&captured).unwrap();
    let fresh = signed_mdoc_crl(&source, &issuer).await.unwrap().unwrap();
    let (_, new_crl) = x509_parser::parse_x509_crl(&fresh).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(chain[1].as_ref()).unwrap();
    old_crl.verify_signature(ca.public_key()).unwrap();
    new_crl.verify_signature(ca.public_key()).unwrap();
    assert_eq!(old_crl.iter_revoked_certificates().count(), 0);
    assert_eq!(new_crl.iter_revoked_certificates().count(), 1);
    assert!(new_crl.crl_number() > old_crl.crl_number());
    let (_, ds) = x509_parser::parse_x509_certificate(chain[0].as_ref()).unwrap();
    assert_eq!(
        new_crl
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .raw_serial(),
        ds.raw_serial()
    );
}

#[test]
fn iaca_profile_uses_twenty_calendar_years_including_century_month_end() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let profile = managed_profile("issuer.example");
    let material = build_managed_material(&key.serialize_pem(), &profile, None).unwrap();
    let (id, pem) = material.iaca_private_materials.iter().next().unwrap();
    let chain = iaca_certificates(&material, id);
    let (_, original_ca) = x509_parser::parse_x509_certificate(chain[1].as_ref()).unwrap();
    let datetime = |year, month, day| {
        time::Date::from_calendar_date(year, month, day)
            .unwrap()
            .with_hms(12, 34, 56)
            .unwrap()
            .assume_utc()
    };
    for (start, limit) in [
        (
            datetime(2026, time::Month::November, 17),
            datetime(2046, time::Month::November, 17),
        ),
        (
            datetime(2080, time::Month::February, 29),
            datetime(2100, time::Month::February, 28),
        ),
    ] {
        for exceeds in [false, true] {
            let der = reissue_test_iaca(
                pem,
                &original_ca,
                profile.mdoc_profile.as_ref().unwrap(),
                id,
                |params| {
                    params.not_before = start;
                    params.not_after = limit + time::Duration::seconds(i64::from(exceeds));
                },
            );
            let (_, ca) = x509_parser::parse_x509_certificate(&der).unwrap();
            nazo_crypto::certificate::verify_signature(&ca, ca.public_key()).unwrap();
            assert_eq!(
                check_mdoc_iaca_profile(&ca).is_ok(),
                !exceeds,
                "start={start}, limit={limit}, exceeds={exceeds}"
            );
        }
    }
    // This is a profile-only boundary test. Real admission separately checks
    // current time, so the deliberately future century fixture is not trusted.
}

#[test]
fn managed_mdoc_certificate_validity_uses_shared_utc_days() {
    // Two unrelated key generations on the same day must not expose their
    // creation second through the MSO's certificate lower bound.
    let day = time::OffsetDateTime::from_unix_timestamp(1_791_590_400).unwrap();
    assert_eq!(day.unix_timestamp().rem_euclid(86_400), 0);
    for offset in [0, 1, 43_217, 86_399, 86_400] {
        let now = day + time::Duration::seconds(offset);
        let key = nazo_crypto::certificate::generate_p256_private_key_pem().unwrap();
        let profile = managed_profile("issuer.example");
        let bundle = build_openid4vc_certificate_bundle(
            &key,
            &profile.hostname,
            profile.mdoc_profile.as_ref(),
            now,
        )
        .unwrap();
        let material = bundle.mdoc_material.unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&material.leaf_der).unwrap();
        let ca_der = parse_certificates(&bundle.ca_pem).remove(0);
        let (_, ca) = x509_parser::parse_x509_certificate(ca_der.as_ref()).unwrap();
        let expected = now.date().midnight().assume_utc().unix_timestamp();
        for (certificate, lifetime) in [(&leaf, 457), (&ca, 3650)] {
            assert_eq!(certificate.validity().not_before.timestamp(), expected);
            assert_eq!(
                certificate.validity().not_after.timestamp(),
                expected + lifetime * 86_400
            );
            assert!(
                certificate.validity().not_after.timestamp()
                    <= now.unix_timestamp() + lifetime * 86_400
            );
        }
        assert!(mdoc_certificate_profile_matches(
            &leaf,
            &ca,
            profile.mdoc_profile.as_ref().unwrap()
        ));
    }
}
