use std::{collections::BTreeSet, sync::Arc};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseKeyBuilder, iana};
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode_header, encode};
use nazo_digital_credentials::{
    CertificateRevocationSnapshot, CredentialFormat, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError, HolderBinding, PresentedCredential, VcIssuerTrustPolicy,
};
use nazo_key_management::{
    KeyManager, KeySettings, LocalKeyRegistration, Openid4vcMaterial, Openid4vcPublicMaterial,
};
use nazo_mdoc::{
    builder::DocumentBuilder,
    model::{
        document::DeviceSigned,
        types::{CoseAlgorithm, DeviceAuth, ValidityInfo},
    },
    session::{RedirectHandover, SessionTranscript, build_device_authentication_bytes},
};
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use sha2::Digest as _;

use super::mdoc::{from_protocol_time, to_protocol_time};
use super::*;

#[cfg(not(target_arch = "wasm32"))]
#[path = "openid4vc_credential_perf.rs"]
mod performance;

fn verify_certificate_chain_at<'a>(
    certificates: &[Vec<u8>],
    anchors: &'a [Vec<u8>],
    time: i64,
) -> Result<Option<&'a [u8]>, CredentialTrustError> {
    super::mdoc::verify_certificate_chain_with_scoped_at(certificates, anchors, &[], time)
}

trait CredentialCryptoTestExt {
    fn verify_sd_jwt(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential<'_>,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    >;

    fn validate_sd_jwt_chain(
        &self,
        x5c: &[String],
        additional_trust_anchors: &[Vec<u8>],
    ) -> Result<super::sd_jwt::ValidatedSdJwtChain, nazo_digital_credentials::CredentialTrustError>;

    fn verify_mdoc(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential<'_>,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    >;
}

impl CredentialCryptoTestExt for Openid4vcCredentialCrypto {
    fn verify_sd_jwt(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential<'_>,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::sd_jwt::verify(self, presentation).map(|(credential, _)| credential)
    }

    fn validate_sd_jwt_chain(
        &self,
        x5c: &[String],
        additional_trust_anchors: &[Vec<u8>],
    ) -> Result<super::sd_jwt::ValidatedSdJwtChain, nazo_digital_credentials::CredentialTrustError>
    {
        super::sd_jwt::validate_sd_jwt_chain(self, x5c, additional_trust_anchors)
    }

    fn verify_mdoc(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential<'_>,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::mdoc::verify(self, presentation, Utc::now()).map(|(credential, _)| credential)
    }
}

pub(super) struct CertificateFixture {
    pub(super) ca_der: Vec<u8>,
    pub(super) ca_pem: String,
    pub(super) leaf_der: Vec<u8>,
    pub(super) leaf_pem: String,
    pub(super) leaf_key: KeyPair,
}

pub(super) fn certificate_fixture(host: &str) -> CertificateFixture {
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    certificate_fixture_with_key(host, leaf_key)
}

fn certificate_fixture_with_key(host: &str, leaf_key: KeyPair) -> CertificateFixture {
    certificate_fixture_with_key_and_aki(host, leaf_key, true)
}

fn certificate_fixture_with_key_and_aki(
    host: &str,
    leaf_key: KeyPair,
    include_aki: bool,
) -> CertificateFixture {
    certificate_fixture_with_parameters(host, leaf_key, include_aki, |_, _| {})
}

fn certificate_fixture_with_parameters(
    host: &str,
    leaf_key: KeyPair,
    include_aki: bool,
    edit: impl FnOnce(&mut CertificateParams, &mut CertificateParams),
) -> CertificateFixture {
    certificate_fixture_with_wire_edit(host, leaf_key, include_aki, edit, |der, _| der)
}

// A test can construct malformed but genuinely signed certificate fields that
// the safe certificate generator intentionally refuses to create.
fn certificate_fixture_with_wire_edit(
    host: &str,
    leaf_key: KeyPair,
    include_aki: bool,
    edit: impl FnOnce(&mut CertificateParams, &mut CertificateParams),
    wire_edit: impl FnOnce(Vec<u8>, &KeyPair) -> Vec<u8>,
) -> CertificateFixture {
    let now = time::OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenID4VC test root");
    ca_params.distinguished_name.push(
        DnType::CountryName,
        rcgen::DnValue::PrintableString("US".try_into().unwrap()),
    );
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.key_identifier_method =
        rcgen::KeyIdMethod::PreSpecified(sha1::Sha1::digest(ca_key.public_key_raw()).to_vec());
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::days(365);
    let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).expect("leaf SAN");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    leaf_params.distinguished_name.push(
        DnType::CountryName,
        rcgen::DnValue::PrintableString("US".try_into().unwrap()),
    );
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = include_aki;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::days(365);
    // ISO 18013-5 Annex B.1.4: critical ExtendedKeyUsage with id-kp-mdlDS.
    // DER SEQUENCE { OBJECT IDENTIFIER 1.0.18013.5.1.2 }.
    let mut eku = rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        vec![
            0x30, 0x09, 0x06, 0x07, 0x28, 0x81, 0x8c, 0x5d, 0x05, 0x01, 0x02,
        ],
    );
    eku.set_criticality(true);
    leaf_params.custom_extensions.push(eku);
    leaf_params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            yasna::construct_der(|writer| {
                writer.write_bytes(&sha1::Sha1::digest(leaf_key.public_key_raw()))
            }),
        ));
    leaf_params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 18],
            yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer
                        .next()
                        .write_tagged_implicit(yasna::Tag::context(6), |writer| {
                            writer.write_ia5_string("https://issuer.example");
                        });
                });
            }),
        ));
    leaf_params
        .crl_distribution_points
        .push(rcgen::CrlDistributionPoint {
            uris: vec!["https://issuer.example/test-issuer.crl".to_owned()],
        });
    edit(&mut ca_params, &mut leaf_params);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed CA");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca)
        .expect("leaf certificate");
    let leaf_der = wire_edit(leaf.der().as_ref().to_vec(), ca.key());
    let leaf_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&leaf_der)
    );

    CertificateFixture {
        ca_der: ca.der().as_ref().to_vec(),
        ca_pem: ca.pem(),
        leaf_der,
        leaf_pem,
        leaf_key,
    }
}

pub(super) async fn real_crypto_fixture() -> (Openid4vcCredentialCrypto, CertificateFixture, String)
{
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(1),
        prepublish_window: chrono::Duration::hours(1),
        verification_grace: chrono::Duration::hours(1),
    };
    let keyset = nazo_key_management::test_support::key_manager(settings)
        .await
        .expect("database-backed credential keyset should initialize");
    let kid = keyset
        .database_register_local(LocalKeyRegistration {
            algorithm: Algorithm::ES256,
            purposes: [
                nazo_auth::SigningPurpose::Credential,
                nazo_auth::SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        })
        .await
        .expect("database credential key should register");
    let leaf_pem = keyset
        .database_local_private_key_pem(&kid)
        .expect("database credential private key should be available");
    let leaf_key = KeyPair::from_pem(&leaf_pem).expect("credential private key should parse");
    let certs = certificate_fixture_with_key("issuer.example", leaf_key);
    let crypto = crypto_with_certificate(
        keyset,
        &certs,
        crate::policy::Openid4vcRevocationPolicy::Disabled,
    );
    (crypto, certs, kid)
}

fn crypto_with_certificate(
    keyset: nazo_key_management::KeyManager,
    certs: &CertificateFixture,
    revocation_policy: crate::policy::Openid4vcRevocationPolicy,
) -> Openid4vcCredentialCrypto {
    let signing_kid = keyset
        .snapshot()
        .signing_verification_key(
            nazo_auth::SigningPurpose::Credential,
            jsonwebtoken::Algorithm::ES256,
        )
        .expect("fixture credential key")
        .kid
        .clone();
    keyset.set_openid4vc_material_for_test(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid,
            certificate_chain_pem: format!("{}{}", certs.leaf_pem, certs.ca_pem),
            trust_anchors_pem: certs.ca_pem.clone(),
            revocation_snapshot: None,
        },
        iaca_private_materials: Default::default(),
    });
    Openid4vcCredentialCrypto::new_with_policies(
        keyset,
        VcIssuerTrustPolicy::san_bound(),
        revocation_policy,
    )
    .expect("fixture OpenID4VC material should validate")
}

pub(super) fn valid_mdoc_presentation(
    certs: &CertificateFixture,
    signed_at: chrono::DateTime<Utc>,
    status: Option<ciborium::Value>,
) -> (String, Vec<u8>) {
    use p256::elliptic_curve::Generate as _;
    let secret = p256::SecretKey::generate();
    let holder = SigningKey::from_slice(&secret.to_bytes()).expect("device signing key");
    valid_mdoc_presentation_with_holder(certs, signed_at, status, &holder)
}

fn valid_mdoc_presentation_with_holder(
    certs: &CertificateFixture,
    signed_at: chrono::DateTime<Utc>,
    status: Option<ciborium::Value>,
    device_signing_key: &SigningKey,
) -> (String, Vec<u8>) {
    let issuer_secret =
        p256::SecretKey::from_pkcs8_der(&certs.leaf_key.serialize_der()).expect("leaf private key");
    let issuer_signing_key =
        SigningKey::from_slice(&issuer_secret.to_bytes()).expect("leaf signing key");
    let device_point = device_signing_key.verifying_key().to_sec1_point(false);
    let device_key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        device_point.x().expect("device x").to_vec(),
        device_point.y().expect("device y").to_vec(),
    )
    .build();
    let now = Utc::now();
    let builder = DocumentBuilder::new("org.iso.18013.5.1.mDL")
        .device_key(device_key)
        .validity(ValidityInfo {
            signed: to_protocol_time(signed_at).unwrap(),
            valid_from: to_protocol_time(signed_at.max(now - Duration::minutes(1))).unwrap(),
            valid_until: to_protocol_time(now + Duration::hours(1)).unwrap(),
            expected_update: None,
        })
        .add_namespace(
            "org.iso.18013.5.1",
            vec![
                ("given_name", ciborium::Value::Text("Ada".to_owned())),
                ("age", ciborium::Value::Integer(42.into())),
            ],
        );
    let builder = match status {
        Some(status) => builder.status_raw(status),
        None => builder,
    };
    let prepared = builder
        .prepare(CoseAlgorithm::ES256, vec![certs.leaf_der.clone()])
        .expect("prepared issuer-signed mdoc");
    let issuer_signature: p256::ecdsa::Signature =
        issuer_signing_key.sign(prepared.signing_input());
    let mut document = prepared
        .finish(issuer_signature.to_bytes().to_vec())
        .expect("issuer-signed mdoc");
    let transcript = SessionTranscript::redirect(RedirectHandover {
        client_id: "https://verifier.example",
        nonce: "verifier-nonce",
        jwk_thumbprint: None,
        response_uri: "https://verifier.example/response",
    })
    .expect("Final redirect transcript");
    let transcript_bytes = transcript.into_bytes();
    let name_spaces_bytes = vec![0xd8, 0x18, 0x41, 0xa0];
    let device_authentication = build_device_authentication_bytes(
        &transcript_bytes,
        &document.doc_type,
        &name_spaces_bytes,
    )
    .expect("DeviceAuthenticationBytes");
    let signature = coset::CoseSign1Builder::new()
        .protected(
            coset::HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .build(),
        )
        .create_detached_signature(&device_authentication, &[], |tbs| {
            let signature: p256::ecdsa::Signature = device_signing_key.sign(tbs);
            signature.to_bytes().to_vec()
        })
        .build();
    document.device_signed = Some(DeviceSigned {
        device_auth: DeviceAuth::Signature(signature),
        name_spaces: Default::default(),
        name_spaces_bytes,
    });
    (
        URL_SAFE_NO_PAD.encode(
            document
                .to_device_response_cbor()
                .expect("device response CBOR"),
        ),
        transcript_bytes,
    )
}

#[test]
fn mdoc_time_conversion_preserves_nanoseconds_and_whole_leap_seconds() {
    for text in [
        "1969-12-31T23:59:59.999999999Z",
        "2026-11-17T12:00:00.123456789Z",
        "2016-12-31T23:59:60Z",
    ] {
        let original = chrono::DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc);
        let protocol = to_protocol_time(original).unwrap();
        assert_eq!(from_protocol_time(protocol).unwrap(), original);
        if text.contains(":60Z") {
            assert!(protocol.is_leap_second());
            assert!(protocol.unix_seconds().is_none());
        }
    }
    let fractional_leap = chrono::DateTime::parse_from_rfc3339("2016-12-31T23:59:60.5Z")
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(
        to_protocol_time(fractional_leap),
        Err(CredentialTrustError::InvalidValidity)
    );
}

fn sd_input(
    holder_binding: Option<HolderBinding>,
    subject_claims: Value,
    status: Option<Value>,
) -> CredentialSignInput {
    let issued_at = Utc::now() - Duration::minutes(1);
    CredentialSignInput {
        payload: nazo_digital_credentials::CredentialPayload {
            format: CredentialFormat::SdJwtVc,
            issuer: "https://issuer.example".to_owned(),
            configuration_id: "example-sd-jwt".to_owned(),
            credential_type: "ExampleCredential".to_owned(),
            subject_claims,
            holder_binding,
        },
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        status,
    }
}

fn mdoc_input(holder_binding: Option<HolderBinding>, subject_claims: Value) -> CredentialSignInput {
    let issued_at = Utc::now() - Duration::minutes(1);
    CredentialSignInput {
        payload: nazo_digital_credentials::CredentialPayload {
            format: CredentialFormat::MsoMdoc,
            issuer: "https://issuer.example".to_owned(),
            configuration_id: "example-mdoc".to_owned(),
            credential_type: "org.iso.18013.5.1.mDL".to_owned(),
            subject_claims,
            holder_binding,
        },
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        status: None,
    }
}

fn es256_jwk(seed: u8) -> (Value, EncodingKey) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).expect("P-256 key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
    });
    let der = signing_key.to_pkcs8_der().expect("PKCS#8");
    (jwk, EncodingKey::from_ec_der(der.as_bytes()))
}

pub(super) fn sd_presentation_fixture() -> (
    Openid4vcCredentialCrypto,
    PresentedCredential<'static>,
    Value,
    CertificateFixture,
) {
    sd_presentation_fixture_with_aki(true)
}

fn sd_presentation_fixture_with_aki(
    include_aki: bool,
) -> (
    Openid4vcCredentialCrypto,
    PresentedCredential<'static>,
    Value,
    CertificateFixture,
) {
    let certs = certificate_fixture_with_key_and_aki(
        "issuer.example",
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key"),
        include_aki,
    );
    let (holder_jwk, holder_key) = es256_jwk(71);
    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let disclosure = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!(["salt", "given_name", "Ada"])).expect("disclosure"));
    let issued_at = Utc::now() - Duration::minutes(1);
    let credential_claims = json!({
        "iss": "https://issuer.example",
        "iat": issued_at.timestamp(),
        "nbf": issued_at.timestamp(),
        "exp": (issued_at + Duration::hours(1)).timestamp(),
        "vct": "ExampleCredential",
        "_sd_alg": "sha-256",
        "_sd": [URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(disclosure.as_bytes()))],
        "cnf": {"jwk": holder_jwk},
    });
    let mut credential_header = Header::new(Algorithm::ES256);
    credential_header.typ = Some("dc+sd-jwt".to_owned());
    credential_header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let credential_jwt =
        encode(&credential_header, &credential_claims, &issuer_key).expect("credential JWT");
    let expected_audience = "https://verifier.example";
    let expected_nonce = "nonce-1";
    let sd_input = format!("{credential_jwt}~{disclosure}~");
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let kb_jwt = encode(
        &kb_header,
        &json!({
            "nonce": expected_nonce,
            "aud": expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes())),
        }),
        &holder_key,
    )
    .expect("key binding JWT");
    let encoded = format!("{credential_jwt}~{disclosure}~{kb_jwt}");
    let presentation = PresentedCredential {
        format: CredentialFormat::SdJwtVc,
        encoded: encoded.into(),
        expected_nonce: expected_nonce.into(),
        expected_audience: expected_audience.into(),
        mdoc_session_transcript: None,
        additional_trust_anchors: vec![].into(),
    };
    let crypto = crypto_with_certificate(
        nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        &certs,
        crate::policy::Openid4vcRevocationPolicy::Disabled,
    );
    (crypto, presentation, json!("Ada"), certs)
}

#[test]
fn scoped_trust_anchors_require_a_bounded_unique_current_ca_set() {
    let certs = certificate_fixture("issuer.example");
    let other = certificate_fixture("other-issuer.example");
    assert_eq!(
        parse_scoped_credential_trust_anchors(&certs.ca_pem).expect("valid CA"),
        vec![certs.ca_der.clone()]
    );
    assert_eq!(
        parse_scoped_credential_trust_anchors(&format!("{}{}", certs.ca_pem, other.ca_pem))
            .expect("two independent CA anchors"),
        vec![certs.ca_der.clone(), other.ca_der]
    );
    assert!(parse_scoped_credential_trust_anchors("").is_err());
    assert!(
        parse_scoped_credential_trust_anchors(&format!("{}{}", certs.ca_pem, certs.ca_pem))
            .is_err()
    );
    assert!(parse_scoped_credential_trust_anchors(&certs.leaf_pem).is_err());
    assert!(
        parse_scoped_credential_trust_anchors(
            "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----"
        )
        .is_err()
    );
}

#[test]
fn constructor_fails_closed_without_managed_material() {
    assert!(
        Openid4vcCredentialCrypto::new_with_policies(
            nazo_key_management::KeyManager::for_test(Algorithm::ES256),
            VcIssuerTrustPolicy::san_bound(),
            crate::policy::Openid4vcRevocationPolicy::Disabled,
        )
        .is_err()
    );
}

#[test]
fn request_and_metadata_signing_emit_required_jose_headers() {
    futures_executor::block_on(async {
        let (crypto, certs, kid) = real_crypto_fixture().await;
        let expected_x5c = vec![STANDARD.encode(&certs.leaf_der)];
        let lease = crypto.prepare_signing().expect("signing lease");
        let request = crypto
            .sign_request_object(
                crypto.signing_material(lease).expect("signing material"),
                &json!({"client_id": "wallet", "response_type": ["vp_token"]}),
            )
            .await
            .expect("request object");
        let request_header = decode_header(&request).expect("request header");
        assert_eq!(request_header.typ.as_deref(), Some("oauth-authz-req+jwt"));
        assert_eq!(request_header.alg, Algorithm::ES256);
        assert_eq!(request_header.kid.as_deref(), Some(kid.as_str()));
        assert_eq!(request_header.x5c.as_ref(), Some(&expected_x5c));

        let metadata = crypto
            .sign_issuer_metadata(&json!({"credential_issuer": "https://issuer.example"}))
            .await
            .expect("issuer metadata");
        let metadata_header = decode_header(&metadata).expect("metadata header");
        assert_eq!(
            metadata_header.typ.as_deref(),
            Some("openidvci-issuer-metadata+jwt")
        );
        assert_eq!(metadata_header.alg, Algorithm::ES256);
        assert_eq!(metadata_header.kid.as_deref(), Some(kid.as_str()));
        assert_eq!(metadata_header.x5c.as_ref(), Some(&expected_x5c));
    })
}

#[test]
fn request_and_metadata_signing_map_key_failures_to_errors() {
    futures_executor::block_on(async {
        let certs = certificate_fixture("issuer.example");
        let failing_keyset = nazo_key_management::KeyManager::for_test_behavior(
            Algorithm::ES256,
            nazo_key_management::TestSigningBehavior::Failing,
        );
        let crypto = crypto_with_certificate(
            failing_keyset,
            &certs,
            crate::policy::Openid4vcRevocationPolicy::Disabled,
        );
        assert!(
            crypto
                .sign_request_object(
                    crypto
                        .signing_material(crypto.prepare_signing().expect("failing signing lease"))
                        .expect("signing material"),
                    &json!({"iss": "issuer"}),
                )
                .await
                .is_err()
        );
        assert!(
            crypto
                .sign_issuer_metadata(&json!({"iss": "issuer"}))
                .await
                .is_err()
        );
    })
}

#[test]
fn certificate_client_ids_bind_to_hash_and_dns_san() {
    let certs = certificate_fixture("issuer.example");
    let crypto = crypto_with_certificate(
        nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        &certs,
        crate::policy::Openid4vcRevocationPolicy::Disabled,
    );
    let lease = crypto.prepare_signing().expect("signing lease");
    let material = crypto.signing_material(lease).expect("signing material");
    assert_eq!(
        material.x509_hash_client_id(),
        format!(
            "x509_hash:{}",
            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certs.leaf_der))
        )
    );
    assert_eq!(
        material.x509_san_dns_client_id().expect("DNS SAN"),
        "x509_san_dns:issuer.example"
    );
}

#[test]
fn sd_jwt_signing_supports_disclosures_holder_binding_and_status() {
    futures_executor::block_on(async {
        let (holder_jwk, _) = es256_jwk(17);
        let input = sd_input(
            Some(HolderBinding::Jwk {
                jwk: holder_jwk.clone(),
            }),
            json!({"given_name": "Ada", "age": 42, "nested": {"items": [null, true, "Ada", 42]}}),
            Some(json!({"idx": 2, "uri": "https://status.example"})),
        );
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (_, leaf) =
            x509_parser::parse_x509_certificate(&certs.leaf_der).expect("leaf certificate");
        let decoding_key = nazo_crypto::jwt::VerificationKey::from_ec_sec1(
            leaf.public_key().subject_public_key.data.as_ref(),
        );
        let encoded = crypto.sign(&input).await.expect("SD-JWT signing");
        let parts = encoded.split('~').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        assert!(parts[0].split('.').count() == 3);
        assert_eq!(parts.last(), Some(&""));
        let header = decode_header(parts[0]).expect("SD-JWT header");
        assert_eq!(header.typ.as_deref(), Some("dc+sd-jwt"));
        let claims: Value = nazo_crypto::jwt::decode(
            parts[0],
            &decoding_key,
            &jsonwebtoken::Validation::new(Algorithm::ES256),
        )
        .expect("decode SD-JWT")
        .claims;
        assert_eq!(claims["vct"], "ExampleCredential");
        assert_eq!(claims["cnf"]["jwk"], holder_jwk);
        for disclosure in &parts[1..parts.len() - 1] {
            let decoded = URL_SAFE_NO_PAD.decode(disclosure).unwrap();
            let fields: Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(fields.as_array().unwrap().len(), 3);
            let name = fields[1].as_str().unwrap();
            assert_eq!(fields[2], input.payload.subject_claims[name]);
            assert!(claims["_sd"].as_array().unwrap().contains(&json!(
                URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(disclosure.as_bytes()))
            )));
        }

        let empty = crypto
            .sign(&sd_input(None, json!({}), None))
            .await
            .expect("SD-JWT without disclosures");
        let (jwt, suffix) = empty.split_once('~').unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        assert_eq!(suffix, "");
        let empty_claims: Value = nazo_crypto::jwt::decode(
            jwt,
            &decoding_key,
            &jsonwebtoken::Validation::new(Algorithm::ES256),
        )
        .expect("decode SD-JWT without disclosures")
        .claims;
        assert!(empty_claims.get("_sd").is_none());

        let malformed = sd_input(None, json!("not an object"), None);
        assert_eq!(
            crypto.sign(&malformed).await,
            Err(CredentialTrustError::InvalidEncoding)
        );
        for name in [
            "iss",
            "nbf",
            "exp",
            "cnf",
            "vct",
            "vct#integrity",
            "aka_vcts",
            "status",
            "_sd",
            "_sd_alg",
            "...",
        ] {
            let forbidden = sd_input(None, json!({name: "subject-controlled"}), None);
            assert_eq!(
                crypto.sign(&forbidden).await,
                Err(CredentialTrustError::InvalidEncoding),
                "{name}"
            );
        }
    })
}

#[test]
fn mdoc_signing_covers_holder_and_namespace_encoding_errors() {
    futures_executor::block_on(async {
        let (holder_jwk, _) = es256_jwk(33);
        let (crypto, _, _) = real_crypto_fixture().await;
        let input = mdoc_input(
            Some(HolderBinding::Jwk { jwk: holder_jwk }),
            json!({
                "org.iso.18013.5.1": {
                    "name": "Ada",
                    "issuing_country": "US",
                    "age": 42,
                    "active": true,
                    "score": 1.5,
                    "empty": null,
                    "tags": ["a", 2],
                    "nested": {"ok": true},
                }
            }),
        );
        let encoded = crypto.sign(&input).await.expect("mDoc signing");
        assert!(!encoded.is_empty());
        assert!(URL_SAFE_NO_PAD.decode(encoded).is_ok());

        assert_eq!(
            crypto.sign(&mdoc_input(None, json!({"ns": {}}))).await,
            Err(CredentialTrustError::InvalidHolderBinding)
        );
        assert_eq!(
            crypto
                .sign(&mdoc_input(
                    Some(HolderBinding::Jwk {
                        jwk: json!({"kty": "RSA"})
                    }),
                    json!({"org.iso.18013.5.1": {"issuing_country": "US"}}),
                ))
                .await,
            Err(CredentialTrustError::InvalidHolderBinding)
        );
        assert_eq!(
            crypto
                .sign(&mdoc_input(
                    Some(HolderBinding::Jwk {
                        jwk: json!({"kty": "EC", "crv": "P-256", "x": "bad", "y": "bad"})
                    }),
                    json!({"org.iso.18013.5.1": {"issuing_country": "US"}}),
                ))
                .await,
            Err(CredentialTrustError::InvalidHolderBinding)
        );
        let (valid_jwk, _) = es256_jwk(35);
        assert_eq!(
            crypto
                .sign(&mdoc_input(
                    Some(HolderBinding::Jwk {
                        jwk: valid_jwk.clone()
                    }),
                    json!([]),
                ))
                .await,
            Err(CredentialTrustError::InvalidEncoding)
        );
        assert_eq!(
            crypto
                .sign(&mdoc_input(
                    Some(HolderBinding::Jwk { jwk: valid_jwk }),
                    json!({"org.iso.18013.5.1": {"issuing_country": "US"}, "ns": "not an object"}),
                ))
                .await,
            Err(CredentialTrustError::InvalidEncoding)
        );
    })
}

#[test]
fn mdoc_issuance_preserves_privacy_times_within_signing_certificate_validity() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (_, certificate) = x509_parser::parse_x509_certificate(&certs.leaf_der).unwrap();
        let not_before =
            chrono::DateTime::from_timestamp(certificate.validity().not_before.timestamp(), 0)
                .unwrap();
        let not_after =
            chrono::DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0)
                .unwrap();
        let (holder_jwk, _) = es256_jwk(37);
        let mut input = mdoc_input(
            Some(HolderBinding::Jwk { jwk: holder_jwk }),
            json!({"org.iso.18013.5.1": {"issuing_country": "US"}}),
        );
        input.issued_at = not_before - Duration::days(1);
        input.expires_at = not_before + Duration::days(7);
        for issued_at in [input.issued_at, not_before + Duration::seconds(10)] {
            input.issued_at = issued_at;
            let encoded = crypto
                .sign(&input)
                .await
                .expect("credential within certificate validity");
            let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
            let document: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
            let issuer_auth = document
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_text() == Some("issuerAuth"))
                .unwrap()
                .1
                .clone();
            let cose = coset::CoseSign1::from_slice(
                &nazo_mdoc::cbor::data_item::encode_cbor_canonical(&issuer_auth).unwrap(),
            )
            .unwrap();
            let issuer_auth = nazo_mdoc::model::issuer_auth::IssuerAuth::new(cose);
            assert_eq!(
                issuer_auth.certificate_chain_der().unwrap(),
                vec![certs.leaf_der.clone()],
                "IssuerAuth carries the DS, never the configured IACA root"
            );
            let mso = issuer_auth.mso().unwrap();
            assert!(
                mso.validity_info.signed >= to_protocol_time(not_before).unwrap(),
                "published MSO signed time must not precede the pinned certificate"
            );
            assert!(mso.validity_info.signed <= to_protocol_time(not_after).unwrap());
            assert_eq!(
                mso.validity_info.signed,
                to_protocol_time(issued_at.max(not_before)).unwrap()
            );
            assert_eq!(mso.validity_info.valid_from, mso.validity_info.signed);
            assert_eq!(
                mso.validity_info.valid_until,
                to_protocol_time(input.expires_at).unwrap(),
                "certificate alignment must not extend credential expiry"
            );
        }
        input.issued_at = not_before - Duration::days(1);
        input.expires_at = not_before;
        assert_eq!(
            crypto.sign(&input).await,
            Err(CredentialTrustError::InvalidEncoding)
        );
        input.issued_at = not_after + Duration::seconds(1);
        input.expires_at = not_after + Duration::days(1);
        assert_eq!(
            crypto.sign(&input).await,
            Err(CredentialTrustError::InvalidEncoding)
        );
    });
}

#[test]
fn mdoc_issuance_rejects_invalid_ds_purpose_and_issuer_binding() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (holder, _) = es256_jwk(37);
        let input = mdoc_input(
            Some(HolderBinding::Jwk { jwk: holder }),
            json!({"org.iso.18013.5.1":{"issuing_country":"US"}}),
        );
        for case in ["missing_eku", "excess_ku", "country", "state"] {
            let certs = certificate_fixture_with_parameters(
                "issuer.example",
                KeyPair::from_pem(&certs.leaf_key.serialize_pem()).unwrap(),
                true,
                |ca, leaf| match case {
                    "missing_eku" => {
                        leaf.custom_extensions.remove(0);
                    }
                    "excess_ku" => leaf.key_usages.push(KeyUsagePurpose::KeyCertSign),
                    "country" => ca.distinguished_name.push(
                        DnType::CountryName,
                        rcgen::DnValue::PrintableString("CA".try_into().unwrap()),
                    ),
                    "state" => ca
                        .distinguished_name
                        .push(DnType::StateOrProvinceName, "California"),
                    _ => unreachable!(),
                },
            );
            let candidate = crypto_with_certificate(
                crypto.keyset.clone(),
                &certs,
                crate::policy::Openid4vcRevocationPolicy::Disabled,
            );
            assert_eq!(
                candidate.sign(&input).await,
                Err(CredentialTrustError::UntrustedIssuer),
                "{case}"
            );
        }
    });
}

#[test]
fn mdoc_signing_skips_mdl_country_validation_for_other_document_types() {
    futures_executor::block_on(async {
        let (holder_jwk, _) = es256_jwk(34);
        let (crypto, _, _) = real_crypto_fixture().await;
        let mut input = mdoc_input(
            Some(HolderBinding::Jwk { jwk: holder_jwk }),
            json!({"example.namespace": {"value": "accepted"}}),
        );
        input.payload.credential_type = "org.example.other".to_owned();
        let encoded = crypto
            .sign(&input)
            .await
            .expect("non-mDL document should not require an mDL issuing country");
        assert!(!encoded.is_empty());
    })
}

#[test]
fn mdoc_signing_requires_the_issuing_country_from_the_leaf_certificate() {
    futures_executor::block_on(async {
        let (holder_jwk, _) = es256_jwk(36);
        let (crypto, _, _) = real_crypto_fixture().await;
        for claims in [
            json!({"org.iso.18013.5.1": {"family_name":"Lovelace"}}),
            json!({"org.iso.18013.5.1": {"issuing_country": 840}}),
            json!({"org.iso.18013.5.1": {"issuing_country":"us"}}),
            json!({"org.iso.18013.5.1": {"issuing_country":"CA"}}),
        ] {
            assert_eq!(
                crypto
                    .sign(&mdoc_input(
                        Some(HolderBinding::Jwk {
                            jwk: holder_jwk.clone(),
                        }),
                        claims,
                    ))
                    .await,
                Err(CredentialTrustError::InvalidEncoding)
            );
        }
        let encoded = crypto
            .sign(&mdoc_input(
                Some(HolderBinding::Jwk { jwk: holder_jwk }),
                json!({
                    "org.iso.18013.5.1": {
                        "issuing_country":"US",
                        "family_name":"Lovelace"
                    }
                }),
            ))
            .await
            .expect("matching mDL issuing country");
        assert!(!encoded.is_empty());
    })
}

#[test]
fn mdoc_date_tags_are_scoped_to_the_iso_mdl_schema() {
    use super::mdoc::mdoc_element_to_cbor;
    const DOC: &str = "org.iso.18013.5.1.mDL";
    const NS: &str = "org.iso.18013.5.1";
    for (element, text, expected_tag) in [
        ("birth_date", "2000-02-29", 1004),
        ("issue_date", "2026-11-17", 1004),
        ("expiry_date", "2030-11-17", 1004),
        ("issue_date", "2026-11-17T00:00:00Z", 0),
        ("expiry_date", "2030-11-17T23:59:59Z", 0),
        ("portrait_capture_date", "2026-11-17T12:34:56Z", 0),
    ] {
        let value = json!(text);
        assert_eq!(
            mdoc_element_to_cbor(DOC, NS, element, &value).unwrap(),
            ciborium::Value::Tag(expected_tag, Box::new(ciborium::Value::Text(text.into()))),
        );
        for (doc, namespace) in [("org.example.custom", NS), (DOC, "org.example.custom")] {
            assert_eq!(
                mdoc_element_to_cbor(doc, namespace, element, &value).unwrap(),
                ciborium::Value::Text(text.into()),
                "custom schemas must not inherit mDL date semantics",
            );
        }
    }
    for (element, value) in [
        ("birth_date", json!("2025-02-29")),
        ("birth_date", json!("2026-11-17T00:00:00Z")),
        ("birth_date", json!("2026-1-7")),
        ("birth_date", json!(42)),
        ("issue_date", json!("2026-11-17T00:00:00.1Z")),
        ("expiry_date", json!("2030-11-17T00:00:00+00:00")),
        ("portrait_capture_date", json!("2026-11-17")),
    ] {
        assert_eq!(
            mdoc_element_to_cbor(DOC, NS, element, &value),
            Err(CredentialTrustError::InvalidEncoding)
        );
    }
    let privileges = json!([{"vehicle_category_code":"B", "issue_date":"2026-11-17", "expiry_date":"2030-11-17"}]);
    let encoded = mdoc_element_to_cbor(DOC, NS, "driving_privileges", &privileges).unwrap();
    let fields = encoded.as_array().unwrap()[0].as_map().unwrap();
    for name in ["issue_date", "expiry_date"] {
        assert!(matches!(
            fields
                .iter()
                .find(|(key, _)| key.as_text() == Some(name))
                .unwrap()
                .1,
            ciborium::Value::Tag(1004, _)
        ));
    }
    let invalid = json!([{"vehicle_category_code":"B", "issue_date":"2026-11-17T00:00:00Z"}]);
    assert_eq!(
        mdoc_element_to_cbor(DOC, NS, "driving_privileges", &invalid),
        Err(CredentialTrustError::InvalidEncoding)
    );
}

#[test]
fn mdoc_issuance_authenticates_explicit_date_tags_and_preserves_custom_values() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let holder = nazo_digital_credentials::EphemeralEncryptionKey::generate().public_jwk();
        let input = mdoc_input(
            Some(HolderBinding::Jwk { jwk: holder }),
            json!({
                "org.iso.18013.5.1": {"issuing_country":"US", "birth_date":"2000-02-29", "issue_date":"2026-11-17T00:00:00Z"},
                "org.example.custom": {"birth_date":"a custom literal"}
            }),
        );
        let issued = URL_SAFE_NO_PAD
            .decode(crypto.sign(&input).await.unwrap())
            .unwrap();
        let pending = nazo_mdoc::verifier::verify_issued(
            &issued,
            "org.iso.18013.5.1.mDL",
            to_protocol_time(Utc::now()).unwrap(),
        )
        .unwrap();
        let namespaces = &pending.document().issuer_signed.name_spaces;
        let mdl = &namespaces["org.iso.18013.5.1"];
        assert!(matches!(
            mdl.iter()
                .find(|item| item.element_identifier == "birth_date")
                .unwrap()
                .element_value,
            ciborium::Value::Tag(1004, _)
        ));
        assert!(matches!(
            mdl.iter()
                .find(|item| item.element_identifier == "issue_date")
                .unwrap()
                .element_value,
            ciborium::Value::Tag(0, _)
        ));
        assert_eq!(
            namespaces["org.example.custom"][0].element_value,
            ciborium::Value::Text("a custom literal".into())
        );
    });
}

#[test]
fn mdoc_mdl_binary_elements_require_base64url_and_encode_as_bstr() {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"portrait-bytes");
    assert_eq!(
        super::mdoc::mdoc_element_to_cbor(
            "org.iso.18013.5.1.mDL",
            "org.iso.18013.5.1",
            "portrait",
            &json!(encoded),
        )
        .unwrap(),
        ciborium::Value::Bytes(b"portrait-bytes".to_vec())
    );
    assert!(
        super::mdoc::mdoc_element_to_cbor(
            "org.iso.18013.5.1.mDL",
            "org.iso.18013.5.1",
            "portrait",
            &json!("not-base64url-length-one-x"),
        )
        .is_err()
    );
    assert_eq!(
        super::mdoc::mdoc_element_to_cbor(
            "other-document",
            "org.iso.18013.5.1",
            "portrait",
            &json!("plain-text"),
        )
        .unwrap(),
        ciborium::Value::Text("plain-text".to_owned())
    );
}

#[test]
fn sd_jwt_chain_and_combined_anchor_validation_fail_closed() {
    let certs = certificate_fixture("issuer.example");
    let crypto = crypto_with_certificate(
        nazo_key_management::KeyManager::for_test(Algorithm::ES256),
        &certs,
        crate::policy::Openid4vcRevocationPolicy::Disabled,
    );
    let valid = crypto
        .validate_sd_jwt_chain(&[STANDARD.encode(&certs.leaf_der)], &[])
        .expect("valid SD-JWT chain");
    assert_eq!(valid.certificates, vec![certs.leaf_der.clone()]);
    assert_eq!(
        crypto
            .combined_trust_anchors(std::slice::from_ref(&certs.ca_der))
            .unwrap()
            .len(),
        1
    );
    let other_certs = certificate_fixture("other.example");
    assert_eq!(
        crypto
            .combined_trust_anchors(std::slice::from_ref(&other_certs.ca_der))
            .unwrap()
            .len(),
        2
    );
    assert!(crypto.validate_sd_jwt_chain(&[], &[]).is_err());
    assert!(matches!(
        crypto.validate_sd_jwt_chain(&["bad".to_owned()], &[]),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    assert!(matches!(
        crypto.combined_trust_anchors(&[vec![1, 2, 3]]),
        Err(CredentialTrustError::InvalidEncoding)
    ));
    assert!(matches!(
        crypto.combined_trust_anchors(&[certs.leaf_der]),
        Err(CredentialTrustError::UntrustedIssuer)
    ));
}

#[test]
fn current_revocation_policy_preserves_optional_and_required_snapshots() {
    let snapshot = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: Utc::now() - Duration::minutes(1),
        next_update: Utc::now() + Duration::minutes(1),
        entries: Vec::new(),
    };
    for (mode, required) in [
        (crate::policy::Openid4vcRevocationPolicy::Optional, false),
        (crate::policy::Openid4vcRevocationPolicy::Required, true),
    ] {
        let certs = certificate_fixture("issuer.example");
        let keyset = KeyManager::for_test(Algorithm::ES256);
        let signing_kid = keyset.snapshot().active_kid.clone();
        keyset.set_openid4vc_material_for_test(Openid4vcMaterial {
            public: Openid4vcPublicMaterial {
                signing_kid,
                certificate_chain_pem: format!("{}{}", certs.leaf_pem, certs.ca_pem),
                trust_anchors_pem: certs.ca_pem,
                revocation_snapshot: Some(snapshot.clone()),
            },
            iaca_private_materials: Default::default(),
        });
        let crypto = Openid4vcCredentialCrypto::new_with_policies(
            keyset,
            VcIssuerTrustPolicy::san_bound(),
            mode,
        )
        .expect("revocation policy fixture");
        let policy = crypto.current_revocation_policy();
        assert_eq!(policy.is_required(), required);
        assert_eq!(policy.snapshot().as_deref(), Some(&snapshot));
    }
}

#[test]
fn sd_jwt_verification_accepts_valid_holder_binding_and_rejects_tampering() {
    futures_executor::block_on(async {
        let (crypto, presentation, disclosed, _certs) = sd_presentation_fixture();
        let verified = crypto
            .verify_sd_jwt(&presentation)
            .expect("valid SD-JWT presentation");
        let verified_via_port = crypto
            .verify(&presentation)
            .await
            .expect("credential verifier port");
        assert_eq!(verified_via_port, verified);
        assert_eq!(verified.format, CredentialFormat::SdJwtVc);
        assert_eq!(verified.issuer, "https://issuer.example");
        assert_eq!(verified.credential_type, "ExampleCredential");
        assert_eq!(verified.claims["given_name"], disclosed);
        assert_eq!(verified.status, None);
        assert!(verified.holder_key.is_some());

        let mut malformed = presentation.clone();
        malformed.encoded = "broken".into();
        assert_eq!(
            crypto.verify_sd_jwt(&malformed),
            Err(CredentialTrustError::InvalidEncoding)
        );
        let mut wrong_typ = presentation.clone();
        let parts = wrong_typ.encoded.split('~').collect::<Vec<_>>();
        let mut header = decode_header(parts[0]).expect("header");
        header.typ = Some("JWT".to_owned());
        let (_, issuer_key) = es256_jwk(99);
        let claims = json!({"iss": "https://issuer.example", "exp": Utc::now().timestamp() + 300});
        let jwt = encode(&header, &claims, &issuer_key).expect("JWT");
        wrong_typ.encoded = format!("{jwt}~{}~{}", parts[1], parts[2]).into();
        assert_eq!(
            crypto.verify_sd_jwt(&wrong_typ),
            Err(CredentialTrustError::InvalidEncoding)
        );

        // Re-sign only the holder's exact presentation binding. This never
        // changes the issuer-signed disclosure digests or credential JWT.
        let rebind = |sd_input: String| {
            let (_, holder_key) = es256_jwk(71);
            let mut header = Header::new(Algorithm::ES256);
            header.typ = Some("kb+jwt".to_owned());
            let kb_jwt = encode(
                &header,
                &json!({
                    "nonce": &presentation.expected_nonce,
                    "aud": &presentation.expected_audience,
                    "iat": Utc::now().timestamp(),
                    "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes())),
                }),
                &holder_key,
            )
            .expect("fixture holder binding must be signed with its original holder key");
            format!("{sd_input}{kb_jwt}")
        };
        let mut unknown_disclosure = presentation.clone();
        let parts = presentation.encoded.split('~').collect::<Vec<_>>();
        let disclosure =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!(["salt2", "x", 1])).unwrap());
        unknown_disclosure.encoded = format!("{}~{}~{}", parts[0], disclosure, parts[2]).into();
        assert_eq!(
            crypto.verify_sd_jwt(&unknown_disclosure),
            Err(CredentialTrustError::InvalidHolderBinding),
            "changing the disclosure while retaining the original KB JWT breaks sd_hash",
        );
        unknown_disclosure.encoded = rebind(format!("{}~{disclosure}~", parts[0])).into();
        assert_eq!(
            crypto.verify_sd_jwt(&unknown_disclosure),
            Err(CredentialTrustError::InvalidSignature),
            "a valid holder binding cannot authorize an issuer-unsigned disclosure",
        );

        let mut duplicate = presentation.clone();
        duplicate.encoded = rebind(format!("{}~{}~{}~", parts[0], parts[1], parts[1])).into();
        assert_eq!(
            crypto.verify_sd_jwt(&duplicate),
            Err(CredentialTrustError::InvalidEncoding)
        );
    })
}

#[test]
fn sd_jwt_rejects_empty_vct_even_with_a_valid_alias() {
    let (crypto, original, _, certs) = sd_presentation_fixture();
    let jwt = original.encoded.split('~').next().unwrap();
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    claims["vct"] = json!("");
    claims["aka_vcts"] = json!(["urn:example:base"]);
    let presentation = resign_sd_fixture_with_claims(
        &original,
        &certs,
        vec![STANDARD.encode(&certs.leaf_der)],
        &original.expected_nonce,
        &claims,
    );
    assert_eq!(
        crypto.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::InvalidEncoding)
    );
}

#[test]
fn sd_jwt_rejects_invalid_aliases_before_query_matching() {
    let (crypto, original, _, certs) = sd_presentation_fixture();
    let jwt = original.encoded.split('~').next().unwrap();
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    for aliases in [
        json!([]),
        json!([""]),
        json!([claims["vct"]]),
        json!(["urn:example:base", 1]),
        json!("urn:example:base"),
    ] {
        claims["aka_vcts"] = aliases;
        let presentation = resign_sd_fixture_with_claims(
            &original,
            &certs,
            vec![STANDARD.encode(&certs.leaf_der)],
            &original.expected_nonce,
            &claims,
        );
        assert_eq!(
            crypto.verify_sd_jwt(&presentation),
            Err(CredentialTrustError::InvalidEncoding)
        );
    }
}

#[test]
fn sd_jwt_key_binding_requires_type_and_matches_disclosure_hash() {
    let (crypto, presentation, _, certs) = sd_presentation_fixture();
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let (holder_jwk, holder_key) = es256_jwk(71);

    let mut wrong_type_header = Header::new(Algorithm::ES256);
    wrong_type_header.typ = Some("jwt".to_owned());
    let wrong_type_kb = encode(
        &wrong_type_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": "unused",
        }),
        &holder_key,
    )
    .expect("wrong-type key binding");
    let wrong_type = PresentedCredential {
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_type_kb).into(),
        ..presentation.clone()
    };
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_type),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let issued_at = Utc::now() - Duration::minutes(1);
    let mut credential_header = Header::new(Algorithm::ES256);
    credential_header.typ = Some("dc+sd-jwt".to_owned());
    credential_header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let credential_jwt = encode(
        &credential_header,
        &json!({
            "iss": "https://issuer.example",
            "iat": issued_at.timestamp(),
            "nbf": issued_at.timestamp(),
            "exp": (issued_at + Duration::hours(1)).timestamp(),
            "vct": "ExampleCredential",
            "_sd_alg": "sha-256",
            "_sd": [],
            "cnf": {"jwk": holder_jwk},
        }),
        &issuer_key,
    )
    .expect("credential without disclosures");
    let no_disclosure_input = format!("{credential_jwt}~");
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let no_disclosure_kb = encode(
        &kb_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(no_disclosure_input.as_bytes())),
        }),
        &holder_key,
    )
    .expect("empty disclosure key binding");
    let no_disclosure = PresentedCredential {
        encoded: format!("{credential_jwt}~{no_disclosure_kb}").into(),
        ..presentation.clone()
    };
    let verified = crypto
        .verify_sd_jwt(&no_disclosure)
        .expect("empty disclosure presentation");
    assert_eq!(verified.claims["iss"], "https://issuer.example");
    assert_eq!(verified.claims["cnf"]["jwk"], holder_jwk);
    assert!(verified.claims.get("_sd").is_none());
    assert!(verified.claims.get("_sd_alg").is_none());

    for audience in [
        json!([presentation.expected_audience]),
        json!([presentation.expected_audience, "https://other.example"]),
    ] {
        let binding = encode(
            &kb_header,
            &json!({
                "nonce": presentation.expected_nonce,
                "aud": audience,
                "iat": Utc::now().timestamp(),
                "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(no_disclosure_input.as_bytes())),
            }),
            &holder_key,
        )
        .expect("signed array audience");
        let invalid = PresentedCredential {
            encoded: format!("{credential_jwt}~{binding}").into(),
            ..presentation.clone()
        };
        assert_eq!(
            crypto.verify_sd_jwt(&invalid),
            Err(CredentialTrustError::InvalidHolderBinding)
        );
    }

    let wrong_hash_kb = encode(
        &kb_header,
        &json!({
            "nonce": presentation.expected_nonce,
            "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": "not-the-presentation-hash",
        }),
        &holder_key,
    )
    .expect("wrong disclosure hash key binding");
    let wrong_hash = PresentedCredential {
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_hash_kb).into(),
        ..presentation
    };
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_hash),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn sd_jwt_verification_rejects_holder_and_issuer_policy_failures() {
    let (crypto, presentation, _, certs) = sd_presentation_fixture();
    let mut no_anchor = presentation.clone();
    no_anchor.additional_trust_anchors = vec![certs.leaf_der.clone()].into();
    assert_eq!(
        crypto.verify_sd_jwt(&no_anchor),
        Err(CredentialTrustError::UntrustedIssuer)
    );

    let mut no_cnf = presentation.clone();
    let parts = no_cnf.encoded.split('~').collect::<Vec<_>>();
    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let mut header = decode_header(parts[0]).expect("header");
    let claims = json!({
        "iss": "https://issuer.example",
        "exp": Utc::now().timestamp() + 300,
        "_sd_alg": "sha-256",
        "_sd": [],
        "vct": "ExampleCredential",
    });
    header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let jwt = encode(&header, &claims, &issuer_key).expect("JWT");
    no_cnf.encoded = format!("{jwt}~{}", parts[2]).into();
    assert_eq!(
        crypto.verify_sd_jwt(&no_cnf),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let mut wrong_audience = presentation.clone();
    wrong_audience.expected_audience = "https://other.example".into();
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_audience),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    let mut wrong_nonce = presentation.clone();
    wrong_nonce.expected_nonce = "other-nonce".into();
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_nonce),
        Err(CredentialTrustError::InvalidNonce)
    );

    let strict = Openid4vcCredentialCrypto {
        issuer_trust_policy: VcIssuerTrustPolicy::allowlisted(["https://other.example"]),
        ..crypto.clone()
    };
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::UntrustedIssuer)
    );
    let strict_revocation = Openid4vcCredentialCrypto {
        revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
        ..crypto
    };
    assert_eq!(
        strict_revocation.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationSnapshotUnavailable)
    );
}

#[test]
fn mdoc_verification_rejects_missing_transcript_bad_cbor_and_bad_anchors() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let missing_transcript = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: URL_SAFE_NO_PAD.encode([0xa0]).into(),
            expected_nonce: "nonce".into(),
            expected_audience: "aud".into(),
            mdoc_session_transcript: None,
            additional_trust_anchors: vec![].into(),
        };
        assert_eq!(
            crypto.verify_mdoc(&missing_transcript),
            Err(CredentialTrustError::InvalidHolderBinding)
        );
        let bad_cbor = PresentedCredential {
            mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6].into()),
            ..missing_transcript.clone()
        };
        assert_eq!(
            crypto.verify_mdoc(&bad_cbor),
            Err(CredentialTrustError::InvalidEncoding)
        );
        let bad_anchor = PresentedCredential {
            mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6].into()),
            encoded: URL_SAFE_NO_PAD.encode([0xa0]).into(),
            additional_trust_anchors: vec![vec![1, 2, 3]].into(),
            ..missing_transcript
        };
        assert_eq!(
            crypto.verify_mdoc(&bad_anchor),
            Err(CredentialTrustError::InvalidEncoding)
        );
    })
}

#[test]
fn mdoc_verification_accepts_signed_device_response_and_extracts_claims() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        let verified = crypto
            .verify_mdoc(&presentation)
            .expect("signed mdoc presentation");
        assert_eq!(verified.format, CredentialFormat::MsoMdoc);
        assert_eq!(verified.credential_type, "org.iso.18013.5.1.mDL");
        assert_eq!(verified.claims["org.iso.18013.5.1"]["given_name"], "Ada");
        assert_eq!(verified.claims["org.iso.18013.5.1"]["age"], 42);
        assert!(verified.holder_key.is_some());
        assert_eq!(verified.status, None);
        assert_eq!(
            verified.issuer_chain_authority_key_identifiers,
            vec![certificate_subject_key_identifier(&certs.ca_der)]
        );
        assert_eq!(
            verified.issuer,
            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certs.leaf_der))
        );
        let strict_revocation = Openid4vcCredentialCrypto {
            revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
            ..crypto
        };
        assert_eq!(
            strict_revocation.verify_mdoc(&presentation),
            Err(CredentialTrustError::RevocationSnapshotUnavailable)
        );
    })
}

#[test]
fn mdoc_verification_rejects_expired_ds_even_when_mso_is_current() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let now = Utc::now();
        let certs = certificate_fixture_with_parameters(
            "issuer.example",
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
            true,
            |ca, leaf| {
                ca.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
                leaf.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(2);
                leaf.not_after = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
            },
        );
        let signed = now - Duration::minutes(90);
        let (encoded, transcript) = valid_mdoc_presentation(&certs, signed, None);
        assert!(
            verify_certificate_chain_at(
                std::slice::from_ref(&certs.leaf_der),
                std::slice::from_ref(&certs.ca_der),
                signed.timestamp(),
            )
            .unwrap()
            .is_some(),
            "this is an authentic DS that was valid when the MSO was signed"
        );
        assert!(
            verify_certificate_chain_at(
                std::slice::from_ref(&certs.leaf_der),
                std::slice::from_ref(&certs.ca_der),
                now.timestamp(),
            )
            .unwrap()
            .is_none(),
            "the DS is expired at presentation time"
        );
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let session = SessionTranscript::from_cbor(&transcript).unwrap();
        let pending = nazo_mdoc::verifier::verify_presentation(
            &bytes,
            &session,
            &nazo_mdoc::verifier::VerificationOptions {
                now: to_protocol_time(now).unwrap(),
                max_documents: 1,
            },
        )
        .expect("issuer signature, holder proof and current MSO validity are correct");
        assert_eq!(pending.len(), 1);
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![certs.ca_der].into(),
        };
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::UntrustedIssuer),
            "MSO.signed must not replace current-time certificate path validation"
        );
    });
}

#[test]
fn mdoc_verification_preserves_historical_whole_leap_second_with_current_path_time() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let signed = chrono::DateTime::parse_from_rfc3339("2016-12-31T23:59:60Z")
            .unwrap()
            .with_timezone(&Utc);
        let now = chrono::DateTime::parse_from_rfc3339("2017-01-01T00:01:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let certs = certificate_fixture_with_parameters(
            "issuer.example",
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
            true,
            |ca, leaf| {
                let start = time::OffsetDateTime::from_unix_timestamp(
                    (now - Duration::days(1)).timestamp(),
                )
                .unwrap();
                ca.not_before = start;
                ca.not_after = start + time::Duration::days(365);
                leaf.not_before = start;
                leaf.not_after = start + time::Duration::days(30);
            },
        );
        let (encoded, transcript) = valid_mdoc_presentation(&certs, signed, None);
        let encoded =
            resign_mdoc_validity(&encoded, &certs, signed, signed, now + Duration::hours(1));
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![certs.ca_der].into(),
        };
        let (verified, _) = super::mdoc::verify(&crypto, &presentation, now).expect(
            "the current path time is ordinary; the authenticated MSO leap second is preserved",
        );
        assert_eq!(verified.issued_at, Some(signed));
        assert_eq!(
            verified.issued_at.unwrap().timestamp_subsec_nanos(),
            1_000_000_000
        );
    });
}

#[test]
fn mdoc_verification_rejects_signing_before_certificate_validity() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let now = Utc::now();
        let (encoded, transcript) = valid_mdoc_presentation(&certs, now, None);
        let encoded = resign_mdoc_validity(
            &encoded,
            &certs,
            now - Duration::hours(1),
            now,
            now + Duration::minutes(10),
        );
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        assert!(
            verify_certificate_chain_at(
                std::slice::from_ref(&certs.leaf_der),
                std::slice::from_ref(&certs.ca_der),
                Utc::now().timestamp(),
            )
            .expect("certificate is valid at presentation time")
            .is_some()
        );
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidValidity)
        );
    })
}

#[test]
fn certificate_chain_at_checks_leaf_intermediates_anchor_and_time() {
    let certs = certificate_fixture("issuer.example");
    let now = Utc::now().timestamp();
    assert!(
        verify_certificate_chain_at(
            std::slice::from_ref(&certs.leaf_der),
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("valid chain")
        .is_some()
    );
    assert!(
        verify_certificate_chain_at(
            std::slice::from_ref(&certs.ca_der),
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("CA as leaf is a normal false result")
        .is_none()
    );
    assert!(matches!(
        verify_certificate_chain_at(&[vec![1, 2, 3]], std::slice::from_ref(&certs.ca_der), now),
        Ok(None)
    ));
    assert!(
        verify_certificate_chain_at(std::slice::from_ref(&certs.leaf_der), &[], now,)
            .expect("unanchored chain")
            .is_none()
    );
    assert!(matches!(
        verify_certificate_chain_at(
            std::slice::from_ref(&certs.leaf_der),
            std::slice::from_ref(&certs.ca_der),
            i64::MAX
        ),
        Ok(None)
    ));
}

#[test]
fn mdoc_verification_rejects_a_scoped_iaca_used_as_document_signer() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        let ca = params.self_signed(&key).unwrap();
        let certs = CertificateFixture {
            ca_der: ca.der().to_vec(),
            ca_pem: ca.pem(),
            leaf_der: ca.der().to_vec(),
            leaf_pem: ca.pem(),
            leaf_key: key,
        };
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![certs.ca_der].into(),
        };
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::UntrustedIssuer),
            "pinning an IACA does not authorize it to serve as a DS end entity"
        );
    });
}

#[test]
fn mdoc_verification_requires_document_signer_profile() {
    futures_executor::block_on(async {
        let (crypto, template, _) = real_crypto_fixture().await;
        let (_, parsed_template) = x509_parser::parse_x509_certificate(&template.leaf_der).unwrap();
        let crldp_der = parsed_template
            .get_extension_unique(&x509_parser::der_parser::oid!(2.5.29.31))
            .unwrap()
            .unwrap()
            .value
            .to_vec();
        let mut unexpectedly_accepted = Vec::new();
        for case in [
            "valid",
            "missing_eku",
            "noncritical_eku",
            "wrong_eku",
            "missing_ku",
            "noncritical_ku",
            "excess_ku",
            "long_validity",
            "wrong_country",
            "nonprintable_country",
            "missing_country",
            "wrong_state",
            "missing_state",
            "matching_state",
            "zero_serial",
            "oversized_serial",
            "missing_cn",
            "subject_serial_utf8",
            "missing_ski",
            "wrong_ski",
            "critical_ski",
            "missing_aki",
            "wrong_aki",
            "missing_ian",
            "critical_ian",
            "wrong_ian_kind",
            "missing_crldp",
            "critical_crldp",
            "forbidden_policy_mappings",
            "forbidden_name_constraints",
            "forbidden_policy_constraints",
            "forbidden_inhibit_any_policy",
            "forbidden_freshest_crl",
            "critical_extension",
            "duplicate_extension",
            "noncritical_extension",
        ] {
            let certs = certificate_fixture_with_parameters(
                "issuer.example",
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
                true,
                |ca, leaf| match case {
                    "valid" => {}
                    "missing_eku" => {
                        leaf.custom_extensions.remove(0);
                    }
                    "noncritical_eku" => leaf.custom_extensions[0].set_criticality(false),
                    "wrong_eku" => {
                        let mut eku = rcgen::CustomExtension::from_oid_content(
                            &[2, 5, 29, 37],
                            vec![
                                0x30, 0x09, 0x06, 0x07, 0x28, 0x81, 0x8c, 0x5d, 0x05, 0x01, 0x03,
                            ],
                        );
                        eku.set_criticality(true);
                        leaf.custom_extensions[0] = eku;
                    }
                    "missing_ku" => leaf.key_usages.clear(),
                    "noncritical_ku" => {
                        leaf.key_usages.clear();
                        leaf.custom_extensions
                            .push(rcgen::CustomExtension::from_oid_content(
                                &[2, 5, 29, 15],
                                vec![0x03, 0x02, 0x07, 0x80],
                            ));
                    }
                    "excess_ku" => leaf.key_usages.push(KeyUsagePurpose::KeyCertSign),
                    "long_validity" => leaf.not_after = leaf.not_before + time::Duration::days(458),
                    "wrong_country" => leaf.distinguished_name.push(
                        DnType::CountryName,
                        rcgen::DnValue::PrintableString("CA".try_into().unwrap()),
                    ),
                    "nonprintable_country" => {
                        leaf.distinguished_name.push(DnType::CountryName, "US")
                    }
                    "missing_country" => {
                        leaf.distinguished_name = DistinguishedName::new();
                        leaf.distinguished_name
                            .push(DnType::CommonName, "issuer.example");
                    }
                    "wrong_state" => {
                        ca.distinguished_name
                            .push(DnType::StateOrProvinceName, "California");
                        leaf.distinguished_name
                            .push(DnType::StateOrProvinceName, "New York");
                    }
                    "missing_state" => ca
                        .distinguished_name
                        .push(DnType::StateOrProvinceName, "California"),
                    "matching_state" => {
                        ca.distinguished_name
                            .push(DnType::StateOrProvinceName, "California");
                        leaf.distinguished_name
                            .push(DnType::StateOrProvinceName, "California");
                    }
                    "zero_serial" => leaf.serial_number = Some(rcgen::SerialNumber::from(0_u64)),
                    "oversized_serial" => {
                        leaf.serial_number = Some(rcgen::SerialNumber::from(vec![1; 21]))
                    }
                    "missing_cn" => {
                        leaf.distinguished_name = DistinguishedName::new();
                        leaf.distinguished_name.push(
                            DnType::CountryName,
                            rcgen::DnValue::PrintableString("US".try_into().unwrap()),
                        );
                    }
                    "subject_serial_utf8" => leaf
                        .distinguished_name
                        .push(DnType::CustomDnType(vec![2, 5, 4, 5]), "synthetic-serial"),
                    "missing_ski" => {
                        leaf.custom_extensions.remove(1);
                    }
                    "wrong_ski" => {
                        leaf.custom_extensions[1] = rcgen::CustomExtension::from_oid_content(
                            &[2, 5, 29, 14],
                            yasna::construct_der(|writer| writer.write_bytes(&[0; 20])),
                        )
                    }
                    "critical_ski" => leaf.custom_extensions[1].set_criticality(true),
                    "missing_aki" => leaf.use_authority_key_identifier_extension = false,
                    "wrong_aki" => {
                        leaf.use_authority_key_identifier_extension = false;
                        leaf.custom_extensions
                            .push(rcgen::CustomExtension::from_oid_content(
                                &[2, 5, 29, 35],
                                yasna::construct_der(|writer| {
                                    writer.write_sequence(|writer| {
                                        writer.next().write_tagged_implicit(
                                            yasna::Tag::context(0),
                                            |writer| writer.write_bytes(&[0; 20]),
                                        )
                                    });
                                }),
                            ));
                    }
                    "missing_ian" => {
                        leaf.custom_extensions.remove(2);
                    }
                    "critical_ian" => leaf.custom_extensions[2].set_criticality(true),
                    "wrong_ian_kind" => {
                        leaf.custom_extensions[2] = rcgen::CustomExtension::from_oid_content(
                            &[2, 5, 29, 18],
                            vec![0x30, 0x04, 0x82, 0x02, b'x', b'y'],
                        )
                    }
                    "missing_crldp" => leaf.crl_distribution_points.clear(),
                    "critical_crldp" => {
                        leaf.crl_distribution_points.clear();
                        let mut extension = rcgen::CustomExtension::from_oid_content(
                            &[2, 5, 29, 31],
                            crldp_der.clone(),
                        );
                        extension.set_criticality(true);
                        leaf.custom_extensions.push(extension);
                    }
                    "forbidden_policy_mappings"
                    | "forbidden_name_constraints"
                    | "forbidden_policy_constraints"
                    | "forbidden_inhibit_any_policy"
                    | "forbidden_freshest_crl" => {
                        let oid = match case {
                            "forbidden_policy_mappings" => 33,
                            "forbidden_name_constraints" => 30,
                            "forbidden_policy_constraints" => 36,
                            "forbidden_inhibit_any_policy" => 54,
                            _ => 46,
                        };
                        let value = if oid == 54 {
                            vec![2, 1, 0]
                        } else {
                            vec![0x30, 0]
                        };
                        leaf.custom_extensions
                            .push(rcgen::CustomExtension::from_oid_content(
                                &[2, 5, 29, oid],
                                value,
                            ));
                    }
                    "critical_extension" | "duplicate_extension" | "noncritical_extension" => {
                        let mut extension =
                            rcgen::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![5, 0]);
                        extension.set_criticality(case == "critical_extension");
                        leaf.custom_extensions.push(extension.clone());
                        if case == "duplicate_extension" {
                            leaf.custom_extensions.push(extension);
                        }
                    }
                    _ => unreachable!(),
                },
            );
            let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
            let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            assert!(
                nazo_mdoc::verifier::verify_presentation(
                    &bytes,
                    &SessionTranscript::from_cbor(&transcript).unwrap(),
                    &nazo_mdoc::verifier::VerificationOptions {
                        now: to_protocol_time(Utc::now()).unwrap(),
                        max_documents: 1,
                    },
                )
                .is_ok(),
                "{case}: reject the authenticated certificate profile, not a bad issuer or holder signature"
            );
            let presentation = PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                additional_trust_anchors: vec![certs.ca_der].into(),
            };
            let result = crypto.verify_mdoc(&presentation);
            if matches!(case, "valid" | "matching_state" | "noncritical_extension") {
                result.unwrap_or_else(|error| panic!("{case}: {error}"));
            } else if result.is_ok() {
                unexpectedly_accepted.push(case);
            } else {
                assert_eq!(result, Err(CredentialTrustError::UntrustedIssuer), "{case}");
            }
        }
        assert!(
            unexpectedly_accepted.is_empty(),
            "accepted non-DS profiles: {unexpectedly_accepted:?}"
        );
    });
}

#[test]
fn signed_mdoc_certificate_fields_retain_asn1_and_uri_syntax() {
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let mut unexpectedly_accepted = Vec::new();
        for case in [
            "valid",
            "valid_uri_spelling",
            "printable_cn_charset",
            "utf8_cn_charset",
            "context_cn_tag",
            "constructed_cn_tag",
            "printable_serial_charset",
            "ian_uri_whitespace",
            "ian_uri_unicode",
            "ian_uri_mixed",
            "crldp_uri_whitespace",
            "crldp_uri_unicode",
            "crldp_uri_mixed",
        ] {
            let certs = certificate_fixture_with_wire_edit(
                "issuer.example",
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
                true,
                |_, leaf| {
                    match case {
                        "printable_cn_charset" => leaf.distinguished_name.push(
                            DnType::CommonName,
                            rcgen::DnValue::PrintableString("Printable CN".try_into().unwrap()),
                        ),
                        "utf8_cn_charset" => {
                            leaf.distinguished_name.push(DnType::CommonName, "UTF8 CN")
                        }
                        "context_cn_tag" | "constructed_cn_tag" => leaf
                            .distinguished_name
                            .push(DnType::CommonName, "Tagged CN"),
                        "printable_serial_charset" => leaf.distinguished_name.push(
                            DnType::CustomDnType(vec![2, 5, 4, 5]),
                            rcgen::DnValue::PrintableString("serial-sample".try_into().unwrap()),
                        ),
                        "valid_uri_spelling" => {
                            leaf.crl_distribution_points[0].uris =
                                vec!["HTTPS://ISSUER.EXAMPLE/%63rl".into()];
                        }
                        "crldp_uri_whitespace" => {
                            leaf.crl_distribution_points[0].uris =
                                vec!["https://issuer.example/te\nst.crl".into()];
                        }
                        "crldp_uri_mixed" => {
                            leaf.crl_distribution_points[0]
                                .uris
                                .push("https://issuer.example/te\nst.crl".into());
                        }
                        _ => {}
                    }
                    if matches!(
                        case,
                        "ian_uri_whitespace"
                            | "ian_uri_unicode"
                            | "ian_uri_mixed"
                            | "crldp_uri_unicode"
                    ) {
                        let uri = if case == "ian_uri_whitespace" {
                            "https://issuer.example/con\ttact"
                        } else {
                            "https://éssuer.example/contact"
                        };
                        let der = yasna::construct_der(|writer| {
                            writer.write_sequence(|writer| {
                                if case == "crldp_uri_unicode" {
                                    writer.next().write_sequence(|writer| {
                                        writer.next().write_tagged(
                                            yasna::Tag::context(0),
                                            |writer| {
                                                writer.write_tagged_implicit(
                                                    yasna::Tag::context(0),
                                                    |writer| {
                                                        writer.write_sequence(|writer| {
                                                            writer.next().write_tagged_implicit(
                                                                yasna::Tag::context(6),
                                                                |writer| {
                                                                    writer
                                                                        .write_bytes(uri.as_bytes())
                                                                },
                                                            );
                                                        });
                                                    },
                                                );
                                            },
                                        );
                                    });
                                } else {
                                    writer
                                        .next()
                                        .write_tagged_implicit(yasna::Tag::context(6), |writer| {
                                            writer.write_bytes(uri.as_bytes())
                                        });
                                    if case == "ian_uri_mixed" {
                                        writer.next().write_tagged_implicit(
                                            yasna::Tag::context(6),
                                            |writer| {
                                                writer.write_ia5_string(
                                                    "https://issuer.example/contact",
                                                )
                                            },
                                        );
                                    }
                                }
                            });
                        });
                        if case == "crldp_uri_unicode" {
                            leaf.crl_distribution_points.clear();
                            leaf.custom_extensions
                                .push(rcgen::CustomExtension::from_oid_content(
                                    &[2, 5, 29, 31],
                                    der,
                                ));
                        } else {
                            leaf.custom_extensions[2] =
                                rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 18], der);
                        }
                    }
                },
                |der, ca_key| {
                    let (marker, byte): (&[u8], u8) = match case {
                        "printable_cn_charset" => (b"Printable CN", b'*'),
                        "utf8_cn_charset" => (b"UTF8 CN", 0xff),
                        "context_cn_tag" | "constructed_cn_tag" => (b"Tagged CN", 0),
                        "printable_serial_charset" => (b"serial-sample", b'*'),
                        _ => return der,
                    };
                    let (_, certificate) = x509_parser::parse_x509_certificate(&der).unwrap();
                    let mut tbs = certificate.tbs_certificate.as_ref().to_vec();
                    let offsets: Vec<_> = tbs
                        .windows(marker.len())
                        .enumerate()
                        .filter_map(|(index, value)| (value == marker).then_some(index))
                        .collect();
                    assert_eq!(offsets.len(), 1);
                    if matches!(case, "context_cn_tag" | "constructed_cn_tag") {
                        assert_eq!(tbs[offsets[0] - 1], marker.len() as u8);
                        tbs[offsets[0] - 2] |= if case == "context_cn_tag" { 0x80 } else { 0x20 };
                    } else {
                        tbs[offsets[0]] = byte;
                    }
                    let secret = p256::SecretKey::from_pkcs8_der(&ca_key.serialize_der()).unwrap();
                    let key = SigningKey::from_slice(&secret.to_bytes()).unwrap();
                    let signature: p256::ecdsa::Signature = key.sign(&tbs);
                    let signature = signature.to_der();
                    yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_der(&tbs);
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(
                                    &yasna::models::ObjectIdentifier::from_slice(&[
                                        1, 2, 840, 10045, 4, 3, 2,
                                    ]),
                                );
                            });
                            writer.next().write_bitvec_bytes(
                                signature.as_bytes(),
                                signature.as_bytes().len() * 8,
                            );
                        })
                    })
                },
            );
            let (_, leaf) = x509_parser::parse_x509_certificate(&certs.leaf_der).unwrap();
            let (_, ca) = x509_parser::parse_x509_certificate(&certs.ca_der).unwrap();
            nazo_crypto::certificate::verify_signature(&leaf, ca.public_key()).unwrap();
            // The builder can already reject some malformed DER. Start with a
            // benign certificate for this same signing key, then replace the
            // received chain so every case reaches the verification boundary.
            let benign = certificate_fixture_with_key(
                "issuer.example",
                KeyPair::from_pem(&certs.leaf_key.serialize_pem()).unwrap(),
            );
            let (encoded, transcript) = valid_mdoc_presentation(&benign, Utc::now(), None);
            let encoded = resign_mdoc(&encoded, &certs, |document, _| {
                document
                    .issuer_signed
                    .issuer_auth
                    .cose_sign1
                    .unprotected
                    .rest
                    .iter_mut()
                    .find(|(label, _)| *label == coset::Label::Int(33))
                    .unwrap()
                    .1 = ciborium::Value::Bytes(certs.leaf_der.clone());
            });
            let result = crypto.verify_mdoc(&PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                additional_trust_anchors: vec![certs.ca_der].into(),
            });
            if matches!(case, "valid" | "valid_uri_spelling") {
                result.unwrap_or_else(|error| panic!("{case}: {error}"));
            } else if result.is_ok() {
                unexpectedly_accepted.push(case);
            } else {
                assert_eq!(result, Err(CredentialTrustError::UntrustedIssuer), "{case}");
            }
        }
        assert!(
            unexpectedly_accepted.is_empty(),
            "accepted malformed authenticated certificate fields: {unexpectedly_accepted:?}"
        );
    });
}

fn install_revocation_snapshot(
    crypto: &Openid4vcCredentialCrypto,
    certs: &CertificateFixture,
    snapshot: CertificateRevocationSnapshot,
) {
    let signing_kid = crypto
        .keyset
        .openid4vc_public_material()
        .unwrap()
        .signing_kid
        .clone();
    crypto
        .keyset
        .set_openid4vc_material_for_test(Openid4vcMaterial {
            public: Openid4vcPublicMaterial {
                signing_kid,
                certificate_chain_pem: format!("{}{}", certs.leaf_pem, certs.ca_pem),
                trust_anchors_pem: certs.ca_pem.clone(),
                revocation_snapshot: Some(snapshot),
            },
            iaca_private_materials: Default::default(),
        });
}

#[test]
fn sd_jwt_required_unknown_status_uses_authenticated_anchor_not_loaded_scope() {
    let (crypto, mut presentation, _, certs) = sd_presentation_fixture();
    let strict = Openid4vcCredentialCrypto {
        revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
        ..crypto
    };
    let fresh = CertificateRevocationSnapshot {
        version: CertificateRevocationSnapshot::VERSION,
        this_update: Utc::now() - Duration::minutes(1),
        next_update: Utc::now() + Duration::minutes(5),
        entries: vec![],
    };
    install_revocation_snapshot(&strict, &certs, fresh.clone());
    let unrelated = certificate_fixture("unrelated.example");
    presentation.additional_trust_anchors = vec![unrelated.ca_der.clone()].into();
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationStatusUnknown)
    );
    // An unused configured anchor is rejected rather than becoming a chain fact.
    let token = presentation.encoded.split('~').next().unwrap();
    let header = decode_header(token).unwrap();
    let mut attached = header.x5c.unwrap();
    attached.push(STANDARD.encode(&unrelated.ca_der));
    assert!(
        super::sd_jwt::validate_sd_jwt_chain(
            &strict,
            &attached,
            &presentation.additional_trust_anchors,
        )
        .is_err()
    );
    presentation.additional_trust_anchors = vec![certs.ca_der.clone()].into();
    assert!(
        strict.verify_sd_jwt(&presentation).is_ok(),
        "same DER globally and scoped is an actual scoped path"
    );
    let mut revoked = fresh.clone();
    revoked
        .entries
        .push(nazo_digital_credentials::CertificateRevocationEntry {
            issuer: "https://issuer.example".into(),
            certificate: nazo_digital_credentials::certificate_identity(&certs.leaf_der),
            status: nazo_digital_credentials::CertificateRevocationStatus::Revoked,
            revoked_at: Some(Utc::now()),
        });
    install_revocation_snapshot(&strict, &certs, revoked);
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevokedCertificate)
    );
    let mut stale = fresh;
    stale.next_update = Utc::now() - Duration::seconds(1);
    install_revocation_snapshot(&strict, &certs, stale);
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationSnapshotStale)
    );
}

#[test]
fn mdoc_required_unknown_status_uses_authenticated_anchor_not_loaded_scope() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let strict = Openid4vcCredentialCrypto {
            revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
            ..crypto
        };
        let fresh = CertificateRevocationSnapshot {
            version: CertificateRevocationSnapshot::VERSION,
            this_update: Utc::now() - Duration::minutes(1),
            next_update: Utc::now() + Duration::minutes(5),
            entries: vec![],
        };
        install_revocation_snapshot(&strict, &certs, fresh.clone());
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let unrelated = certificate_fixture("unrelated.example");
        let mut presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![unrelated.ca_der].into(),
        };
        assert_eq!(
            strict.verify_mdoc(&presentation),
            Err(CredentialTrustError::RevocationStatusUnknown)
        );
        presentation.additional_trust_anchors = vec![certs.ca_der.clone()].into();
        assert!(strict.verify_mdoc(&presentation).is_ok());
        let mut revoked = fresh;
        revoked
            .entries
            .push(nazo_digital_credentials::CertificateRevocationEntry {
                issuer: "https://issuer.example".into(),
                certificate: nazo_digital_credentials::certificate_identity(&certs.leaf_der),
                status: nazo_digital_credentials::CertificateRevocationStatus::Revoked,
                revoked_at: Some(Utc::now()),
            });
        install_revocation_snapshot(&strict, &certs, revoked);
        assert_eq!(
            strict.verify_mdoc(&presentation),
            Err(CredentialTrustError::RevokedCertificate)
        );
    });
}

#[test]
fn shared_signing_key_anchor_selection_prefers_actual_scoped_der_without_second_validation() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pem = key.serialize_pem();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "shared-root");
    params.serial_number = Some(1_u64.into());
    let global = CertifiedIssuer::self_signed(params.clone(), key).unwrap();
    params.serial_number = Some(2_u64.into());
    let scoped = CertifiedIssuer::self_signed(params, KeyPair::from_pem(&pem).unwrap()).unwrap();
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = CertificateParams::new(vec!["issuer.example".into()])
        .unwrap()
        .signed_by(&leaf_key, &global)
        .unwrap();
    let certificates = vec![leaf.der().as_ref().to_vec()];
    let global_der = vec![global.der().as_ref().to_vec()];
    let scoped_der = vec![scoped.der().as_ref().to_vec()];
    assert_ne!(global_der, scoped_der);
    assert_eq!(
        super::super::crypto_helpers::verify_openid4vc_chain_with_scoped(
            &certificates,
            &global_der,
            &scoped_der
        )
        .unwrap(),
        scoped_der[0].as_slice()
    );
    assert_eq!(
        super::mdoc::verify_certificate_chain_with_scoped_at(
            &certificates,
            &global_der,
            &scoped_der,
            Utc::now().timestamp()
        )
        .unwrap(),
        Some(scoped_der[0].as_slice())
    );
}

#[test]
fn expired_scoped_anchor_with_valid_global_path_cannot_exempt_required_unknown_status() {
    let (crypto, mut presentation, _, certs) = sd_presentation_fixture();
    let strict = Openid4vcCredentialCrypto {
        revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
        ..crypto
    };
    install_revocation_snapshot(
        &strict,
        &certs,
        CertificateRevocationSnapshot {
            version: CertificateRevocationSnapshot::VERSION,
            this_update: Utc::now() - Duration::minutes(1),
            next_update: Utc::now() + Duration::minutes(5),
            entries: vec![],
        },
    );
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
    params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let expired = CertifiedIssuer::self_signed(
        params,
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
    )
    .unwrap();
    presentation.additional_trust_anchors = vec![expired.der().as_ref().to_vec()].into();
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationStatusUnknown)
    );
    presentation.additional_trust_anchors = vec![vec![1, 2, 3]].into();
    assert!(strict.verify_sd_jwt(&presentation).is_err());
}

fn certificate_subject_key_identifier(der: &[u8]) -> Vec<u8> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).expect("fixture certificate");
    certificate
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(identifier) => {
                Some(identifier.0.to_vec())
            }
            _ => None,
        })
        .expect("fixture CA subject key identifier")
}

#[test]
fn sd_jwt_projects_aki_only_from_its_authenticated_issuer_chain() {
    let (crypto, mut presentation, _, certs) = sd_presentation_fixture();
    let unrelated = certificate_fixture("unrelated.example");
    presentation.additional_trust_anchors = vec![unrelated.ca_der.clone()].into();
    let verified = crypto
        .verify_sd_jwt(&presentation)
        .expect("real signed SD-JWT and holder binding");
    let issuer_key_identifier = certificate_subject_key_identifier(&certs.ca_der);
    assert_eq!(
        verified.issuer_chain_authority_key_identifiers,
        vec![issuer_key_identifier.clone()]
    );
    assert!(
        verified
            .has_issuer_authority_key_identifier(&URL_SAFE_NO_PAD.encode(issuer_key_identifier))
    );
    assert!(!verified.has_issuer_authority_key_identifier(
        &URL_SAFE_NO_PAD.encode(certificate_subject_key_identifier(&unrelated.ca_der))
    ));
    assert!(!verified.has_issuer_authority_key_identifier(&verified.issuer));

    let (crypto, presentation, _, _) = sd_presentation_fixture_with_aki(false);
    let without_aki = crypto
        .verify_sd_jwt(&presentation)
        .expect("valid issuer chain without optional AKI");
    assert!(
        without_aki
            .issuer_chain_authority_key_identifiers
            .is_empty()
    );
    let legacy: nazo_digital_credentials::VerifiedCredential = serde_json::from_value(serde_json::json!({
        "format": "dc+sd-jwt", "issuer": "https://issuer.example", "credential_type": "ExampleCredential",
        "claims": {}, "holder_key": null, "issued_at": null, "expires_at": null, "status": null,
    })).expect("retained results without AKI metadata remain readable");
    assert!(legacy.issuer_chain_authority_key_identifiers.is_empty());
}

#[test]
fn signed_holder_nonce_failure_is_distinct_from_other_holder_failures() {
    let (crypto, presentation, _, _) = sd_presentation_fixture();
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let (_, holder_key) = es256_jwk(71);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("kb+jwt".to_owned());
    for nonce in [None, Some("other-transaction")] {
        let mut claims =
            json!({"aud": "https://other-verifier.example", "iat": 0, "sd_hash": "bad"});
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let kb = encode(&header, &claims, &holder_key).expect("signed holder proof");
        let response = PresentedCredential {
            encoded: format!("{}~{}~{kb}", parts[0], parts[1]).into(),
            ..presentation.clone()
        };
        assert_eq!(
            crypto.verify_sd_jwt(&response),
            Err(CredentialTrustError::InvalidNonce)
        );
    }
    let (_, attacker_key) = es256_jwk(72);
    let kb = encode(&header, &json!({"nonce": "other-transaction", "aud": presentation.expected_audience, "iat": Utc::now().timestamp(), "sd_hash": "bad"}), &attacker_key).unwrap();
    let untrusted = PresentedCredential {
        encoded: format!("{}~{}~{kb}", parts[0], parts[1]).into(),
        ..presentation
    };
    assert_eq!(
        crypto.verify_sd_jwt(&untrusted),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[derive(Clone, Default)]
struct PresentationCompletionSink(Arc<std::sync::atomic::AtomicUsize>);

impl nazo_openid4vp::PresentationStorePort for PresentationCompletionSink {
    fn create<'a>(
        &'a self,
        _transaction: &'a nazo_openid4vp::PresentationTransaction,
        _idempotency: nazo_openid4vp::PresentationCreateIdempotency<'a>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<nazo_openid4vp::PresentationCreateOutcome, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
    fn find_by_create_request<'a>(
        &'a self,
        _idempotency: nazo_openid4vp::PresentationCreateIdempotency<'a>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vp::PresentationTransaction>,
            nazo_openid4vp::PresentationStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
    fn request<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vp::PresentationTransaction>,
            nazo_openid4vp::PresentationStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
    fn bind_wallet_nonce<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _wallet_nonce: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<bool, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
    fn complete<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _state_hash: &'a str,
        _result: &'a nazo_openid4vp::PresentationResult,
        _now: chrono::DateTime<Utc>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<bool, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async move {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        })
    }
    fn result<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<Option<nazo_openid4vp::PresentationResult>, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
}

#[test]
fn signed_sd_jwt_aki_and_nonce_flow_through_real_presentation_service() {
    futures_executor::block_on(async {
        let (crypto, presentation, _, certs) = sd_presentation_fixture();
        let mut transaction = signed_sd_transaction(&presentation);
        let actual_aki = URL_SAFE_NO_PAD.encode(certificate_subject_key_identifier(&certs.ca_der));
        for (value, accepted) in [
            (actual_aki.as_str(), true),
            ("https://issuer.example", false),
            ("AQID", false),
        ] {
            transaction.request.dcql_query.credentials[0].trusted_authorities =
                Some(vec![nazo_digital_credentials::TrustedAuthority {
                    authority_type: "aki".to_owned(),
                    values: vec![value.to_owned()],
                }]);
            let sink = PresentationCompletionSink::default();
            let result = nazo_openid4vp::PresentationService::new(sink.clone(), crypto.clone())
                .verify_response(
                    &transaction,
                    &nazo_openid4vp::AuthorizationResponse {
                        vp_token: Some(
                            json!({"first": [presentation.encoded], "optional": ["broken"]}),
                        ),
                        state: Some("state".to_owned()),
                        error: None,
                        error_description: None,
                    },
                    &[],
                    Utc::now(),
                )
                .await;
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(
                sink.0.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(accepted)
            );
            if accepted {
                assert_eq!(result.unwrap().credentials.len(), 1);
            }
        }
        transaction.request.dcql_query.credentials[0].trusted_authorities = None;
        let parts = presentation.encoded.split('~').collect::<Vec<_>>();
        let (_, holder_key) = es256_jwk(71);
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("kb+jwt".to_owned());
        let kb = encode(&header, &json!({
            "nonce": "another-transaction", "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(format!("{}~{}~", parts[0], parts[1]).as_bytes()))
        }), &holder_key).unwrap();
        let replay = format!("{}~{}~{kb}", parts[0], parts[1]);
        let sink = PresentationCompletionSink::default();
        let result = nazo_openid4vp::PresentationService::new(sink.clone(), crypto)
            .verify_response(
                &transaction,
                &nazo_openid4vp::AuthorizationResponse {
                    vp_token: Some(json!({"first": [presentation.encoded], "optional": [replay]})),
                    state: Some("state".to_owned()),
                    error: None,
                    error_description: None,
                },
                &[],
                Utc::now(),
            )
            .await;
        assert_eq!(
            result.unwrap_err(),
            nazo_openid4vp::PresentationServiceError::Presentation(
                nazo_openid4vp::PresentationError::UntrustedPresentation
            )
        );
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    })
}

#[test]
fn signed_mdoc_rejects_an_unmatched_current_session_without_nonce_claim_guessing() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, _) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let different_transcript = SessionTranscript::redirect(RedirectHandover {
            client_id: "https://verifier.example",
            response_uri: "https://verifier.example/response",
            nonce: "another-transaction",
            jwk_thumbprint: None,
        })
        .unwrap()
        .into_bytes();
        let mut presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "another-transaction".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(different_transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidSessionBinding)
        );
        let mut response = nazo_mdoc::parser::parse(
            &URL_SAFE_NO_PAD
                .decode(presentation.encoded.as_bytes())
                .unwrap(),
        )
        .unwrap();
        let mut malformed = response.documents[0].clone();
        malformed.issuer_signed.issuer_auth.cose_sign1.payload = Some(vec![0xff]);
        response.documents.push(malformed);
        presentation.encoded = URL_SAFE_NO_PAD
            .encode(nazo_mdoc::encoder::encode_device_response(&response).unwrap())
            .into();
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidSessionBinding),
            "a later malformed MSO must not hide the first document's session mismatch",
        );
    })
}

fn signed_sd_transaction(
    presentation: &PresentedCredential<'_>,
) -> nazo_openid4vp::PresentationTransaction {
    nazo_openid4vp::PresentationTransaction {
        id: uuid::Uuid::now_v7(),
        client_id_prefix: nazo_openid4vp::ClientIdPrefix::RedirectUri,
        request_method: nazo_openid4vp::RequestMethod::RequestUriSignedPost,

        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request: serde_json::from_value(json!({
            "client_id": presentation.expected_audience,
            "response_type": "vp_token", "response_mode": "direct_post",
            "response_uri": "https://verifier.example/response",
            "nonce": presentation.expected_nonce, "state": "state",
            "dcql_query": {
                "credentials": [
                    {"id": "first", "format": "dc+sd-jwt", "meta":{"vct_values":["ExampleCredential"]}},
                    {"id": "optional", "format": "dc+sd-jwt", "meta":{"vct_values":["ExampleCredential"]}}
                ],
                "credential_sets": [{"options": [["first"]]}]
            }
        }))
        .unwrap(),
        request_object: None,
        request_uri: None,
        openid4vc_trust_policy_binding_id: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
        response_encryption_private_key: None,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn resign_sd_fixture(
    presentation: &PresentedCredential<'static>,
    certs: &CertificateFixture,
    x5c: Vec<String>,
    nonce: &str,
) -> PresentedCredential<'static> {
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0].split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    resign_sd_fixture_with_claims(presentation, certs, x5c, nonce, &claims)
}

pub(super) fn resign_sd_fixture_with_claims(
    presentation: &PresentedCredential<'static>,
    certs: &CertificateFixture,
    x5c: Vec<String>,
    nonce: &str,
    claims: &Value,
) -> PresentedCredential<'static> {
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let mut issuer_header = Header::new(Algorithm::ES256);
    issuer_header.typ = Some("dc+sd-jwt".to_owned());
    issuer_header.x5c = Some(x5c);
    let jwt = encode(
        &issuer_header,
        claims,
        &EncodingKey::from_ec_der(&certs.leaf_key.serialize_der()),
    )
    .unwrap();
    let sd_input = format!("{jwt}~{}~", parts[1]);
    let (_, holder_key) = es256_jwk(71);
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let kb = encode(
        &kb_header,
        &json!({
            "nonce": nonce, "aud": presentation.expected_audience,
            "iat": Utc::now().timestamp(),
            "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes()))
        }),
        &holder_key,
    )
    .unwrap();
    PresentedCredential {
        encoded: format!("{sd_input}{kb}").into(),
        ..presentation.clone()
    }
}

fn install_service_trust_fixture(
    crypto: &Openid4vcCredentialCrypto,
    certs: &CertificateFixture,
    anchors_pem: String,
    snapshot: Option<CertificateRevocationSnapshot>,
) {
    let signing_kid = crypto
        .keyset
        .openid4vc_public_material()
        .unwrap()
        .signing_kid
        .clone();
    crypto
        .keyset
        .set_openid4vc_material_for_test(Openid4vcMaterial {
            public: Openid4vcPublicMaterial {
                signing_kid,
                certificate_chain_pem: format!("{}{}", certs.leaf_pem, certs.ca_pem),
                trust_anchors_pem: anchors_pem,
                revocation_snapshot: snapshot,
            },
            iaca_private_materials: Default::default(),
        });
}

#[test]
fn signed_unused_configured_anchor_cannot_supply_a_dcql_aki() {
    futures_executor::block_on(async {
        let (crypto, presentation, _, certs) = sd_presentation_fixture();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "unused configured anchor");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::days(365);
        let unused = params
            .self_signed(&KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap())
            .unwrap();
        let unused_der = unused.der().as_ref().to_vec();
        let identifiers = super::certificates::issuer_authority_key_identifiers(
            std::slice::from_ref(&unused_der),
        )
        .unwrap();
        assert_eq!(
            identifiers.len(),
            1,
            "counterexample anchor must actually carry AKI"
        );
        let unused_aki = URL_SAFE_NO_PAD.encode(&identifiers[0]);
        assert_ne!(
            identifiers[0],
            certificate_subject_key_identifier(&certs.ca_der)
        );
        install_service_trust_fixture(
            &crypto,
            &certs,
            format!("{}{}", certs.ca_pem, unused.pem()),
            None,
        );
        let poisoned = resign_sd_fixture(
            &presentation,
            &certs,
            vec![
                STANDARD.encode(&certs.leaf_der),
                STANDARD.encode(&unused_der),
            ],
            &presentation.expected_nonce,
        );
        // Fresh issuer and holder signatures cover the changed header/sd_hash.
        // This is not an edited, signature-invalid protected header.
        assert_eq!(
            crypto.verify_sd_jwt(&poisoned),
            Err(CredentialTrustError::UntrustedIssuer)
        );
        let mut transaction = signed_sd_transaction(&presentation);
        transaction.request.dcql_query.credentials[0].trusted_authorities =
            Some(vec![nazo_digital_credentials::TrustedAuthority {
                authority_type: "aki".to_owned(),
                values: vec![unused_aki],
            }]);
        let sink = PresentationCompletionSink::default();
        let error = nazo_openid4vp::PresentationService::new(sink.clone(), crypto)
            .verify_response(
                &transaction,
                &nazo_openid4vp::AuthorizationResponse {
                    vp_token: Some(json!({"first": [poisoned.encoded]})),
                    state: Some("state".to_owned()),
                    error: None,
                    error_description: None,
                },
                &[],
                Utc::now(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            nazo_openid4vp::PresentationServiceError::Presentation(
                nazo_openid4vp::PresentationError::DcqlUnsatisfied
            )
        );
        assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            super::mdoc::verify_certificate_chain_with_scoped_at(
                &[certs.leaf_der.clone(), unused_der.clone()],
                &[certs.ca_der, unused_der],
                &[],
                Utc::now().timestamp(),
            )
            .unwrap()
            .is_none()
        );
    })
}

#[test]
fn signed_revoked_optional_nonce_is_fatal_and_stale_snapshot_is_unavailable() {
    futures_executor::block_on(async {
        let (crypto, accepted, _, certs) = sd_presentation_fixture();
        let (_, revoked, _, revoked_certs) = sd_presentation_fixture();
        let strict = Openid4vcCredentialCrypto {
            revocation_policy: crate::policy::Openid4vcRevocationPolicy::Required,
            ..crypto
        };
        let now = Utc::now();
        let snapshot = CertificateRevocationSnapshot {
            version: CertificateRevocationSnapshot::VERSION,
            this_update: now - Duration::minutes(1),
            next_update: now + Duration::minutes(5),
            entries: vec![
                nazo_digital_credentials::CertificateRevocationEntry {
                    issuer: "https://issuer.example".to_owned(),
                    certificate: nazo_digital_credentials::certificate_identity(&certs.leaf_der),
                    status: nazo_digital_credentials::CertificateRevocationStatus::Good,
                    revoked_at: None,
                },
                nazo_digital_credentials::CertificateRevocationEntry {
                    issuer: "https://issuer.example".to_owned(),
                    certificate: nazo_digital_credentials::certificate_identity(
                        &revoked_certs.leaf_der,
                    ),
                    status: nazo_digital_credentials::CertificateRevocationStatus::Revoked,
                    revoked_at: Some(now - Duration::seconds(1)),
                },
            ],
        };
        let anchors = format!("{}{}", certs.ca_pem, revoked_certs.ca_pem);
        install_service_trust_fixture(&strict, &certs, anchors.clone(), Some(snapshot.clone()));
        let wrong_nonce = resign_sd_fixture(
            &revoked,
            &revoked_certs,
            vec![STANDARD.encode(&revoked_certs.leaf_der)],
            "another-transaction",
        );
        let transaction = signed_sd_transaction(&accepted);
        for (optional, expected_error) in [
            (&revoked, None),
            (
                &wrong_nonce,
                Some(nazo_openid4vp::PresentationServiceError::Presentation(
                    nazo_openid4vp::PresentationError::UntrustedPresentation,
                )),
            ),
        ] {
            let sink = PresentationCompletionSink::default();
            let result = nazo_openid4vp::PresentationService::new(sink.clone(), strict.clone())
                .verify_response(
                    &transaction,
                    &nazo_openid4vp::AuthorizationResponse {
                        vp_token: Some(
                            json!({"first": [accepted.encoded], "optional": [optional.encoded]}),
                        ),
                        state: Some("state".to_owned()),
                        error: None,
                        error_description: None,
                    },
                    &[],
                    Utc::now(),
                )
                .await;
            if let Some(error) = expected_error {
                assert_eq!(result.unwrap_err(), error);
                assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            } else {
                assert_eq!(
                    result.unwrap().credentials.len(),
                    1,
                    "revoked optional credential must remain excluded"
                );
                assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 1);
            }
        }
        for (snapshot, expected) in [
            (
                Some(CertificateRevocationSnapshot {
                    next_update: now - Duration::seconds(1),
                    ..snapshot
                }),
                CredentialTrustError::RevocationSnapshotStale,
            ),
            (None, CredentialTrustError::RevocationSnapshotUnavailable),
        ] {
            install_service_trust_fixture(&strict, &certs, anchors.clone(), snapshot);
            let sink = PresentationCompletionSink::default();
            let error = nazo_openid4vp::PresentationService::new(sink.clone(), strict.clone())
                .verify_response(
                    &transaction,
                    &nazo_openid4vp::AuthorizationResponse {
                        vp_token: Some(json!({"first": [accepted.encoded]})),
                        state: Some("state".to_owned()),
                        error: None,
                        error_description: None,
                    },
                    &[],
                    Utc::now(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error,
                nazo_openid4vp::PresentationServiceError::Verifier(expected)
            );
            assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    })
}

#[test]
fn signed_issuer_time_policy_cannot_hide_optional_holder_nonce() {
    futures_executor::block_on(async {
        let (crypto, accepted, _, certs) = sd_presentation_fixture();
        install_service_trust_fixture(&crypto, &certs, certs.ca_pem.clone(), None);
        let encoded_claims = accepted
            .encoded
            .split('~')
            .next()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let original: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded_claims).unwrap()).unwrap();
        let transaction = signed_sd_transaction(&accepted);
        for expiration in [
            Some(json!((Utc::now() - Duration::seconds(120)).timestamp())),
            None,
            Some(json!("invalid-time")),
        ] {
            let mut claims = original.clone();
            match expiration {
                Some(expiration) => {
                    claims["exp"] = expiration;
                }
                None => {
                    claims.as_object_mut().unwrap().remove("exp");
                }
            }
            for (nonce, fatal) in [
                (accepted.expected_nonce.as_ref(), false),
                ("another-transaction", true),
            ] {
                let optional = resign_sd_fixture_with_claims(
                    &accepted,
                    &certs,
                    vec![STANDARD.encode(&certs.leaf_der)],
                    nonce,
                    &claims,
                );
                assert_eq!(
                    crypto.verify_sd_jwt(&optional),
                    Err(if fatal {
                        CredentialTrustError::InvalidNonce
                    } else {
                        CredentialTrustError::InvalidSignature
                    })
                );
                let sink = PresentationCompletionSink::default();
                let result = nazo_openid4vp::PresentationService::new(sink.clone(), crypto.clone())
                    .verify_response(
                        &transaction,
                        &nazo_openid4vp::AuthorizationResponse {
                            vp_token: Some(json!({"first": [accepted.encoded], "optional": [optional.encoded]})),
                            state: Some("state".to_owned()), error: None, error_description: None,
                        }, &[], Utc::now(),
                    ).await;
                if fatal {
                    assert_eq!(
                        result.unwrap_err(),
                        nazo_openid4vp::PresentationServiceError::Presentation(
                            nazo_openid4vp::PresentationError::UntrustedPresentation,
                        )
                    );
                    assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
                } else {
                    assert_eq!(
                        result.unwrap().credentials.len(),
                        1,
                        "invalid issuer time still excludes the optional credential"
                    );
                    assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 1);
                }
                // An attacker-signed KB still cannot authenticate its nonce,
                // even when issuer time is independently invalid.
                let parts = optional.encoded.split('~').collect::<Vec<_>>();
                let (_, attacker_key) = es256_jwk(72);
                let mut header = Header::new(Algorithm::ES256);
                header.typ = Some("kb+jwt".to_owned());
                let sd_input = format!("{}~{}~", parts[0], parts[1]);
                let kb = encode(&header, &json!({
                    "nonce": "another-transaction", "aud": accepted.expected_audience,
                    "iat": Utc::now().timestamp(),
                    "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes())),
                }), &attacker_key).unwrap();
                let untrusted = PresentedCredential {
                    encoded: format!("{sd_input}{kb}").into(),
                    ..optional
                };
                assert_eq!(
                    crypto.verify_sd_jwt(&untrusted),
                    Err(CredentialTrustError::InvalidHolderBinding)
                );
            }
        }
        let mut fractional = original;
        fractional["exp"] = json!(Utc::now().timestamp() as f64 + 300.25);
        let fractional = resign_sd_fixture_with_claims(
            &accepted,
            &certs,
            vec![STANDARD.encode(&certs.leaf_der)],
            &accepted.expected_nonce,
            &fractional,
        );
        assert!(
            crypto.verify_sd_jwt(&fractional).is_ok(),
            "retain the pinned NumericDate fractional-time acceptance"
        );
    })
}

#[test]
fn sd_jwt_checks_validity_after_disclosures_with_valid_issuer_and_holder_signatures() {
    let (crypto, original, _, certs) = sd_presentation_fixture();
    let parts: Vec<_> = original.encoded.split('~').collect();
    let header = decode_header(parts[0]).unwrap();
    let original_claims: Value = jsonwebtoken::dangerous::insecure_decode::<Value>(parts[0])
        .unwrap()
        .claims;
    let issuer_key = EncodingKey::from_ec_der(&certs.leaf_key.serialize_der());
    let (_, holder_key) = es256_jwk(71);
    let mut kb_header = Header::new(Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".into());
    for (name, value, accepted, selective) in [
        ("nbf", json!(Utc::now().timestamp() + 300), false, false),
        ("nbf", json!("tomorrow"), false, false),
        ("nbf", json!(Utc::now().timestamp() - 1), true, false),
        ("exp", json!(Utc::now().timestamp() - 120), false, false),
        ("name", json!("Permanently disclosed"), true, false),
        ("nbf", json!(Utc::now().timestamp() - 1), false, true),
        ("exp", json!(Utc::now().timestamp() + 300), false, true),
        ("iat", json!(Utc::now().timestamp()), true, true),
    ] {
        let mut claims = original_claims.clone();
        let extra = if selective {
            claims.as_object_mut().unwrap().remove(name);
            let encoded =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!(["salt", name, value])).unwrap());
            claims["_sd"].as_array_mut().unwrap().push(json!(
                URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(encoded.as_bytes()))
            ));
            format!("{encoded}~")
        } else {
            claims[name] = value.clone();
            String::new()
        };
        let jwt = encode(&header, &claims, &issuer_key).unwrap();
        let input = format!("{jwt}~{}~{extra}", parts[1]);
        let kb = encode(
            &kb_header,
            &json!({
                "nonce": original.expected_nonce, "aud": original.expected_audience,
                "iat": Utc::now().timestamp(),
                "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input.as_bytes())),
            }),
            &holder_key,
        )
        .unwrap();
        let presentation = PresentedCredential {
            encoded: format!("{input}{kb}").into(),
            ..original.clone()
        };
        let result = crypto.verify_sd_jwt(&presentation);
        assert_eq!(result.is_ok(), accepted, "{name}: {result:?}");
        if accepted {
            assert_eq!(result.unwrap().claims[name], value);
        }
    }
}

#[test]
fn verifier_requires_status_resolver_after_holder_authentication() {
    futures_executor::block_on(async {
        let (crypto, presentation, _, certs) = sd_presentation_fixture();
        let parts: Vec<_> = presentation.encoded.split('~').collect();
        let mut claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0].split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        claims["status"] =
            json!({"status_list": {"idx": 3, "uri": "https://issuer.example/status"}});
        let with_status = resign_sd_fixture_with_claims(
            &presentation,
            &certs,
            vec![STANDARD.encode(&certs.leaf_der)],
            &presentation.expected_nonce,
            &claims,
        );
        assert_eq!(
            crypto.verify(&with_status).await,
            Err(CredentialTrustError::InvalidStatus)
        );
        let unrelated_nonce = crate::crypto::random_urlsafe_token();
        let wrong_nonce = resign_sd_fixture_with_claims(
            &presentation,
            &certs,
            vec![STANDARD.encode(&certs.leaf_der)],
            &unrelated_nonce,
            &claims,
        );
        assert_eq!(
            crypto.verify(&wrong_nonce).await,
            Err(CredentialTrustError::InvalidNonce)
        );
        assert!(crypto.verify(&presentation).await.is_ok());
    });
}

#[test]
fn verifier_requires_status_resolver_for_mdoc() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let status = ciborium::Value::Map(vec![(
            ciborium::Value::Text("status_list".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("idx".into()),
                    ciborium::Value::Integer(3.into()),
                ),
                (
                    ciborium::Value::Text("uri".into()),
                    ciborium::Value::Text("https://issuer.example/status".into()),
                ),
            ]),
        )]);
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), Some(status));
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        assert!(
            crypto.verify_mdoc(&presentation).is_ok(),
            "signatures and transcript must be valid"
        );
        assert_eq!(
            crypto.verify(&presentation).await,
            Err(CredentialTrustError::InvalidStatus)
        );
    });
}

#[test]
fn authenticated_unknown_mdoc_status_cannot_become_absent() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        for status in [
            json!({"future_status":{"uri":"https://issuer.example/status"}}),
            json!({"status_list":{"idx":0,"uri":"https://issuer.example/status"},"future_status":{}}),
        ] {
            let (encoded, transcript) = valid_mdoc_presentation(
                &certs,
                Utc::now(),
                Some(super::super::crypto_helpers::json_to_cbor(&status).unwrap()),
            );
            let presentation = PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                additional_trust_anchors: vec![].into(),
            };
            assert_eq!(
                crypto.verify_mdoc(&presentation),
                Err(CredentialTrustError::InvalidStatus)
            );
            assert_eq!(
                crypto.verify(&presentation).await,
                Err(CredentialTrustError::InvalidStatus)
            );
        }
    });
}

#[test]
fn mdoc_status_tampering_or_removal_fails_before_status_resolution() {
    struct MustNotFetch;
    impl crate::ports::credential_status::CredentialStatusResolver for MustNotFetch {
        fn fetch<'a>(
            &'a self,
            _uri: &'a str,
            _format: CredentialFormat,
        ) -> nazo_digital_credentials::CredentialFuture<'a, Result<Vec<u8>, CredentialTrustError>>
        {
            panic!("unauthenticated or absent MSO status must not initiate a request")
        }
    }
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let crypto = crypto.with_status_resolver(Arc::new(MustNotFetch));
        let reference = super::super::crypto_helpers::json_to_cbor(&json!({
            "status_list": {"idx":0, "uri":"https://issuer.example/status"}
        }))
        .unwrap();
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), Some(reference));
        for remove in [false, true] {
            let mut response =
                nazo_mdoc::parser::parse(&URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();
            let auth = &mut response.documents[0].issuer_signed.issuer_auth.cose_sign1;
            let ciborium::Value::Tag(24, embedded) =
                ciborium::from_reader(auth.payload.as_deref().unwrap()).unwrap()
            else {
                panic!("MSO Tag24")
            };
            let ciborium::Value::Bytes(inner) = *embedded else {
                panic!("MSO bytes")
            };
            let mut mso: ciborium::Value = ciborium::from_reader(inner.as_slice()).unwrap();
            let fields = mso.as_map_mut().unwrap();
            if remove {
                fields.retain(|(key, _)| key.as_text() != Some("status"));
            } else {
                fields
                    .iter_mut()
                    .find(|(key, _)| key.as_text() == Some("status"))
                    .unwrap()
                    .1 = super::super::crypto_helpers::json_to_cbor(&json!({
                    "status_list": {"idx":1, "uri":"https://issuer.example/status"}
                }))
                .unwrap();
            }
            let inner = nazo_mdoc::cbor::data_item::encode_cbor_canonical(&mso).unwrap();
            auth.payload = Some(
                nazo_mdoc::cbor::data_item::encode_cbor_canonical(&ciborium::Value::Tag(
                    24,
                    Box::new(ciborium::Value::Bytes(inner)),
                ))
                .unwrap(),
            );
            let presentation = PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: URL_SAFE_NO_PAD
                    .encode(response.to_device_response_cbor().unwrap())
                    .into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.as_slice().into()),
                additional_trust_anchors: vec![].into(),
            };
            assert_eq!(
                crypto.verify(&presentation).await,
                Err(CredentialTrustError::InvalidSignature)
            );
        }
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        assert!(crypto.verify(&presentation).await.is_ok());
    });
}

// Independent wire mutation and signing makes these negative fixtures bypass
// issuance validation while retaining an authentic issuer and holder proof.
fn resign_mdoc(
    encoded: &str,
    certs: &CertificateFixture,
    edit: impl FnOnce(&mut nazo_mdoc::model::document::IssuerSignedDocument, &mut ciborium::Value),
) -> String {
    let mut response = nazo_mdoc::parser::parse(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
    let document = &mut response.documents[0];
    let payload = document
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .payload
        .as_deref()
        .unwrap();
    let outer: ciborium::Value = ciborium::from_reader(payload).unwrap();
    let ciborium::Value::Tag(24, embedded) = outer else {
        panic!("MSO Tag24")
    };
    let ciborium::Value::Bytes(inner) = *embedded else {
        panic!("MSO bytes")
    };
    let mut mso: ciborium::Value = ciborium::from_reader(inner.as_slice()).unwrap();
    edit(document, &mut mso);
    let inner = nazo_mdoc::cbor::data_item::encode_cbor_canonical(&mso).unwrap();
    let auth = &mut document.issuer_signed.issuer_auth.cose_sign1;
    auth.payload = Some(
        nazo_mdoc::cbor::data_item::encode_cbor_canonical(&ciborium::Value::Tag(
            24,
            Box::new(ciborium::Value::Bytes(inner)),
        ))
        .unwrap(),
    );
    let secret = p256::SecretKey::from_pkcs8_der(&certs.leaf_key.serialize_der()).unwrap();
    let signing = SigningKey::from_slice(&secret.to_bytes()).unwrap();
    let signature: p256::ecdsa::Signature = signing.sign(&auth.tbs_data(&[]));
    auth.signature = signature.to_bytes().to_vec();
    URL_SAFE_NO_PAD.encode(response.to_device_response_cbor().unwrap())
}

// The production issuance builder rejects these invalid dates before it creates
// signing material, so mutate the authenticated wire MSO deliberately.
fn resign_mdoc_validity(
    encoded: &str,
    certs: &CertificateFixture,
    signed: chrono::DateTime<Utc>,
    valid_from: chrono::DateTime<Utc>,
    valid_until: chrono::DateTime<Utc>,
) -> String {
    resign_mdoc(encoded, certs, |_, mso| {
        let validity = mso
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("validityInfo"))
            .unwrap()
            .1
            .as_map_mut()
            .unwrap();
        for (key, value) in validity {
            let date = match key.as_text() {
                Some("signed") => signed,
                Some("validFrom") => valid_from,
                Some("validUntil") => valid_until,
                _ => continue,
            };
            *value = ciborium::Value::Tag(
                0,
                Box::new(ciborium::Value::Text(
                    date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                )),
            );
        }
    })
}

fn replace_disclosed_mdoc_claim(
    document: &mut nazo_mdoc::model::document::IssuerSignedDocument,
    mso: &mut ciborium::Value,
    original_name: &str,
    name: &str,
    value: ciborium::Value,
) {
    use ciborium::Value as Cbor;
    let item = document
        .issuer_signed
        .name_spaces
        .get_mut("org.iso.18013.5.1")
        .unwrap()
        .iter_mut()
        .find(|item| item.element_identifier == original_name)
        .unwrap();
    item.element_identifier = name.into();
    item.element_value = value.clone();
    let value = Cbor::Map(vec![
        ("digestID".into(), item.digest_id.into()),
        ("random".into(), Cbor::Bytes(item.random.clone())),
        ("elementIdentifier".into(), name.into()),
        ("elementValue".into(), value),
    ]);
    // Independent wire construction can deliberately preserve unsupported or
    // non-preferred tags that the production canonical encoder rejects.
    let mut inner = Vec::new();
    ciborium::into_writer(&value, &mut inner).unwrap();
    item.encoded = nazo_mdoc::cbor::data_item::encode_cbor_canonical(&Cbor::Tag(
        24,
        Box::new(Cbor::Bytes(inner)),
    ))
    .unwrap();
    let digests = &mut mso
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("valueDigests"))
        .unwrap()
        .1;
    let namespace = &mut digests
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("org.iso.18013.5.1"))
        .unwrap()
        .1;
    let digest = &mut namespace
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(key, _)| key.as_integer() == Some(item.digest_id.into()))
        .unwrap()
        .1;
    *digest = Cbor::Bytes(sha2::Sha256::digest(&item.encoded).to_vec());
}

#[test]
fn authenticated_mdl_disclosures_match_the_document_signer_country() {
    use ciborium::Value as Cbor;
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let mut unexpectedly_accepted = Vec::new();
        for (name, claim, accepted) in [
            ("matching", Cbor::Text("US".into()), true),
            ("wrong_country", Cbor::Text("CA".into()), false),
            ("lowercase", Cbor::Text("us".into()), false),
            ("wrong_type", Cbor::Integer(840.into()), false),
        ] {
            let changed = resign_mdoc(&encoded, &certs, |document, mso| {
                replace_disclosed_mdoc_claim(document, mso, "given_name", "issuing_country", claim);
            });
            let bytes = URL_SAFE_NO_PAD.decode(&changed).unwrap();
            assert!(
                nazo_mdoc::verifier::verify_presentation(
                    &bytes,
                    &SessionTranscript::from_cbor(&transcript).unwrap(),
                    &nazo_mdoc::verifier::VerificationOptions {
                        now: to_protocol_time(Utc::now()).unwrap(),
                        max_documents: 1,
                    },
                )
                .is_ok(),
                "{name}: issuer, holder and digest must authenticate before the country comparison"
            );
            let presentation = PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: changed.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.as_slice().into()),
                additional_trust_anchors: vec![].into(),
            };
            let result = crypto.verify_mdoc(&presentation);
            if accepted {
                result.unwrap();
            } else if result.is_ok() {
                unexpectedly_accepted.push(name);
            } else {
                assert_eq!(result, Err(CredentialTrustError::UntrustedIssuer), "{name}");
            }
        }
        assert!(
            unexpectedly_accepted.is_empty(),
            "accepted mismatched authenticated disclosures: {unexpectedly_accepted:?}"
        );
        // An undisclosed country is not an inconsistency: selective disclosure
        // does not require revealing every mDL attribute.
        crypto
            .verify_mdoc(&PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                additional_trust_anchors: vec![].into(),
            })
            .unwrap();
    });
}

#[test]
fn authenticated_mdoc_claim_tags_are_not_erased() {
    use ciborium::Value as Cbor;
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        for claim in [
            Cbor::Tag(42, Box::new(Cbor::Text("Ada".into()))),
            Cbor::Tag(2, Box::new(Cbor::Bytes(vec![1]))),
            Cbor::Tag(
                0,
                Box::new(Cbor::Tag(1004, Box::new(Cbor::Text("2024-02-29".into())))),
            ),
            Cbor::Tag(1004, Box::new(Cbor::Text("2023-02-29".into()))),
        ] {
            let changed = resign_mdoc(&encoded, &certs, |document, mso| {
                replace_disclosed_mdoc_claim(
                    document,
                    mso,
                    "given_name",
                    "given_name",
                    claim.clone(),
                );
            });
            let bytes = URL_SAFE_NO_PAD.decode(&changed).unwrap();
            // The error must come from the application's semantic projection,
            // after issuer, digest, holder and session authentication succeeded.
            assert!(
                nazo_mdoc::verifier::verify_presentation(
                    &bytes,
                    &SessionTranscript::from_cbor(&transcript).unwrap(),
                    &nazo_mdoc::verifier::VerificationOptions {
                        now: to_protocol_time(Utc::now()).unwrap(),
                        max_documents: 1
                    },
                )
                .is_ok()
            );
            let presentation = PresentedCredential {
                format: CredentialFormat::MsoMdoc,
                encoded: changed.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.as_slice().into()),
                additional_trust_anchors: vec![].into(),
            };
            assert_eq!(
                crypto.verify(&presentation).await,
                Err(CredentialTrustError::InvalidEncoding)
            );
        }
    });
}

#[test]
fn mdl_jurisdiction_binds_only_when_the_document_signer_has_a_state() {
    use ciborium::Value as Cbor;
    futures_executor::block_on(async {
        let (crypto, template, _) = real_crypto_fixture().await;
        let (holder, _) = es256_jwk(38);
        for has_state in [false, true] {
            let certs = certificate_fixture_with_parameters(
                "issuer.example",
                KeyPair::from_pem(&template.leaf_key.serialize_pem()).unwrap(),
                true,
                |ca, leaf| {
                    if has_state {
                        for params in [ca, leaf] {
                            params
                                .distinguished_name
                                .push(DnType::StateOrProvinceName, "US-CA");
                        }
                    }
                },
            );
            let candidate = crypto_with_certificate(
                crypto.keyset.clone(),
                &certs,
                crate::policy::Openid4vcRevocationPolicy::Disabled,
            );
            let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
            for jurisdiction in [
                None,
                Some(json!("US-CA")),
                Some(json!("US-NY")),
                Some(json!(42)),
            ] {
                let accepted = jurisdiction.as_ref().is_none_or(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| !has_state || value == "US-CA")
                });
                let mut claims = json!({"org.iso.18013.5.1":{"issuing_country":"US"}});
                if let Some(value) = jurisdiction.as_ref() {
                    claims["org.iso.18013.5.1"]["issuing_jurisdiction"] = value.clone();
                }
                let result = candidate
                    .sign(&mdoc_input(
                        Some(HolderBinding::Jwk {
                            jwk: holder.clone(),
                        }),
                        claims,
                    ))
                    .await;
                if accepted {
                    result.unwrap();
                } else {
                    assert_eq!(result, Err(CredentialTrustError::InvalidEncoding));
                }
                let changed = match jurisdiction.as_ref() {
                    None => encoded.clone(),
                    Some(jurisdiction) => resign_mdoc(&encoded, &certs, |document, mso| {
                        replace_disclosed_mdoc_claim(
                            document,
                            mso,
                            "given_name",
                            "issuing_jurisdiction",
                            jurisdiction.as_str().map_or_else(
                                || Cbor::Integer(42.into()),
                                |value| Cbor::Text(value.into()),
                            ),
                        );
                    }),
                };
                let result = candidate.verify_mdoc(&PresentedCredential {
                    format: CredentialFormat::MsoMdoc,
                    encoded: changed.into(),
                    expected_nonce: "verifier-nonce".into(),
                    expected_audience: "https://verifier.example".into(),
                    mdoc_session_transcript: Some(transcript.as_slice().into()),
                    additional_trust_anchors: vec![].into(),
                });
                if accepted {
                    result.unwrap();
                } else {
                    assert_eq!(result, Err(CredentialTrustError::UntrustedIssuer));
                }
            }
        }
    });
}

#[test]
fn mdoc_current_session_failure_precedes_expiration_policy() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now(), None);
        let now = Utc::now();
        let encoded = resign_mdoc_validity(
            &encoded,
            &certs,
            now - Duration::seconds(45),
            now - Duration::seconds(45),
            now - Duration::seconds(30),
        );
        let mut presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded: encoded.into(),
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            mdoc_session_transcript: Some(transcript.into()),
            additional_trust_anchors: vec![].into(),
        };
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidValidity)
        );
        presentation.mdoc_session_transcript = Some(
            SessionTranscript::redirect(RedirectHandover {
                client_id: "https://verifier.example",
                nonce: "another-transaction",
                jwk_thumbprint: None,
                response_uri: "https://verifier.example/response",
            })
            .unwrap()
            .into_bytes()
            .into(),
        );
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidSessionBinding)
        );
    });
}

mod certificate_path_constraints {
    use nazo_crypto::certificate::{self as certs, CertificateDer};

    const NOW: u64 = 1_800_000_000;

    fn ca(name: &str, path_length: u8) -> certs::CertificateParams {
        let mut params = certs::CertificateParams::default();
        params
            .distinguished_name
            .push(certs::DnType::CommonName, name);
        params.is_ca = certs::IsCa::Ca(certs::BasicConstraints::Constrained(path_length));
        params.key_usages = vec![certs::KeyUsagePurpose::KeyCertSign];
        params
    }

    #[test]
    fn mdoc_chain_enforces_document_signing_constraints() {
        let root_key = certs::generate_p256_private_key_pem().unwrap();
        let root = certs::self_signed(ca("root", 3), &root_key).unwrap();
        for case in ["valid", "pathlen", "keyusage", "nameconstraint", "critical"] {
            let issuer_key = certs::generate_p256_private_key_pem().unwrap();
            let mut issuer = ca("intermediate", if case == "pathlen" { 0 } else { 1 });
            if case == "keyusage" {
                issuer.key_usages = vec![certs::KeyUsagePurpose::DigitalSignature];
            }
            if case == "nameconstraint" {
                issuer.name_constraints = Some(rcgen::NameConstraints {
                    permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(
                        "allowed.example".into(),
                    )],
                    excluded_subtrees: Vec::new(),
                });
            }
            let issuer = certs::sign(issuer, &issuer_key, &root, &root_key).unwrap();
            let leaf_key = certs::generate_p256_private_key_pem().unwrap();
            let mut leaf =
                certs::CertificateParams::new(vec!["document.example".to_owned()]).unwrap();
            leaf.key_usages = vec![certs::KeyUsagePurpose::DigitalSignature];
            // ISO mdoc document signing is not TLS client or server authentication.
            leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(vec![
                1, 0, 18013, 5, 1, 2,
            ])];
            if case == "critical" {
                let mut extension =
                    certs::CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![0x05, 0x00]);
                extension.set_criticality(true);
                leaf.custom_extensions.push(extension);
            }
            let chain = if case == "pathlen" {
                let sub_key = certs::generate_p256_private_key_pem().unwrap();
                let sub = certs::sign(ca("sub-ca", 0), &sub_key, &issuer, &issuer_key).unwrap();
                vec![
                    certs::sign(leaf, &leaf_key, &sub, &sub_key).unwrap(),
                    sub,
                    issuer,
                ]
            } else {
                vec![
                    certs::sign(leaf, &leaf_key, &issuer, &issuer_key).unwrap(),
                    issuer,
                ]
            };
            let mdoc_accepted = super::super::mdoc::verify_certificate_chain_with_scoped_at(
                &chain,
                std::slice::from_ref(&root),
                &[],
                NOW as i64,
            )
            .unwrap()
            .is_some();
            assert_eq!(mdoc_accepted, case == "valid", "{case}");
            let chain: Vec<_> = chain.into_iter().map(CertificateDer::from).collect();
            assert_eq!(
                certs::verify_document_signing_chain_at(&chain, &root.as_slice().into(), NOW)
                    .is_ok(),
                case == "valid",
                "{case}",
            );
            if case == "valid" {
                let mut out_of_order = chain.clone();
                out_of_order.swap(0, 1);
                assert!(
                    certs::verify_document_signing_chain_at(
                        &out_of_order,
                        &root.as_slice().into(),
                        NOW
                    )
                    .is_err()
                );
            }
        }
    }
}
