use std::{collections::BTreeSet, sync::Arc};

#[path = "../../support/mdoc_signer.rs"]
mod mdoc_signer;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseKeyBuilder, SignatureContext, iana};
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode_header, encode};
use mdoc_rs::{
    MdocError,
    builder::{CoseSigner, DocumentBuilder},
    model::types::ValidityInfo,
    response_builder::DeviceResponseBuilder,
    session::SessionTranscript,
};
use nazo_digital_credentials::{
    CertificateRevocationSnapshot, CredentialFormat, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError, HolderBinding, PresentedCredential, VcIssuerTrustPolicy,
};
use nazo_key_management::{
    KeyManager, KeySettings, LocalKeyRegistration, Openid4vcMaterial, Openid4vcPublicMaterial,
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

use super::mdoc::{
    mdoc_assessments_accepted, mdoc_failed_assessments_accepted, mdoc_holder_key,
    standard_device_authentication_bytes, verify_direct_scoped_trust_anchor,
};
use super::*;
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
        presentation: &nazo_digital_credentials::PresentedCredential,
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
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    >;
}

impl CredentialCryptoTestExt for Openid4vcCredentialCrypto {
    fn verify_sd_jwt(
        &self,
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::sd_jwt::verify(self, presentation)
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
        presentation: &nazo_digital_credentials::PresentedCredential,
    ) -> Result<
        nazo_digital_credentials::VerifiedCredential,
        nazo_digital_credentials::CredentialTrustError,
    > {
        super::mdoc::verify(self, presentation)
    }
}

struct CertificateFixture {
    ca_der: Vec<u8>,
    ca_pem: String,
    leaf_der: Vec<u8>,
    leaf_pem: String,
    leaf_key: KeyPair,
}

fn certificate_fixture(host: &str) -> CertificateFixture {
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
    let now = time::OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenID4VC test root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::days(365);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-signed CA");

    let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).expect("leaf SAN");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    leaf_params
        .distinguished_name
        .push(DnType::CountryName, "US");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.use_authority_key_identifier_extension = include_aki;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::days(365);
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca)
        .expect("leaf certificate");

    CertificateFixture {
        ca_der: ca.der().as_ref().to_vec(),
        ca_pem: ca.pem(),
        leaf_der: leaf.der().as_ref().to_vec(),
        leaf_pem: leaf.pem(),
        leaf_key,
    }
}

async fn real_crypto_fixture() -> (Openid4vcCredentialCrypto, CertificateFixture, String) {
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
        Arc::new(mdoc_signer::LocalTestMdocDocumentSigner),
    )
    .expect("fixture OpenID4VC material should validate")
}

struct TestMdocIssuerSigner {
    signing_key: SigningKey,
    certificate_der: Vec<u8>,
}

impl CoseSigner for TestMdocIssuerSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, MdocError> {
        let signature: p256::ecdsa::Signature = self.signing_key.sign(tbs);
        Ok(signature.to_bytes().to_vec())
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}

fn valid_mdoc_presentation(
    certs: &CertificateFixture,
    signed_at: chrono::DateTime<Utc>,
) -> (String, Vec<u8>) {
    let issuer_secret =
        p256::SecretKey::from_pkcs8_der(&certs.leaf_key.serialize_der()).expect("leaf private key");
    let issuer_signing_key =
        SigningKey::from_slice(&issuer_secret.to_bytes()).expect("leaf signing key");
    let device_signing_key = SigningKey::from_slice(&[83; 32]).expect("device signing key");
    let device_point = device_signing_key.verifying_key().to_sec1_point(false);
    let device_key = CoseKeyBuilder::new_ec2_pub_key(
        iana::EllipticCurve::P_256,
        device_point.x().expect("device x").to_vec(),
        device_point.y().expect("device y").to_vec(),
    )
    .build();
    let now = Utc::now();
    let issuer_document = DocumentBuilder::new("org.iso.18013.5.1.mDL")
        .device_key(device_key)
        .validity(ValidityInfo {
            signed: signed_at,
            valid_from: now - Duration::minutes(1),
            valid_until: now + Duration::hours(1),
            expected_update: None,
        })
        .add_namespace(
            "org.iso.18013.5.1",
            vec![
                ("given_name", ciborium::Value::Text("Ada".to_owned())),
                ("age", ciborium::Value::Integer(42.into())),
            ],
        )
        .sign(&TestMdocIssuerSigner {
            signing_key: issuer_signing_key,
            certificate_der: certs.leaf_der.clone(),
        })
        .expect("issuer-signed mdoc");
    let transcript = SessionTranscript::Oid4vp {
        mdoc_nonce: "mdoc-nonce".to_owned(),
        client_id: "https://verifier.example".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        verifier_nonce: "verifier-nonce".to_owned(),
    };
    let transcript_bytes = transcript.to_cbor_bytes().expect("session transcript");
    let device_key_der = device_signing_key.to_bytes().to_vec();
    let mut response = DeviceResponseBuilder::from_documents(vec![issuer_document])
        .session_transcript(transcript)
        .authenticate_with_signature(device_key_der, -7)
        .build()
        .expect("device response");
    let document = response
        .documents
        .first_mut()
        .expect("device response document");
    let device_signed = document
        .device_signed
        .as_mut()
        .expect("device-signed response");
    let mdoc_rs::model::types::DeviceAuth::Signature(device_signature) =
        &mut device_signed.device_auth
    else {
        panic!("device response should use a signature");
    };
    let device_authentication = standard_device_authentication_bytes(
        &transcript_bytes,
        &document.doc_type,
        &device_signed.name_spaces_bytes,
    )
    .expect("standard DeviceAuthenticationBytes");
    let signature_input = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        &[],
        &device_authentication,
    );
    let signature: p256::ecdsa::Signature = device_signing_key.sign(&signature_input);
    device_signature.payload = None;
    device_signature.signature = signature.to_bytes().to_vec();
    (
        URL_SAFE_NO_PAD.encode(
            response
                .to_device_response_cbor()
                .expect("device response CBOR"),
        ),
        transcript_bytes,
    )
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

fn sd_presentation_fixture() -> (
    Openid4vcCredentialCrypto,
    PresentedCredential,
    Value,
    CertificateFixture,
) {
    sd_presentation_fixture_with_aki(true)
}

fn sd_presentation_fixture_with_aki(
    include_aki: bool,
) -> (
    Openid4vcCredentialCrypto,
    PresentedCredential,
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
        "status": {"idx": 3},
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
        encoded,
        expected_nonce: expected_nonce.to_owned(),
        expected_audience: expected_audience.to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        mdoc_session_transcript: None,
        additional_trust_anchors: vec![],
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
            Arc::new(mdoc_signer::LocalTestMdocDocumentSigner),
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
                &lease,
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
                    &crypto.prepare_signing().expect("failing signing lease"),
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
    assert_eq!(
        crypto.x509_hash_client_id(&lease).expect("x509 hash"),
        format!(
            "x509_hash:{}",
            URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&certs.leaf_der))
        )
    );
    assert_eq!(
        crypto.x509_san_dns_client_id(&lease).expect("DNS SAN"),
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
            json!({"given_name": "Ada", "age": 42}),
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
        assert_eq!(parts.len(), 4);
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

        let malformed = sd_input(None, json!("not an object"), None);
        assert_eq!(
            crypto.sign(&malformed).await,
            Err(CredentialTrustError::InvalidEncoding)
        );
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
                &mdoc_rs::cbor::data_item::encode_cbor_canonical(&issuer_auth).unwrap(),
            )
            .unwrap();
            let mso = mdoc_rs::model::issuer_auth::IssuerAuth::new(cose)
                .mso()
                .unwrap();
            assert!(
                mso.validity_info.signed >= not_before,
                "published MSO signed time must not precede the pinned certificate"
            );
            assert!(mso.validity_info.signed <= not_after);
            assert_eq!(mso.validity_info.signed, issued_at.max(not_before));
            assert_eq!(mso.validity_info.valid_from, mso.validity_info.signed);
            assert_eq!(
                mso.validity_info.valid_until, input.expires_at,
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
            Arc::new(mdoc_signer::LocalTestMdocDocumentSigner),
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
        assert_eq!(verified.status, Some(json!({"idx": 3})));
        assert!(verified.holder_key.is_some());

        let mut malformed = presentation.clone();
        malformed.encoded = "broken".to_owned();
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
        wrong_typ.encoded = format!("{jwt}~{}~{}", parts[1], parts[2]);
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
        unknown_disclosure.encoded = format!("{}~{}~{}", parts[0], disclosure, parts[2]);
        assert_eq!(
            crypto.verify_sd_jwt(&unknown_disclosure),
            Err(CredentialTrustError::InvalidHolderBinding),
            "changing the disclosure while retaining the original KB JWT breaks sd_hash",
        );
        unknown_disclosure.encoded = rebind(format!("{}~{disclosure}~", parts[0]));
        assert_eq!(
            crypto.verify_sd_jwt(&unknown_disclosure),
            Err(CredentialTrustError::InvalidSignature),
            "a valid holder binding cannot authorize an issuer-unsigned disclosure",
        );

        let mut duplicate = presentation.clone();
        duplicate.encoded = rebind(format!("{}~{}~{}~", parts[0], parts[1], parts[1]));
        assert_eq!(
            crypto.verify_sd_jwt(&duplicate),
            Err(CredentialTrustError::InvalidEncoding)
        );
    })
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
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_type_kb),
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
        encoded: format!("{credential_jwt}~{no_disclosure_kb}"),
        ..presentation.clone()
    };
    let verified = crypto
        .verify_sd_jwt(&no_disclosure)
        .expect("empty disclosure presentation");
    assert_eq!(verified.claims, json!({}));

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
        encoded: format!("{}~{}~{}", parts[0], parts[1], wrong_hash_kb),
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
    no_anchor.additional_trust_anchors = vec![certs.leaf_der.clone()];
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
    no_cnf.encoded = format!("{jwt}~{}", parts[2]);
    assert_eq!(
        crypto.verify_sd_jwt(&no_cnf),
        Err(CredentialTrustError::InvalidHolderBinding)
    );

    let mut wrong_audience = presentation.clone();
    wrong_audience.expected_audience = "https://other.example".to_owned();
    assert_eq!(
        crypto.verify_sd_jwt(&wrong_audience),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
    let mut wrong_nonce = presentation.clone();
    wrong_nonce.expected_nonce = "other-nonce".to_owned();
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
            encoded: URL_SAFE_NO_PAD.encode([0xa0]),
            expected_nonce: "nonce".to_owned(),
            expected_audience: "aud".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            mdoc_session_transcript: None,
            additional_trust_anchors: vec![],
        };
        assert_eq!(
            crypto.verify_mdoc(&missing_transcript),
            Err(CredentialTrustError::InvalidHolderBinding)
        );
        let bad_cbor = PresentedCredential {
            mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6]),
            ..missing_transcript.clone()
        };
        assert_eq!(
            crypto.verify_mdoc(&bad_cbor),
            Err(CredentialTrustError::InvalidEncoding)
        );
        let bad_anchor = PresentedCredential {
            mdoc_session_transcript: Some(vec![0x83, 0xf6, 0xf6, 0xf6]),
            encoded: URL_SAFE_NO_PAD.encode([0xa0]),
            additional_trust_anchors: vec![vec![1, 2, 3]],
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
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now());
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded,
            expected_nonce: "verifier-nonce".to_owned(),
            expected_audience: "https://verifier.example".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            mdoc_session_transcript: Some(transcript),
            additional_trust_anchors: vec![],
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
fn mdoc_verification_rejects_signing_before_certificate_validity() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let (encoded, transcript) =
            valid_mdoc_presentation(&certs, Utc::now() - Duration::hours(1));
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded,
            expected_nonce: "verifier-nonce".to_owned(),
            expected_audience: "https://verifier.example".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            mdoc_session_transcript: Some(transcript),
            additional_trust_anchors: vec![],
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
            Err(CredentialTrustError::InvalidSignature)
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
        Err(CredentialTrustError::InvalidEncoding)
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
        Err(CredentialTrustError::InvalidEncoding)
    ));
}

#[test]
fn mdoc_direct_scoped_trust_anchor_is_exact_self_signed_and_lease_scoped() {
    let certs = certificate_fixture("issuer.example");
    let now = Utc::now().timestamp();

    assert!(
        verify_direct_scoped_trust_anchor(
            std::slice::from_ref(&certs.ca_der),
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("exact direct trust anchor")
    );
    assert!(
        !verify_direct_scoped_trust_anchor(std::slice::from_ref(&certs.ca_der), &[], now)
            .expect("no active trust anchor")
    );
    assert!(
        !verify_direct_scoped_trust_anchor(
            std::slice::from_ref(&certs.leaf_der),
            std::slice::from_ref(&certs.leaf_der),
            now,
        )
        .expect("non-CA signer cannot become a direct trust anchor")
    );
    assert!(
        !verify_direct_scoped_trust_anchor(
            &[certs.ca_der.clone(), certs.leaf_der],
            std::slice::from_ref(&certs.ca_der),
            now,
        )
        .expect("direct-anchor mode requires an exact one-certificate chain")
    );
}

#[test]
fn mdoc_assessment_and_holder_helpers_fail_closed() {
    let passed = mdoc_rs::verifier::VerificationAssessment {
        status: mdoc_rs::verifier::VerificationStatus::Passed,
        check: "passed".to_owned(),
        reason: None,
        category: mdoc_rs::verifier::VerificationCategory::IssuerAuth,
        id: mdoc_rs::verifier::CheckId::IssuerCertificateValidity,
    };
    assert!(!mdoc_failed_assessments_accepted(
        [&passed].into_iter(),
        true,
        true
    ));
    assert!(!mdoc_assessments_accepted(
        &mdoc_rs::verifier::VerifiedMDoc {
            mdoc: mdoc_rs::model::MDoc {
                version: "1.0".to_owned(),
                status: mdoc_rs::model::MDocStatus::Ok,
                documents: vec![],
            },
            assessments: vec![],
            is_valid: true,
        },
        false,
        true,
    ));

    let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![1; 32], vec![2; 32])
        .build();
    let holder = mdoc_holder_key(Some(&key)).expect("holder key");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(holder["cose_key"].as_str().expect("encoded key"))
            .expect("COSE key"),
        key.to_vec().expect("COSE serialization")
    );
    assert_eq!(
        mdoc_holder_key(None),
        Err(CredentialTrustError::InvalidHolderBinding)
    );
}

#[test]
fn standard_device_authentication_bytes_is_deterministic_and_rejects_bad_inputs() {
    let transcript = [0x83, 0xf6, 0xf6, 0xf6];
    let first = standard_device_authentication_bytes(&transcript, "org.iso.18013.5.1.mDL", &[0xa0])
        .expect("DeviceAuthenticationBytes");
    let second =
        standard_device_authentication_bytes(&transcript, "org.iso.18013.5.1.mDL", &[0xa0])
            .expect("DeviceAuthenticationBytes");
    assert_eq!(first, second);
    assert!(standard_device_authentication_bytes(&[0xff], "doc", &[0xa0]).is_err());
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
    presentation.additional_trust_anchors = vec![unrelated.ca_der.clone()];
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
    presentation.additional_trust_anchors = vec![certs.ca_der.clone()];
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
        let (encoded, transcript) = valid_mdoc_presentation(&certs, Utc::now());
        let unrelated = certificate_fixture("unrelated.example");
        let mut presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded,
            expected_nonce: "verifier-nonce".into(),
            expected_audience: "https://verifier.example".into(),
            response_uri: "https://verifier.example/response".into(),
            mdoc_session_transcript: Some(transcript),
            additional_trust_anchors: vec![unrelated.ca_der],
        };
        assert_eq!(
            strict.verify_mdoc(&presentation),
            Err(CredentialTrustError::RevocationStatusUnknown)
        );
        presentation.additional_trust_anchors = vec![certs.ca_der.clone()];
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
    presentation.additional_trust_anchors = vec![expired.der().as_ref().to_vec()];
    assert_eq!(
        strict.verify_sd_jwt(&presentation),
        Err(CredentialTrustError::RevocationStatusUnknown)
    );
    presentation.additional_trust_anchors = vec![vec![1, 2, 3]];
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
    presentation.additional_trust_anchors = vec![unrelated.ca_der.clone()];
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
            encoded: format!("{}~{}~{kb}", parts[0], parts[1]),
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
        encoded: format!("{}~{}~{kb}", parts[0], parts[1]),
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
        Result<
            Option<nazo_openid4vp::PresentationTransaction>,
            nazo_openid4vp::PresentationStoreError,
        >,
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
        Result<Option<nazo_openid4vp::StoredPresentation>, nazo_openid4vp::PresentationStoreError>,
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
        let (encoded, _) = valid_mdoc_presentation(&certs, Utc::now());
        let different_transcript = SessionTranscript::Oid4vp {
            mdoc_nonce: "mdoc-nonce".to_owned(),
            client_id: "https://verifier.example".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            verifier_nonce: "another-transaction".to_owned(),
        }
        .to_cbor_bytes()
        .unwrap();
        let presentation = PresentedCredential {
            format: CredentialFormat::MsoMdoc,
            encoded,
            expected_nonce: "another-transaction".to_owned(),
            expected_audience: "https://verifier.example".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            mdoc_session_transcript: Some(different_transcript),
            additional_trust_anchors: vec![],
        };
        assert_eq!(
            crypto.verify_mdoc(&presentation),
            Err(CredentialTrustError::InvalidSessionBinding)
        );
    })
}

fn signed_sd_transaction(
    presentation: &PresentedCredential,
) -> nazo_openid4vp::PresentationTransaction {
    nazo_openid4vp::PresentationTransaction {
        id: uuid::Uuid::now_v7(),
        client_id_prefix: nazo_openid4vp::ClientIdPrefix::RedirectUri,
        request_method: nazo_openid4vp::RequestMethod::RequestUriSignedPost,

        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request: serde_json::from_value(json!({
            "client_id": presentation.expected_audience,
            "response_type": "vp_token", "response_mode": "direct_post",
            "response_uri": presentation.response_uri,
            "nonce": presentation.expected_nonce, "state": "state",
            "dcql_query": {
                "credentials": [
                    {"id": "first", "format": "dc+sd-jwt", "meta": {}},
                    {"id": "optional", "format": "dc+sd-jwt", "meta": {}}
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
    presentation: &PresentedCredential,
    certs: &CertificateFixture,
    x5c: Vec<String>,
    nonce: &str,
) -> PresentedCredential {
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0].split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    resign_sd_fixture_with_claims(presentation, certs, x5c, nonce, &claims)
}

fn resign_sd_fixture_with_claims(
    presentation: &PresentedCredential,
    certs: &CertificateFixture,
    x5c: Vec<String>,
    nonce: &str,
    claims: &Value,
) -> PresentedCredential {
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
        encoded: format!("{sd_input}{kb}"),
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
                (accepted.expected_nonce.as_str(), false),
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
                    encoded: format!("{sd_input}{kb}"),
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
