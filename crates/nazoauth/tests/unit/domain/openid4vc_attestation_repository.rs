use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator;
use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
use serde_json::{Value, json};

fn es256_test_key(seed: u8) -> (Value, EncodingKey) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).expect("valid P-256 test key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate")),
    });
    let document = signing_key.to_pkcs8_der().expect("P-256 PKCS#8 key");
    (jwk, EncodingKey::from_ec_der(document.as_bytes()))
}

fn signed_client_attestation_jwt(
    claims: &Value,
    key: &EncodingKey,
    typ: &str,
    algorithm: Algorithm,
    kid: Option<&str>,
) -> String {
    let mut header = Header::new(algorithm);
    header.typ = Some(typ.to_owned());
    header.kid = kid.map(ToOwned::to_owned);
    encode(&header, claims, key).expect("client attestation JWT")
}

fn valid_client_attestation_fixture() -> (
    Openid4vcClientAttestationValidator,
    String,
    String,
    Value,
    EncodingKey,
    i64,
) {
    let now = Utc::now().timestamp();
    let (mut attester_jwk, attester_key) = es256_test_key(83);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let (instance_jwk, instance_key) = es256_test_key(89);
    let attestation = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    let proof = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
        "oauth-client-attestation-pop+jwt",
        Algorithm::ES256,
        None,
    );
    let validator = Openid4vcClientAttestationValidator::new(
        "https://attester.example",
        json!({"keys": [attester_jwk]}),
    )
    .expect("client attestation validator");
    (
        validator,
        attestation,
        proof,
        instance_jwk,
        instance_key,
        now,
    )
}

#[tokio::test]
async fn client_attestation_trust_policy_constructor_and_lookup_fail_closed_without_database() {
    let (mut attester_jwk, attester_key) = es256_test_key(97);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let pool = nazo_postgres::create_pool(
        "postgres://openid4vc_policy:openid4vc_policy@127.0.0.1:1/oauth".to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    let repository = nazo_postgres::TenantResourceRepository::new(pool.clone());
    let configured = Openid4vcClientAttestationValidator::with_trust_policies(
        Some((
            "https://attester.example".to_owned(),
            json!({"keys": [attester_jwk.clone()]}),
        )),
        Arc::new(repository),
        uuid::Uuid::nil(),
    )
    .expect("static trust plus ordinary policy repository should configure");
    let now = Utc::now().timestamp();
    let instance_jwk = es256_test_key(101).0;
    let instance_key = es256_test_key(101).1;
    let attestation = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    let proof = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "constructor-proof",
        }),
        &instance_key,
        "oauth-client-attestation-pop+jwt",
        Algorithm::ES256,
        None,
    );
    let validated = configured
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("configured static trust must validate a matching attestation");
    assert_eq!(validated.client_id, "wallet-client");

    let dynamic = Openid4vcClientAttestationValidator::with_trust_policies(
        None,
        Arc::new(nazo_postgres::TenantResourceRepository::new(pool)),
        uuid::Uuid::nil(),
    )
    .expect("ordinary policy-only validator should configure");
    let (static_validator, attestation, proof, _, _, now) = valid_client_attestation_fixture();
    let error = dynamic
        .validate_for_client(&attestation, &proof, "https://issuer.example", now)
        .await
        .expect_err("unavailable ordinary policy database must fail closed");
    assert!(!format!("{error:#}").is_empty());
    let validated = static_validator
        .validate_for_client(&attestation, &proof, "https://issuer.example", now)
        .await
        .expect("static validator should remain observable through its public behavior");
    assert_eq!(validated.client_id, "wallet-client");
}
