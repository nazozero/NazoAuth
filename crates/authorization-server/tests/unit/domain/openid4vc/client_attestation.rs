use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
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

#[test]
fn client_attestation_draft_07_accepts_optional_time_claims_and_binds_instance_key() {
    let now = Utc::now().timestamp();
    let (mut attester_jwk, attester_key) = es256_test_key(5);
    let (instance_jwk, instance_key) = es256_test_key(7);
    let mut attestation_header = Header::new(Algorithm::ES256);
    attestation_header.typ = Some("oauth-client-attestation+jwt".to_owned());
    attestation_header.kid = Some("attester-key".to_owned());
    let attestation = encode(
        &attestation_header,
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
    )
    .expect("client attestation JWT");
    let mut proof_header = Header::new(Algorithm::ES256);
    proof_header.typ = Some("oauth-client-attestation-pop+jwt".to_owned());
    let proof = encode(
        &proof_header,
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
    )
    .expect("client attestation PoP JWT");
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let validator = Openid4vcClientAttestationValidator::new(
        "https://attester.example",
        json!({"keys": [attester_jwk]}),
    )
    .expect("client attestation validator");

    let validated = validator
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("draft-07 optional claims must remain optional");

    assert_eq!(validated.client_id, "wallet-client");
    assert_eq!(
        validated.client_instance_key_thumbprint,
        client_instance_key_thumbprint(&instance_jwk).expect("instance JWK thumbprint")
    );
    assert_eq!(validated.replay_id, "fresh-proof");
    assert_eq!(validated.replay_ttl_seconds, 300);
}

#[test]
fn client_attestation_rejects_private_instance_key_material() {
    let (mut instance_jwk, _) = es256_test_key(11);
    instance_jwk["d"] = json!("private-material");

    assert!(client_instance_key_thumbprint(&instance_jwk).is_err());
}

#[test]
fn client_attestation_configuration_and_unverified_subject_are_strict() {
    let (jwk, key) = es256_test_key(79);
    assert!(Openid4vcClientAttestationValidator::new("", json!({"keys": [jwk]})).is_err());
    assert!(
        Openid4vcClientAttestationValidator::new("https://attester.example", json!({"keys": []}),)
            .is_err()
    );
    for invalid in [
        json!({"kty": "OKP", "crv": "Ed25519", "x": "AQ"}),
        json!({"kty": "EC", "crv": "P-384", "x": "AQ", "y": "Ag"}),
    ] {
        assert!(client_instance_key_thumbprint(&invalid).is_err());
    }

    let compact = signed_client_attestation_jwt(
        &json!({"sub": "wallet-client"}),
        &key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id(&compact).as_deref(),
        Some("wallet-client")
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id("not-a-jwt"),
        None
    );
    let no_subject = signed_client_attestation_jwt(
        &json!({"sub": ""}),
        &key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        None,
    );
    assert_eq!(
        Openid4vcClientAttestationValidator::unverified_client_id(&no_subject),
        None
    );
}

#[test]
fn client_attestation_rejects_header_key_claim_and_replay_contract_violations() {
    let (validator, attestation, proof, instance_jwk, instance_key, now) =
        valid_client_attestation_fixture();
    validator
        .validate(&attestation, &proof, "https://issuer.example", now)
        .expect("valid client attestation fixture");

    let (mut attester_jwk, attester_key) = es256_test_key(83);
    attester_jwk["kid"] = json!("attester-key");
    attester_jwk["alg"] = json!("ES256");
    let trust = json!({"keys": [attester_jwk]});
    let instance_claim = json!({"jwk": instance_jwk.clone()});
    let attestation_claims = json!({
        "iss": "https://attester.example",
        "sub": "wallet-client",
        "exp": now + 600,
        "cnf": instance_claim,
    });
    let make_validator = |trust: Value| {
        Openid4vcClientAttestationValidator::new("https://attester.example", trust)
            .expect("validator configuration")
    };

    let wrong_type = signed_client_attestation_jwt(
        &attestation_claims,
        &attester_key,
        "JWT",
        Algorithm::ES256,
        Some("attester-key"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&wrong_type, &proof, "https://issuer.example", now)
            .is_err()
    );

    let wrong_algorithm = signed_client_attestation_jwt(
        &attestation_claims,
        &EncodingKey::from_secret(b"attester-secret"),
        "oauth-client-attestation+jwt",
        Algorithm::HS256,
        Some("attester-key"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&wrong_algorithm, &proof, "https://issuer.example", now)
            .is_err()
    );
    let unknown_kid = signed_client_attestation_jwt(
        &attestation_claims,
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("unknown-kid"),
    );
    assert!(
        make_validator(trust.clone())
            .validate(&unknown_kid, &proof, "https://issuer.example", now)
            .is_err()
    );
    let mut ambiguous = trust.clone();
    ambiguous["keys"] = json!([ambiguous["keys"][0].clone(), ambiguous["keys"][0].clone()]);
    assert!(
        make_validator(ambiguous)
            .validate(&attestation, &proof, "https://issuer.example", now)
            .is_err()
    );

    let mut bad_trust_key = trust["keys"][0].clone();
    bad_trust_key["x"] = json!("invalid");
    assert!(
        make_validator(json!({"keys": [bad_trust_key]}))
            .validate(&attestation, &proof, "https://issuer.example", now)
            .is_err()
    );

    for claims in [
        json!({"sub": "wallet-client", "exp": now + 600}),
        json!({"iss": "https://wrong.example", "sub": "wallet-client", "exp": now + 600, "cnf": {"jwk": instance_jwk.clone()}}),
        json!({"iss": "https://attester.example", "sub": "", "exp": now + 600, "cnf": {"jwk": instance_jwk.clone()}}),
        json!({"iss": "https://attester.example", "sub": "wallet-client", "exp": now + 600, "cnf": {}}),
        json!({"iss": "https://attester.example", "sub": "wallet-client", "exp": now + 600, "cnf": {"jwk": {"kty": "RSA"}}}),
    ] {
        let token = signed_client_attestation_jwt(
            &claims,
            &attester_key,
            "oauth-client-attestation+jwt",
            Algorithm::ES256,
            Some("attester-key"),
        );
        assert!(
            validator
                .validate(&token, &proof, "https://issuer.example", now)
                .is_err()
        );
    }

    let future_iat = signed_client_attestation_jwt(
        &json!({
            "iss": "https://attester.example",
            "sub": "wallet-client",
            "iat": now + 61,
            "exp": now + 600,
            "cnf": {"jwk": instance_jwk.clone()},
        }),
        &attester_key,
        "oauth-client-attestation+jwt",
        Algorithm::ES256,
        Some("attester-key"),
    );
    assert!(
        validator
            .validate(&future_iat, &proof, "https://issuer.example", now)
            .is_err()
    );

    let wrong_proof_type = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &instance_key,
        "JWT",
        Algorithm::ES256,
        None,
    );
    assert!(
        validator
            .validate(
                &attestation,
                &wrong_proof_type,
                "https://issuer.example",
                now
            )
            .is_err()
    );

    let wrong_proof_algorithm = signed_client_attestation_jwt(
        &json!({
            "iss": "wallet-client",
            "aud": "https://issuer.example",
            "iat": now,
            "jti": "fresh-proof",
        }),
        &EncodingKey::from_secret(b"proof-secret"),
        "oauth-client-attestation-pop+jwt",
        Algorithm::HS256,
        None,
    );
    assert!(
        validator
            .validate(
                &attestation,
                &wrong_proof_algorithm,
                "https://issuer.example",
                now
            )
            .is_err()
    );

    for claims in [
        json!({"iss": "other-client", "aud": "https://issuer.example", "iat": now, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "wrong-audience", "iat": now, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now, "jti": ""}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now, "jti": "x".repeat(129)}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now - 301, "jti": "fresh-proof"}),
        json!({"iss": "wallet-client", "aud": "https://issuer.example", "iat": now + 61, "jti": "fresh-proof"}),
    ] {
        let token = signed_client_attestation_jwt(
            &claims,
            &instance_key,
            "oauth-client-attestation-pop+jwt",
            Algorithm::ES256,
            None,
        );
        assert!(
            validator
                .validate(&attestation, &token, "https://issuer.example", now)
                .is_err()
        );
    }
}

#[test]
fn client_attestation_validate_for_client_uses_static_trust_when_client_is_unbound() {
    futures_executor::block_on(async {
        let (validator, attestation, proof, _, _, now) = valid_client_attestation_fixture();
        let validated = validator
            .validate_for_client(&attestation, &proof, "https://issuer.example", now)
            .await
            .expect("static trust fallback should validate");
        assert_eq!(validated.client_id, "wallet-client");
    });
}
