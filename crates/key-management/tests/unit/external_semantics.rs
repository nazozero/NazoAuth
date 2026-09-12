use super::*;
use crate::serialization::{generate_key_material, public_jwk_from_private_der};
use serde_json::json;
use std::sync::Arc;

fn external_signing_key() -> ExternalSigningKey {
    ExternalSigningKey {
        key_ref: "kms://test/key".to_owned(),
        signer: Arc::new(crate::test_support::FailingExternalKeySigner),
    }
}

fn eddsa_fixture(kid: &str) -> (Vec<u8>, Value) {
    let material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .expect("public JWK should derive");
    (material.private_pkcs8_der, public_jwk)
}

fn sign_input(private_key: &[u8], signing_input: &str) -> String {
    jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &jsonwebtoken::EncodingKey::from_ed_der(private_key),
        jsonwebtoken::Algorithm::EdDSA,
    )
    .expect("test signature should sign")
}

#[test]
fn external_signature_verification_accepts_signature_bound_to_active_public_jwk() {
    let kid = "external-kid";
    let signing_input = "header.claims";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, signing_input);

    verify_external_jwt_signature(
        &external_signing_key(),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        signing_input,
        &signature,
        &public_jwk,
    )
    .expect("matching external signature should verify locally");
}

#[test]
fn external_signature_verification_rejects_signature_that_does_not_match_input() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "header.claims");
    let error = verify_external_jwt_signature(
        &external_signing_key(),
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        "header.tampered_claims",
        &signature,
        &public_jwk,
    )
    .expect_err("external signer output must be checked against the exact signing input");

    assert!(
        format!("{error}").contains("does not verify"),
        "unexpected verification error: {error}"
    );
}

#[test]
fn external_signature_verification_rejects_unusable_active_public_jwk() {
    let error = verify_external_jwt_signature(
        &external_signing_key(),
        "external-kid",
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        "ZmFrZS1zaWduYXR1cmU",
        &json!({"kty": "oct", "k": "not-a-public-signing-key"}),
    )
    .expect_err("external signer verification must fail closed without usable public JWK");

    assert!(
        format!("{error}").contains("not usable"),
        "unexpected verification error: {error}"
    );
}

#[test]
fn external_public_jwk_policy_is_algorithm_and_usage_bound() {
    let (_private_key, ed_jwk) = eddsa_fixture("ed-kid");
    assert!(decoding_key_from_public_jwk(&ed_jwk, jsonwebtoken::Algorithm::EdDSA).is_some());

    let mut wrong_algorithm = ed_jwk.clone();
    wrong_algorithm["alg"] = json!("RS256");
    assert!(
        decoding_key_from_public_jwk(&wrong_algorithm, jsonwebtoken::Algorithm::EdDSA).is_none()
    );

    let mut private_jwk = ed_jwk.clone();
    private_jwk["d"] = json!("private-material");
    assert!(decoding_key_from_public_jwk(&private_jwk, jsonwebtoken::Algorithm::EdDSA).is_none());

    let mut encryption_key = ed_jwk.clone();
    encryption_key["use"] = json!("enc");
    assert!(
        decoding_key_from_public_jwk(&encryption_key, jsonwebtoken::Algorithm::EdDSA).is_none()
    );

    let mut wrong_curve = ed_jwk.clone();
    wrong_curve["crv"] = json!("P-256");
    assert!(decoding_key_from_public_jwk(&wrong_curve, jsonwebtoken::Algorithm::EdDSA).is_none());

    let mut missing_x = ed_jwk.clone();
    missing_x
        .as_object_mut()
        .expect("fixture should be an object")
        .remove("x");
    assert!(decoding_key_from_public_jwk(&missing_x, jsonwebtoken::Algorithm::EdDSA).is_none());

    let ec_material = generate_key_material(jsonwebtoken::Algorithm::ES256)
        .expect("ES256 test key should generate");
    let ec_jwk = public_jwk_from_private_der(
        "ec-kid",
        jsonwebtoken::Algorithm::ES256,
        &ec_material.private_pkcs8_der,
    )
    .expect("ES256 public JWK should derive");
    assert!(decoding_key_from_public_jwk(&ec_jwk, jsonwebtoken::Algorithm::ES256).is_some());

    let mut wrong_ec_kty = ec_jwk.clone();
    wrong_ec_kty["kty"] = json!("OKP");
    assert!(decoding_key_from_public_jwk(&wrong_ec_kty, jsonwebtoken::Algorithm::ES256).is_none());

    let mut missing_ec_coordinate = ec_jwk.clone();
    missing_ec_coordinate
        .as_object_mut()
        .expect("fixture should be an object")
        .remove("y");
    assert!(
        decoding_key_from_public_jwk(&missing_ec_coordinate, jsonwebtoken::Algorithm::ES256)
            .is_none()
    );

    let rsa_material = generate_key_material(jsonwebtoken::Algorithm::RS256)
        .expect("RSA test key should generate");
    let rsa_jwk = public_jwk_from_private_der(
        "rsa-kid",
        jsonwebtoken::Algorithm::RS256,
        &rsa_material.private_pkcs8_der,
    )
    .expect("RSA public JWK should derive");
    assert!(decoding_key_from_public_jwk(&rsa_jwk, jsonwebtoken::Algorithm::RS256).is_some());
    assert!(decoding_key_from_public_jwk(&rsa_jwk, jsonwebtoken::Algorithm::PS256).is_none());

    let mut unsafe_rsa = rsa_jwk.clone();
    unsafe_rsa["n"] = json!("AQ");
    unsafe_rsa["e"] = json!("AQ");
    assert!(decoding_key_from_public_jwk(&unsafe_rsa, jsonwebtoken::Algorithm::RS256).is_none());

    assert!(
        decoding_key_from_public_jwk(
            &json!({"kty": "oct", "k": "not-a-public-key"}),
            jsonwebtoken::Algorithm::HS256,
        )
        .is_none()
    );
}

#[test]
fn external_signer_output_is_verified_against_exact_message() {
    let kid = "external-kid";
    let (private_key, public_jwk) = eddsa_fixture(kid);
    let signature = sign_input(&private_key, "expected");
    let external = ExternalSigningKey {
        key_ref: "kms://test/key".to_owned(),
        signer: Arc::new(crate::test_support::FixedExternalKeySigner(
            URL_SAFE_NO_PAD.decode(signature).unwrap(),
        )),
    };
    let backend = ExternalBackend {
        external: &external,
        kid,
        algorithm: jsonwebtoken::Algorithm::EdDSA,
        public_jwk: &public_jwk,
    };
    assert!(futures_executor::block_on(backend.sign(b"expected")).is_ok());
    assert!(matches!(
        futures_executor::block_on(backend.sign(b"tampered")),
        Err(SignError::SigningFailed)
    ));
}
