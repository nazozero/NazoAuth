use super::fixtures::*;
use super::*;
use crate::resource_server::dpop::dpop_jwk_decoding_key;
use jsonwebtoken::{Algorithm, Header};
use serde_json::json;

#[test]
fn dpop_proof_verifier_produces_verified_sender_context() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-1",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let proof = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            &access_token,
        )
        .unwrap();
    let header = dpop(&access_token);
    let verified =
        authorize_resource_request(&fixture.verifier, &[header.as_str()], None, &proof).unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt));
}

#[test]
fn dpop_http_authorizer_verifies_proof_and_inserts_extensions() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-http",
        None,
        None,
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let mut request = http::Request::builder()
        .method("GET")
        .uri("/orders")
        .header(http::header::AUTHORIZATION, dpop(&access_token))
        .header("DPoP", proof_jwt)
        .body(())
        .unwrap();

    let verified = authorize_dpop_http_request(
        &fixture.verifier,
        &dpop_verifier,
        &mut request,
        "https://api.example/orders",
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some(dpop_fixture.jkt.clone()));
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedSenderConstraintProof>()
            .unwrap()
            .dpop_jkt,
        Some(dpop_fixture.jkt)
    );
    assert!(request.extensions().get::<VerifiedAccessToken>().is_some());
}

#[test]
fn dpop_authorizer_rejects_invalid_proof_before_token_binding() {
    let fixture = fixture();
    let dpop_fixture = dpop_fixture();
    let access_token = token(&fixture, json!({"cnf": {"jkt": dpop_fixture.jkt}}), None);
    let proof_jwt = dpop_proof(
        &dpop_fixture,
        &access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-invalid",
        None,
        Some("wrong-ath"),
    );
    let dpop_verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let authorization = dpop(&access_token);

    let error = authorize_dpop_resource_request(
        &fixture.verifier,
        &dpop_verifier,
        &[authorization.as_str()],
        &proof_jwt,
        None,
        "GET",
        "https://api.example/orders",
    )
    .unwrap_err();

    assert_eq!(
        error,
        ResourceServerRequestError::InvalidDpopProof(
            DpopProofVerifierError::AccessTokenHashMismatch
        )
    );
}

#[test]
fn dpop_proof_verifier_rejects_replayed_jti() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-replay",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::ReplayDetected);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_ath() {
    let dpop = dpop_fixture();
    let proof_jwt = dpop_proof(
        &dpop,
        "access-token",
        "GET",
        "https://api.example/orders",
        "proof-jti-ath",
        None,
        Some("wrong-ath"),
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            "access-token",
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::AccessTokenHashMismatch);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_method_and_uri() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "POST",
        "https://api.example/orders",
        "proof-jti-method-uri",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let wrong_method = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();
    let wrong_uri = verifier
        .verify(
            &proof_jwt,
            "POST",
            "https://api.example/other",
            access_token,
        )
        .unwrap_err();

    assert_eq!(wrong_method, DpopProofVerifierError::MethodMismatch);
    assert_eq!(wrong_uri, DpopProofVerifierError::UriMismatch);
}

#[test]
fn dpop_proof_verifier_rejects_empty_jti() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        " ",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::MissingJti);
}

#[test]
fn dpop_proof_verifier_rejects_expired_and_future_iat() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let expired = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"iat": Utc::now().timestamp() - 10, "jti": "expired-jti"}),
        None,
    );
    let future = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"iat": Utc::now().timestamp() + 10, "jti": "future-jti"}),
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        clock_skew_seconds: 0,
        max_age_seconds: 1,
        ..DpopProofVerifierConfig::default()
    });

    let expired_error = verifier
        .verify(&expired, "GET", "https://api.example/orders", access_token)
        .unwrap_err();
    let future_error = verifier
        .verify(&future, "GET", "https://api.example/orders", access_token)
        .unwrap_err();

    assert_eq!(expired_error, DpopProofVerifierError::Expired);
    assert_eq!(future_error, DpopProofVerifierError::NotYetValid);
}

#[test]
fn dpop_proof_verifier_rejects_wrong_type_and_unsupported_algorithm() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let wrong_type = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"jti": "wrong-type"}),
        Some({
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("JWT".to_owned());
            header.jwk = Some(dpop.public_jwk.clone());
            header
        }),
    );
    let unsupported_alg = DpopProofVerifier::new(DpopProofVerifierConfig {
        allowed_algs: vec![Algorithm::PS256],
        ..DpopProofVerifierConfig::default()
    });
    let valid_rs256 = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "unsupported-alg",
        None,
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    assert_eq!(
        verifier
            .verify(
                &wrong_type,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::WrongType
    );
    assert_eq!(
        unsupported_alg
            .verify(
                &valid_rs256,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::UnsupportedAlgorithm
    );
}

#[test]
fn dpop_proof_verifier_rejects_missing_or_private_header_jwk() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let missing_jwk = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"jti": "missing-jwk"}),
        Some({
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some("dpop+jwt".to_owned());
            header
        }),
    );
    let mut private_jwk = serde_json::to_value(&dpop.public_jwk).unwrap();
    private_jwk["d"] = json!("private-material");

    assert_eq!(
        DpopProofVerifier::new(DpopProofVerifierConfig::default())
            .verify(
                &missing_jwk,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::MissingPublicJwk
    );
    assert!(dpop_jwk_decoding_key(&private_jwk, Algorithm::RS256).is_none());
}

#[test]
fn dpop_proof_verifier_rejects_invalid_signature() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let mut proof = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "invalid-signature",
        None,
        None,
    );
    proof.push('x');
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());

    let error = verifier
        .verify(&proof, "GET", "https://api.example/orders", access_token)
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::InvalidSignature);
}

#[test]
fn dpop_proof_verifier_enforces_required_nonce() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let proof_jwt = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-nonce",
        Some("nonce-1"),
        None,
    );
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-1".to_owned()),
        ..DpopProofVerifierConfig::default()
    });

    verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap();

    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-2".to_owned()),
        ..DpopProofVerifierConfig::default()
    });
    let error = verifier
        .verify(
            &proof_jwt,
            "GET",
            "https://api.example/orders",
            access_token,
        )
        .unwrap_err();

    assert_eq!(error, DpopProofVerifierError::NonceMismatch);
}

fn signed_dpop_proof_with_overrides(
    fixture: &DpopFixture,
    access_token: &str,
    overrides: serde_json::Value,
    header: Option<Header>,
) -> String {
    let mut claims = json!({
        "htu": "https://api.example/orders",
        "htm": "GET",
        "iat": Utc::now().timestamp(),
        "jti": "proof-jti-overrides",
        "ath": access_token_hash(access_token),
    });
    merge_object(&mut claims, overrides);
    let header = header.unwrap_or_else(|| {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("dpop+jwt".to_owned());
        header.jwk = Some(fixture.public_jwk.clone());
        header
    });
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}
