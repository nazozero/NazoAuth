use crate::support::{
    dpop, dpop_fixture, dpop_proof, fixture, signed_dpop_proof_with_overrides, token,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header};
use nazo_oauth_server::resource_server::{
    DpopProofVerifier, DpopProofVerifierConfig, DpopProofVerifierError, VerifiedAccessToken,
    VerifiedSenderConstraintProof, authorize_dpop_http_request,
};
use serde_json::json;

#[test]
fn dpop_verifier_rejects_replay_wrong_htu_htm_ath_iat_typ_alg_signature_and_nonce() {
    let dpop = dpop_fixture();
    let access_token = "access-token";
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let proof = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-replay",
        None,
        None,
    );

    verifier
        .verify(&proof, "GET", "https://api.example/orders", access_token)
        .unwrap();
    assert_eq!(
        verifier
            .verify(&proof, "GET", "https://api.example/orders", access_token)
            .unwrap_err(),
        DpopProofVerifierError::ReplayDetected
    );

    let wrong_ath = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-ath",
        None,
        Some("wrong-ath"),
    );
    assert_eq!(
        verifier
            .verify(
                &wrong_ath,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::AccessTokenHashMismatch
    );

    let method_uri = dpop_proof(
        &dpop,
        access_token,
        "POST",
        "https://api.example/orders",
        "proof-jti-method-uri",
        None,
        None,
    );
    assert_eq!(
        verifier
            .verify(
                &method_uri,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::MethodMismatch
    );
    assert_eq!(
        verifier
            .verify(
                &method_uri,
                "POST",
                "https://api.example/other",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::UriMismatch
    );

    let strict_time = DpopProofVerifier::new(DpopProofVerifierConfig {
        clock_skew_seconds: 0,
        max_age_seconds: 1,
        ..DpopProofVerifierConfig::default()
    });
    assert_eq!(
        strict_time
            .verify(
                &signed_dpop_proof_with_overrides(
                    &dpop,
                    access_token,
                    json!({"iat": Utc::now().timestamp() - 10, "jti": "expired-jti"}),
                    None,
                ),
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap_err(),
        DpopProofVerifierError::Expired
    );
    assert_eq!(
        strict_time
            .verify(
                &signed_dpop_proof_with_overrides(
                    &dpop,
                    access_token,
                    json!({"iat": Utc::now().timestamp() + 10, "jti": "future-jti"}),
                    None,
                ),
                "GET",
                "https://api.example/orders",
                access_token,
            )
            .unwrap_err(),
        DpopProofVerifierError::NotYetValid
    );

    let mut wrong_type_header = Header::new(Algorithm::RS256);
    wrong_type_header.typ = Some("JWT".to_owned());
    wrong_type_header.jwk = Some(dpop.public_jwk.clone());
    let wrong_type = signed_dpop_proof_with_overrides(
        &dpop,
        access_token,
        json!({"jti": "wrong-type"}),
        Some(wrong_type_header),
    );
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

    let mut tampered = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "invalid-signature",
        None,
        None,
    );
    tampered.push('x');
    assert_eq!(
        verifier
            .verify(&tampered, "GET", "https://api.example/orders", access_token)
            .unwrap_err(),
        DpopProofVerifierError::InvalidSignature
    );

    let nonce_proof = dpop_proof(
        &dpop,
        access_token,
        "GET",
        "https://api.example/orders",
        "proof-jti-nonce",
        Some("nonce-1"),
        None,
    );
    let nonce_required = DpopProofVerifier::new(DpopProofVerifierConfig {
        required_nonce: Some("nonce-2".to_owned()),
        ..DpopProofVerifierConfig::default()
    });
    assert_eq!(
        nonce_required
            .verify(
                &nonce_proof,
                "GET",
                "https://api.example/orders",
                access_token
            )
            .unwrap_err(),
        DpopProofVerifierError::NonceMismatch
    );
}

#[test]
fn dpop_http_authorizer_binds_proof_to_access_token_and_request() {
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
