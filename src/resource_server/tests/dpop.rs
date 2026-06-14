use super::fixtures::*;
use super::*;
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
