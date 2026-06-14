use crate::support::{bearer, dpop, fixture, token, token_with_exact_header};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header};
use nazo_oauth_server::resource_server::{
    ConfirmationPolicy, ResourceServerRequestError, ResourceServerVerifier,
    ResourceServerVerifierConfig, ResourceServerVerifierError, SenderConstraintProof,
    authorize_http_request, authorize_resource_request,
};
use serde_json::json;

#[test]
fn verifies_jwt_access_token_with_required_scope() {
    let fixture = fixture();
    let verified = fixture
        .verifier
        .verify(&token(&fixture, json!({}), None))
        .unwrap();

    assert_eq!(verified.issuer, "https://issuer.example");
    assert_eq!(verified.subject, "subject-1");
    assert_eq!(verified.audiences, vec!["resource://default"]);
    assert_eq!(verified.scopes, vec!["read", "write"]);
}

#[test]
fn rejects_token_with_missing_or_unknown_kid() {
    let fixture = fixture();
    let mut missing_kid = Header::new(Algorithm::RS256);
    missing_kid.typ = Some("at+jwt".to_owned());

    assert_eq!(
        fixture
            .verifier
            .verify(&token_with_exact_header(&fixture, json!({}), missing_kid))
            .unwrap_err(),
        ResourceServerVerifierError::MissingKeyId
    );

    let mut unknown_kid = Header::new(Algorithm::RS256);
    unknown_kid.typ = Some("at+jwt".to_owned());
    unknown_kid.kid = Some("unknown-kid".to_owned());

    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({}), Some(unknown_kid)))
            .unwrap_err(),
        ResourceServerVerifierError::UnknownKeyId
    );
}

#[test]
fn rejects_disallowed_algorithm_and_jwk_algorithm_mismatch() {
    let fixture = fixture();
    let mut disallowed_config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    disallowed_config.required_scopes = vec!["read".to_owned()];
    disallowed_config.allowed_algs = vec![Algorithm::PS256];
    let disallowed = ResourceServerVerifier::new(disallowed_config).unwrap();

    assert_eq!(
        disallowed
            .verify(&token(&fixture, json!({}), None))
            .unwrap_err(),
        ResourceServerVerifierError::UnsupportedAlgorithm
    );

    let mut jwks = fixture.jwks.clone();
    jwks["keys"][0]["alg"] = json!("PS256");
    let mut mismatch_config =
        ResourceServerVerifierConfig::new("https://issuer.example", "resource://default", jwks);
    mismatch_config.required_scopes = vec!["read".to_owned()];
    let mismatch = ResourceServerVerifier::new(mismatch_config).unwrap();

    assert_eq!(
        mismatch
            .verify(&token(&fixture, json!({}), None))
            .unwrap_err(),
        ResourceServerVerifierError::InvalidKey
    );
}

#[test]
fn rejects_wrong_issuer_audience_scope_token_use_and_time_bounds() {
    let fixture = fixture();
    let now = Utc::now().timestamp();

    assert_eq!(
        fixture
            .verifier
            .verify(&token(
                &fixture,
                json!({"iss": "https://attacker.example"}),
                None
            ))
            .unwrap_err(),
        ResourceServerVerifierError::IssuerMismatch
    );
    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({"aud": "resource://other"}), None))
            .unwrap_err(),
        ResourceServerVerifierError::AudienceMismatch
    );
    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({"scope": "write"}), None))
            .unwrap_err(),
        ResourceServerVerifierError::MissingScope("read".to_owned())
    );
    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({"token_use": "id"}), None))
            .unwrap_err(),
        ResourceServerVerifierError::WrongTokenType
    );
    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({"exp": now - 61}), None))
            .unwrap_err(),
        ResourceServerVerifierError::Expired
    );
    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({"nbf": now + 61}), None))
            .unwrap_err(),
        ResourceServerVerifierError::NotYetValid
    );
}

#[test]
fn rejects_id_token_typ_and_missing_trust_anchors() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    header.kid = Some("test-rs256".to_owned());

    assert_eq!(
        fixture
            .verifier
            .verify(&token(&fixture, json!({}), Some(header)))
            .unwrap_err(),
        ResourceServerVerifierError::WrongTokenType
    );
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig::new(
            "",
            "resource://default",
            json!({"keys": []})
        ))
        .unwrap_err(),
        ResourceServerVerifierError::MissingIssuer
    );
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig {
            audiences: Vec::new(),
            ..ResourceServerVerifierConfig::new(
                "https://issuer.example",
                "resource://default",
                json!({"keys": []})
            )
        })
        .unwrap_err(),
        ResourceServerVerifierError::MissingAudience
    );
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig::new(
            "https://issuer.example",
            "resource://default",
            json!({})
        ))
        .unwrap_err(),
        ResourceServerVerifierError::MissingJwks
    );
}

#[test]
fn enforces_sender_constraint_policies_and_presented_proof_binding() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let verified = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None))
        .unwrap();
    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
    assert_eq!(
        verifier
            .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-2"}}), None))
            .unwrap_err(),
        ResourceServerVerifierError::DpopBindingMismatch
    );

    let dpop_token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
    let dpop_header = dpop(&dpop_token);
    assert_eq!(
        authorize_resource_request(
            &fixture.verifier,
            &[dpop_header.as_str()],
            None,
            &SenderConstraintProof::default(),
        )
        .unwrap_err(),
        ResourceServerRequestError::MissingSenderConstraint
    );
    assert!(
        authorize_resource_request(
            &fixture.verifier,
            &[dpop_header.as_str()],
            None,
            &SenderConstraintProof {
                dpop_jkt: Some("jkt-1".to_owned()),
                mtls_x5t_s256: None,
            },
        )
        .is_ok()
    );
}

#[test]
fn resource_request_rejects_query_tokens_duplicates_and_non_utf8_headers() {
    let fixture = fixture();
    let access_token = bearer(&token(&fixture, json!({}), None));

    assert_eq!(
        authorize_resource_request(
            &fixture.verifier,
            &[access_token.as_str()],
            Some("access_token=query-token"),
            &SenderConstraintProof::default(),
        )
        .unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
    assert_eq!(
        authorize_resource_request(
            &fixture.verifier,
            &[access_token.as_str(), access_token.as_str()],
            None,
            &SenderConstraintProof::default(),
        )
        .unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );

    let mut request = http::Request::builder().uri("/orders").body(()).unwrap();
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
    );
    assert_eq!(
        authorize_http_request(&fixture.verifier, &mut request).unwrap_err(),
        ResourceServerRequestError::InvalidRequest
    );
}
