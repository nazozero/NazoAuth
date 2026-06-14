use super::fixtures::*;
use super::*;
use jsonwebtoken::{Algorithm, Header};
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
fn rejects_wrong_audience() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"aud": "resource://other"}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::AudienceMismatch);
}

#[test]
fn rejects_missing_required_scope() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"scope": "write"}), None))
        .unwrap_err();

    assert_eq!(
        error,
        ResourceServerVerifierError::MissingScope("read".to_owned())
    );
}

#[test]
fn rejects_id_token_typ() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    header.kid = Some("test-rs256".to_owned());
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({}), Some(header)))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::WrongTokenType);
}

#[test]
fn enforces_dpop_jkt_binding() {
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
}

#[test]
fn rejects_dpop_jkt_mismatch() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let error = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-2"}}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::DpopBindingMismatch);
}
