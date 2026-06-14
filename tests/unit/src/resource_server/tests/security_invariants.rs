use super::fixtures::*;
use super::*;
use serde_json::json;

fn verifier_with_confirmation(
    fixture: &Fixture,
    confirmation: ConfirmationPolicy,
) -> ResourceServerVerifier {
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.required_scopes = vec!["read".to_owned()];
    config.confirmation = confirmation;
    ResourceServerVerifier::new(config).expect("confirmation test config should be valid")
}

#[test]
fn verifier_enforces_exact_mtls_thumbprint_binding() {
    let fixture = fixture();
    let verifier = verifier_with_confirmation(
        &fixture,
        ConfirmationPolicy::RequireMtlsThumbprint("thumb-1".to_owned()),
    );

    let verified = verifier
        .verify(&token(
            &fixture,
            json!({"cnf": {"x5t#S256": "thumb-1"}}),
            None,
        ))
        .expect("matching mTLS thumbprint should satisfy sender constraint policy");
    assert_eq!(verified.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));

    let missing = verifier
        .verify(&token(&fixture, json!({}), None))
        .expect_err("missing mTLS cnf must fail closed");
    assert_eq!(missing, ResourceServerVerifierError::MissingSenderConstraint);

    let mismatch = verifier
        .verify(&token(
            &fixture,
            json!({"cnf": {"x5t#S256": "thumb-2"}}),
            None,
        ))
        .expect_err("wrong mTLS thumbprint must not authorize the token");
    assert_eq!(mismatch, ResourceServerVerifierError::MtlsBindingMismatch);
}

#[test]
fn verifier_require_any_sender_constraint_accepts_dpop_or_mtls_but_not_empty_cnf() {
    let fixture = fixture();
    let verifier = verifier_with_confirmation(&fixture, ConfirmationPolicy::RequireAnySenderConstraint);

    let dpop_bound = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None))
        .expect("DPoP-bound token should satisfy any sender constraint policy");
    assert_eq!(dpop_bound.cnf.unwrap().jkt, Some("jkt-1".to_owned()));

    let mtls_bound = verifier
        .verify(&token(
            &fixture,
            json!({"cnf": {"x5t#S256": "thumb-1"}}),
            None,
        ))
        .expect("mTLS-bound token should satisfy any sender constraint policy");
    assert_eq!(mtls_bound.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));

    for claims in [json!({}), json!({"cnf": {}})] {
        let error = verifier
            .verify(&token(&fixture, claims, None))
            .expect_err("tokens without concrete cnf binding must fail closed");
        assert_eq!(error, ResourceServerVerifierError::MissingSenderConstraint);
    }
}

#[test]
fn request_authorizer_rejects_unbound_token_presented_as_dpop() {
    let fixture = fixture();
    let token_value = token(&fixture, json!({}), None);
    let header = dpop(&token_value);

    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .expect_err("DPoP authorization scheme requires a sender-constrained token");

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);
}

#[test]
fn request_authorizer_rejects_wrong_verified_sender_constraint_material() {
    let fixture = fixture();
    let dpop_token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
    let dpop_header = dpop(&dpop_token);

    let dpop_error = authorize_resource_request(
        &fixture.verifier,
        &[dpop_header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: Some("jkt-2".to_owned()),
            mtls_x5t_s256: None,
        },
    )
    .expect_err("the verifier must reject a different verified DPoP key");
    assert_eq!(dpop_error, ResourceServerRequestError::DpopBindingMismatch);

    let mtls_token = token(&fixture, json!({"cnf": {"x5t#S256": "thumb-1"}}), None);
    let bearer_header = bearer(&mtls_token);
    let mtls_error = authorize_resource_request(
        &fixture.verifier,
        &[bearer_header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: None,
            mtls_x5t_s256: Some("thumb-2".to_owned()),
        },
    )
    .expect_err("the verifier must reject a different verified mTLS certificate");
    assert_eq!(mtls_error, ResourceServerRequestError::MtlsBindingMismatch);
}
