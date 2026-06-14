use super::fixtures::*;
use super::*;
use serde_json::json;

#[test]
fn request_authorizer_rejects_query_access_tokens() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str()],
        Some("access_token=query-token"),
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_rejects_duplicate_authorization_headers() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let error = authorize_resource_request(
        &fixture.verifier,
        &[token.as_str(), token.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::InvalidRequest);
}

#[test]
fn request_authorizer_requires_verified_dpop_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None);
    let header = dpop(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: Some("jkt-1".to_owned()),
            mtls_x5t_s256: None,
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
}

#[test]
fn request_authorizer_requires_verified_mtls_binding_context() {
    let fixture = fixture();
    let token = token(&fixture, json!({"cnf": {"x5t#S256": "thumb-1"}}), None);
    let header = bearer(&token);
    let error = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof::default(),
    )
    .unwrap_err();

    assert_eq!(error, ResourceServerRequestError::MissingSenderConstraint);

    let verified = authorize_resource_request(
        &fixture.verifier,
        &[header.as_str()],
        None,
        &SenderConstraintProof {
            dpop_jkt: None,
            mtls_x5t_s256: Some("thumb-1".to_owned()),
        },
    )
    .unwrap();

    assert_eq!(verified.cnf.unwrap().x5t_s256, Some("thumb-1".to_owned()));
}
