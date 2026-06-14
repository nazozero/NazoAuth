use super::*;

#[test]
fn authorization_decision_is_explicit_allowlist() {
    assert!(matches!(
        parse_authorization_decision("approve"),
        Some(AuthorizationDecision::Approve)
    ));
    assert!(matches!(
        parse_authorization_decision("deny"),
        Some(AuthorizationDecision::Deny)
    ));
    assert!(parse_authorization_decision("anything-else").is_none());
    assert!(parse_authorization_decision(" approve ").is_none());
}

#[test]
fn missing_or_malformed_consent_payload_is_rejected() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":1}"#.to_owned())).is_none());
}
