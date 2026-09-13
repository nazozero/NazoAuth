use super::*;

#[test]
fn baseline_policy_is_explicitly_default_deny() {
    let policy = ClientSecurityPolicy::default();

    assert_eq!(policy.assurance, ClientAssuranceLevel::Baseline);
    assert!(!policy.require_pushed_authorization_requests);
    assert!(!policy.require_signed_authorization_request);
    assert!(!policy.require_signed_authorization_response);
    assert!(!policy.require_signed_introspection_response);
    assert!(!policy.session_management);
    assert!(!policy.allow_cross_device_flows);
    assert!(!policy.allow_confidential_oidc_without_pkce);
    assert_eq!(policy.validate(), Ok(()));
}

#[test]
fn independent_message_signing_requirements_can_coexist() {
    let policy: ClientSecurityPolicy = serde_json::from_value(serde_json::json!({
        "version": 1,
        "assurance": "fapi2",
        "require_signed_authorization_request": true,
        "require_signed_authorization_response": true,
        "require_signed_introspection_response": true,
        "session_management": false,
        "allow_cross_device_flows": false
    }))
    .expect("composable policy should deserialize");

    assert!(policy.requires_fapi2_security());
    assert!(policy.require_signed_authorization_request);
    assert!(policy.require_signed_authorization_response);
    assert!(policy.require_signed_introspection_response);
    assert_eq!(policy.validate(), Ok(()));
}

#[test]
fn unknown_policy_version_fails_closed() {
    let policy = ClientSecurityPolicy {
        version: 2,
        ..ClientSecurityPolicy::default()
    };

    assert_eq!(
        policy.validate(),
        Err("unsupported client security policy version")
    );
}

#[test]
fn pushed_requests_are_independent_of_fapi_client_authentication() {
    let policy: ClientSecurityPolicy = serde_json::from_value(serde_json::json!({
        "version": 1,
        "require_pushed_authorization_requests": true
    }))
    .expect("PAR can be required for an attested wallet client");
    assert!(policy.require_pushed_authorization_requests);
    assert!(!policy.requires_fapi2_security());
    assert!(!policy.require_signed_authorization_request);
    assert_eq!(policy.validate(), Ok(()));

    let previous: ClientSecurityPolicy = serde_json::from_value(serde_json::json!({"version": 1}))
        .expect("existing policy remains readable");
    assert!(!previous.require_pushed_authorization_requests);
}
