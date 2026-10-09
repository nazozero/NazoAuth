use super::*;

#[test]
fn refresh_token_scope_request_defaults_to_original_authorization() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(
        refresh_token_scopes(original.clone(), None).unwrap(),
        original
    );
    assert_eq!(
        refresh_token_scopes(original.clone(), Some("")).unwrap(),
        original
    );
    assert_eq!(
        refresh_token_scopes(original.clone(), Some("   ")).unwrap(),
        original
    );
}

#[test]
fn refresh_token_scope_request_may_narrow_original_authorization() {
    let original = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ];

    assert_eq!(
        refresh_token_scopes(original.clone(), Some("openid offline_access")).unwrap(),
        vec!["openid".to_owned(), "offline_access".to_owned()]
    );
    assert_eq!(
        refresh_token_scopes(original.clone(), Some("openid")).unwrap(),
        vec!["openid".to_owned()],
        "RFC 6749 allows the access-token scope to be narrower than the refresh-token authorization"
    );
}

#[test]
fn openid4vci_refresh_token_scope_may_narrow_to_credential_authorization() {
    let original = vec!["eu.europa.ec.eudi.pid.1".to_owned()];

    assert_eq!(
        refresh_token_scopes(original.clone(), Some("eu.europa.ec.eudi.pid.1")).unwrap(),
        original
    );
    assert!(
        refresh_token_scopes(
            original.clone(),
            Some("eu.europa.ec.eudi.pid.1 administrator")
        )
        .is_err(),
        "OpenID4VCI refresh must not expand the original scope grant"
    );
}

#[test]
fn attested_refresh_token_requires_the_original_client_instance_key() {
    assert!(client_attestation_refresh_binding_matches(
        "attest_jwt_client_auth",
        Some("original-instance-key"),
        Some("original-instance-key"),
    ));
    assert!(!client_attestation_refresh_binding_matches(
        "attest_jwt_client_auth",
        Some("original-instance-key"),
        Some("different-instance-key"),
    ));
    assert!(!client_attestation_refresh_binding_matches(
        "attest_jwt_client_auth",
        None,
        Some("original-instance-key"),
    ));
    assert!(!client_attestation_refresh_binding_matches(
        "attest_jwt_client_auth",
        Some("original-instance-key"),
        None,
    ));
    assert!(client_attestation_refresh_binding_matches(
        "private_key_jwt",
        None,
        None,
    ));
}

#[test]
fn refresh_token_scope_request_rejects_privilege_expansion() {
    let original = vec!["openid".to_owned(), "offline_access".to_owned()];

    for requested in ["email", "openid email", "offline_access admin"] {
        assert!(
            refresh_token_scopes(original.clone(), Some(requested)).is_err(),
            "refresh_token grant must reject scope expansion: {requested}"
        );
    }
}

#[test]
fn refresh_subject_preparation_hint_respects_effective_scope_shape() {
    for scope in [
        None,
        Some(""),
        Some("   "),
        Some("openid"),
        Some("profile openid"),
    ] {
        assert!(refresh_requests_oidc_subject(scope));
    }
    for scope in [Some("profile"), Some("offline_access"), Some("OPENID")] {
        assert!(!refresh_requests_oidc_subject(scope));
    }
}
