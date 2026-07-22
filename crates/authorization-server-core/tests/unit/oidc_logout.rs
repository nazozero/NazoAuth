use super::*;

#[test]
fn resolve_client_rejects_conflicting_hint_audience() {
    let hint = IdTokenHintClaims {
        sub: "subject".to_owned(),
        aud: Value::String("client-a".to_owned()),
        sid: None,
    };
    assert_eq!(
        resolve_logout_client_id(Some("client-b"), false, Some(&hint)),
        Err(LogoutPolicyError::ClientAudienceMismatch)
    );
}

#[test]
fn redirect_state_is_appended_without_replacing_registered_query() {
    let registered = vec!["https://client.example/logout?source=op".to_owned()];
    assert_eq!(
        validate_post_logout_redirect(
            Some("https://client.example/logout?source=op"),
            Some("logout-state"),
            Some(&registered),
        )
        .expect("registered redirect"),
        Some("https://client.example/logout?source=op&state=logout-state".to_owned())
    );
}
