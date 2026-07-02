use super::*;

#[test]
fn oidc_session_state_is_origin_client_and_salt_bound() {
    let salt = random_urlsafe_token();
    let state = oidc_session_state("client-1", "https://client.example", "opbs-1", &salt);

    assert!(state.ends_with(&format!(".{salt}")));
    assert_eq!(
        state,
        oidc_session_state("client-1", "https://client.example", "opbs-1", &salt)
    );
    assert_ne!(
        state,
        oidc_session_state("client-2", "https://client.example", "opbs-1", &salt)
    );
    assert_ne!(
        state,
        oidc_session_state("client-1", "https://other.example", "opbs-1", &salt)
    );
}

#[test]
fn issue_oidc_session_state_uses_redirect_uri_origin() {
    let state = issue_oidc_session_state(
        "client-1",
        "https://client.example:8443/callback?code=unused",
        "opbs-1",
    )
    .expect("absolute redirect URI should produce a session_state");
    let (_, salt) = state.rsplit_once('.').expect("session_state contains salt");

    assert_eq!(
        state,
        oidc_session_state("client-1", "https://client.example:8443", "opbs-1", salt)
    );
    assert!(issue_oidc_session_state("client-1", "not-a-uri", "opbs-1").is_none());
}

#[test]
fn session_management_iframe_document_escapes_status_endpoint() {
    let html = session_management_iframe_document("https://issuer.example/check?x=1&y='z'");

    assert!(html.contains("https://issuer.example/check?x=1\\u0026y=\\'z\\'"));
    assert!(!html.contains("x=1&y='z'"));
    assert!(!html.contains("var statusEndpoint = '\n"));
    assert!(html.contains("new XMLHttpRequest()"));
    assert!(!html.contains("fetch("));
}
