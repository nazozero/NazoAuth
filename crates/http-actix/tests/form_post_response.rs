use actix_web::{body::to_bytes, http::header};
use nazo_http_actix::form_post_authorization_response;

#[actix_web::test]
async fn form_post_response_escapes_values_and_sets_hardening_headers() {
    let response = form_post_authorization_response(
        "https://client.example/cb?existing=1&next=\"unsafe\"",
        &[
            ("code".to_owned(), "a&<\"'b".to_owned()),
            ("state".to_owned(), "state-value".to_owned()),
        ],
        Some("session-state"),
        "nonce-value",
    );

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get("Referrer-Policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(response.headers().get("X-Frame-Options").unwrap(), "DENY");
    let csp = response
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'nonce-nonce-value'"));
    assert!(csp.contains("frame-ancestors 'none'"));

    let body = String::from_utf8(to_bytes(response.into_body()).await.unwrap().to_vec()).unwrap();
    assert!(body.contains("name=\"code\" value=\"a&amp;&lt;&quot;&#x27;b\""));
    assert!(body.contains("name=\"session_state\" value=\"session-state\""));
    assert!(!body.contains("a&<\"'b"));
}

#[actix_web::test]
async fn form_post_response_does_not_put_protocol_values_in_the_action_uri() {
    let response = form_post_authorization_response(
        "https://client.example/callback",
        &[("error".to_owned(), "access_denied".to_owned())],
        None,
        "nonce",
    );
    let body = String::from_utf8(to_bytes(response.into_body()).await.unwrap().to_vec()).unwrap();
    assert!(body.contains("action=\"https://client.example/callback\""));
    assert!(!body.contains("callback?error="));
}

#[actix_web::test]
async fn form_post_csp_serializes_ipv6_redirect_origin_safely() {
    let response = form_post_authorization_response(
        "https://[2001:db8::1]:8443/callback",
        &[("code".to_owned(), "code-value".to_owned())],
        None,
        "nonce",
    );
    assert!(
        response
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("form-action https://[2001:db8::1]:8443")
    );
}
