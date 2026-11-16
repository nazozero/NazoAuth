use super::*;
use bytes::Bytes;

#[test]
fn tenant_origin_and_token_method_policy_are_preserved() {
    let request = |origin: &'static str, method: &'static str| {
        http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/token")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
            .body(Bytes::new())
            .unwrap()
    };
    let policy = CorsPolicy::BrowserTokenManagement;
    let origins = ["https://app.tenant-a.example".to_owned()];
    let allowed = cors_preflight(
        policy,
        &request("https://app.tenant-a.example", "POST"),
        &origins,
    )
    .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.tenant-a.example"
    );
    assert_eq!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_MAX_AGE)
            .unwrap(),
        "0"
    );
    assert_eq!(
        cors_preflight(
            policy,
            &request("https://app.tenant-a.example", "POST"),
            &["https://app.tenant-b.example".to_owned()]
        )
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        cors_preflight(
            policy,
            &request("https://app.tenant-a.example", "GET"),
            &origins
        )
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn ordinary_responses_keep_exposed_headers_and_vary_without_granting_wrong_origin() {
    let request = http::Request::builder()
        .header(header::ORIGIN, "https://attacker.example")
        .body(Bytes::new())
        .unwrap();
    let mut response = empty_response(StatusCode::OK);
    apply_cors_headers(
        CorsPolicy::BrowserUserinfo,
        &request,
        &["https://app.example".to_owned()],
        response.headers_mut(),
    );
    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap(),
        "www-authenticate, dpop-nonce, retry-after"
    );
    assert!(response.headers().contains_key(header::VARY));
}
