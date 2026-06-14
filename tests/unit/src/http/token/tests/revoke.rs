use super::*;

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[actix_web::test]
async fn revocation_success_response_is_empty_and_not_cacheable() {
    let response = empty_response_no_store(StatusCode::OK);

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    assert!(body.is_empty());
}

#[test]
fn revocation_conflicting_client_auth_error_is_exact_oauth_invalid_request() {
    let response = token_management_oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "同一请求不能同时使用多种客户端认证方式.",
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}
