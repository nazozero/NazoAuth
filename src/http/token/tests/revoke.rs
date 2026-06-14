use super::*;

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
