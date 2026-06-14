use super::*;

#[test]
fn token_management_basic_client_auth_failure_has_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::InvalidClient, true);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Basic realm="nazo-oauth""#)
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
}

#[test]
fn token_management_non_basic_client_auth_failure_has_no_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::InvalidClient, false);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}

#[test]
fn token_management_store_failure_has_no_basic_challenge() {
    let response =
        token_management_client_auth_error(TokenManagementClientAuthError::StoreUnavailable, true);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}
