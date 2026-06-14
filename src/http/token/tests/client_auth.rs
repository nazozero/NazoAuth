use super::*;

fn client_credentials(method: &str) -> ClientCredentials {
    ClientCredentials {
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion: None,
        method: method.to_owned(),
    }
}

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
fn public_revocation_client_accepts_only_none_without_secret_material() {
    let credentials = client_credentials("none");
    assert!(
        revocation_public_client_allows_credentials(&credentials),
        "public revocation may identify the client without authenticating as confidential"
    );

    let mut with_secret = client_credentials("none");
    with_secret.client_secret = Some("secret".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_secret),
        "public revocation must not accept confidential-client secret material"
    );

    let mut with_assertion = client_credentials("none");
    with_assertion.client_assertion = Some("jwt".to_owned());
    assert!(
        !revocation_public_client_allows_credentials(&with_assertion),
        "public revocation must not accept private_key_jwt assertion material"
    );

    let basic = client_credentials("client_secret_basic");
    assert!(
        !revocation_public_client_allows_credentials(&basic),
        "public revocation must not upgrade itself into a confidential auth method"
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

#[test]
fn client_assertion_replay_maps_to_invalid_client_not_server_error() {
    let error = token_management_client_assertion_error(ClientAssertionError::ReplayDetected);
    let response = token_management_client_auth_error(error, false);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_client")
    );
}

#[test]
fn client_assertion_store_failure_maps_to_server_error_without_challenge() {
    let error = token_management_client_assertion_error(ClientAssertionError::StoreUnavailable);
    let response = token_management_client_auth_error(error, true);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}
