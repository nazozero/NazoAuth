use actix_web::http::{StatusCode, header};

use super::*;

#[actix_web::test]
async fn token_error_preserves_cache_and_challenge_contract() {
    let response = oauth_token_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "Client authentication failed.",
        true,
    );
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Basic realm="nazo-oauth""#
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[test]
fn non_ascii_protocol_description_is_replaced() {
    assert_eq!(oauth_error_description("失败"), "Request failed.");
}

#[actix_web::test]
async fn semantic_token_error_preserves_ascii_body_and_basic_challenge() {
    use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;

    let response = oauth_endpoint_error_response(OAuthEndpointError::token(
        http::StatusCode::UNAUTHORIZED,
        "invalid_client",
        "认证失败",
        true,
    ));
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Basic realm="nazo-oauth""#
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    assert_eq!(
        &body[..],
        br#"{"error":"invalid_client","error_description":"Request failed."}"#
    );
}

#[test]
fn semantic_json_bearer_and_disabled_keep_their_distinct_header_contracts() {
    use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;

    let json = oauth_endpoint_error_response(OAuthEndpointError::json(
        http::StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "Unavailable.",
    ));
    assert!(json.headers().get(header::CACHE_CONTROL).is_none());
    assert!(json.headers().get(header::WWW_AUTHENTICATE).is_none());
    let bearer = oauth_endpoint_error_response(OAuthEndpointError::bearer(
        http::StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Invalid token.",
    ));
    assert!(bearer.headers().get(header::CACHE_CONTROL).is_none());
    assert_eq!(
        bearer.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Invalid token.""#
    );
    let disabled = oauth_endpoint_error_response(OAuthEndpointError::Disabled);
    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
    assert!(disabled.headers().is_empty());
}

#[test]
fn semantic_pre_authorized_error_keeps_token_nonce_and_cache_policy() {
    use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;

    let response = oauth_endpoint_error_response(OAuthEndpointError::PreAuthorized(
        nazo_openid4vci::application::CredentialHttpError {
            status: 400,
            error: "use_dpop_nonce",
            description: "Nonce required.",
            dpop_nonce: Some("nonce-1".to_owned()),
        },
    ));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert_eq!(response.headers().get("dpop-nonce").unwrap(), "nonce-1");
}
