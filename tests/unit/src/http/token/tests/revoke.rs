use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use actix_web::test::TestRequest;

fn revocation_state() -> Data<AppState> {
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_revoke_test_invalid:nazo_revoke_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    })
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    (status, value)
}

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

async fn revoke_form(body: &'static [u8]) -> HttpResponse {
    revoke_after_rate_limit(revocation_state(), form_request(), Bytes::from_static(body)).await
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

#[actix_web::test]
async fn revocation_rejects_malformed_form_before_client_or_token_lookup() {
    let cases = [
        (
            revoke_after_rate_limit(
                revocation_state(),
                TestRequest::default()
                    .insert_header((header::CONTENT_TYPE, "application/json"))
                    .to_http_request(),
                Bytes::from_static(br#"{"token":"secret"}"#),
            )
            .await,
            "token management 请求必须使用 application/x-www-form-urlencoded.",
        ),
        (
            revoke_form(b"token=\xff").await,
            "token management 请求体必须使用 UTF-8 编码.",
        ),
        (
            revoke_form(b"token=token-1&token=token-2").await,
            "OAuth 参数不能重复.",
        ),
        (revoke_form(b"token=%20%20").await, "缺少 token."),
    ];

    for (response, expected_description) in cases {
        assert_eq!(oauth_error_code(&response), "invalid_request");
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "malformed revocation input is an invalid request, not a client-auth challenge"
        );
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.get("error"), Some(&json!("invalid_request")));
        assert_eq!(
            body.get("error_description"),
            Some(&json!("Request failed."))
        );
        assert_ne!(
            body.get("error_description"),
            Some(&json!(expected_description)),
            "non-ASCII internal validation reasons must not be reflected to token clients"
        );
        assert!(body.get("access_token").is_none());
        assert!(body.get("refresh_token").is_none());
    }
}

#[actix_web::test]
async fn revocation_rejects_conflicting_client_auth_without_token_state_lookup() {
    let response = revoke_after_rate_limit(
        revocation_state(),
        TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50LTE6c2VjcmV0"))
            .to_http_request(),
        Bytes::from_static(b"token=token-1&client_id=client-1"),
    )
    .await;

    assert_eq!(oauth_error_code(&response), "invalid_request");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_requires_client_authentication_before_token_state_lookup() {
    let response = revoke_after_rate_limit(
        revocation_state(),
        form_request(),
        Bytes::from_static(b"token=token-1"),
    )
    .await;

    assert_eq!(oauth_error_code(&response), "invalid_client");
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "revocation must not invent a Basic challenge unless the client attempted Basic auth"
    );
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}
