use nazo_oauth_server::rate_limit::TokenManagementRequestLimiter;
use std::sync::{Arc, Mutex};

use actix_web::{
    http::{StatusCode, header, header::HeaderValue},
    test::TestRequest,
};
use nazo_auth::{
    RequestRateLimitBucket, RequestRateLimitError, RequestRateLimitFuture, RequestRateLimitPort,
};
use nazo_http_actix::{ClientIpConfig, ClientIpHeaderMode};

use super::*;

#[derive(Clone)]
struct FakeRateLimiter {
    result: Result<u64, RequestRateLimitError>,
    calls: Arc<Mutex<Vec<(RequestRateLimitBucket, String, u64)>>>,
}

impl FakeRateLimiter {
    fn returning(result: Result<u64, RequestRateLimitError>) -> Self {
        Self {
            result,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl RequestRateLimitPort for FakeRateLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((bucket, subject.to_owned(), window_seconds));
            self.result
        })
    }
}

fn direct_client_ip() -> ClientIpConfig {
    ClientIpConfig::new(&[], ClientIpHeaderMode::None)
}

#[actix_web::test]
async fn rate_limited_response_is_exact_oauth_retryable_error() {
    let response = oauth_endpoint_error_response(
        nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::RateLimited {
            retry_after_seconds: 17,
        },
    );

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::RETRY_AFTER).unwrap(),
        HeaderValue::from_static("17")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("temporarily_unavailable")
    );
}

#[actix_web::test]
async fn authentication_limit_uses_semantic_bucket_subject_and_window() {
    let store = FakeRateLimiter::returning(Ok(2));
    let calls = store.calls.clone();
    let req = TestRequest::default()
        .peer_addr("203.0.113.77:12345".parse().unwrap())
        .to_http_request();

    enforce_auth_request_limit(
        &AuthRequestLimiter::new(Arc::new(store), 37, 2),
        &req,
        &direct_client_ip(),
    )
    .await
    .unwrap();

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::Authentication,
            "203.0.113.77".to_owned(),
            37,
        )]
    );
}

#[actix_web::test]
async fn authentication_limit_rejects_post_increment_count_above_threshold() {
    let store = FakeRateLimiter::returning(Ok(3));
    let req = TestRequest::default().to_http_request();

    let response = enforce_auth_request_limit(
        &AuthRequestLimiter::new(Arc::new(store), 41, 2),
        &req,
        &direct_client_ip(),
    )
    .await
    .expect_err("count above the fixed-window threshold must be limited");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::RETRY_AFTER).unwrap(),
        HeaderValue::from_static("41")
    );
}

#[actix_web::test]
async fn dependency_failure_fails_closed_without_backend_details() {
    let store = FakeRateLimiter::returning(Err(RequestRateLimitError));
    let req = TestRequest::default().to_http_request();

    let response = enforce_auth_request_limit(
        &AuthRequestLimiter::new(Arc::new(store), 60, 10),
        &req,
        &direct_client_ip(),
    )
    .await
    .expect_err("dependency failure must fail closed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        oauth_error_name(response).await.as_deref(),
        Some("server_error")
    );
}

#[actix_web::test]
async fn token_management_limiter_uses_distinct_bucket() {
    let store = FakeRateLimiter::returning(Ok(1));
    let calls = store.calls.clone();
    let limiter = TokenManagementRequestLimiter::new(Arc::new(store), 29, 4);
    let req = TestRequest::default()
        .peer_addr("198.51.100.9:443".parse().unwrap())
        .to_http_request();

    limiter
        .enforce(&client_ip_with_config(&req, &direct_client_ip()))
        .await
        .unwrap();

    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::TokenManagement,
            "198.51.100.9".to_owned(),
            29,
        )]
    );
}

async fn oauth_error_name(response: actix_web::HttpResponse) -> Option<String> {
    let bytes = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("OAuth response body should collect");
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("OAuth response body should be JSON");
    body.get("error")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}
