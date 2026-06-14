use super::*;
use crate::support::OAuthJsonErrorFields;

#[test]
fn rate_limit_key_does_not_store_raw_peer_identity() {
    let key = rate_limit_key(RateLimitPolicy::Auth, "203.0.113.9");

    assert!(key.starts_with("oauth:rate:auth:"));
    assert!(!key.contains("203.0.113.9"));
    assert_ne!(key, "oauth:rate:auth:203.0.113.9");
}

#[test]
fn rate_limit_keys_are_isolated_by_policy() {
    let subject = "203.0.113.9";

    let auth = rate_limit_key(RateLimitPolicy::Auth, subject);
    let token = rate_limit_key(RateLimitPolicy::Token, subject);
    let token_management = rate_limit_key(RateLimitPolicy::TokenManagement, subject);

    assert!(auth.starts_with("oauth:rate:auth:"));
    assert!(token.starts_with("oauth:rate:token:"));
    assert!(token_management.starts_with("oauth:rate:token_management:"));
    assert_ne!(auth, token);
    assert_ne!(auth, token_management);
    assert_ne!(token, token_management);
}

#[test]
fn rate_limited_response_is_exact_oauth_retryable_error() {
    let response = rate_limited_response(17);

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
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("temporarily_unavailable")
    );
}
