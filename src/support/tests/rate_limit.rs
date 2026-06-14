use super::*;

#[test]
fn rate_limit_key_does_not_store_raw_peer_identity() {
    let key = rate_limit_key(RateLimitPolicy::Auth, "203.0.113.9");

    assert!(key.starts_with("oauth:rate:auth:"));
    assert!(!key.contains("203.0.113.9"));
    assert_ne!(key, "oauth:rate:auth:203.0.113.9");
}
