use bytes::Bytes;
use cookie::Cookie;
use http::{StatusCode, header};
use serde_json::Value;

use super::*;

#[test]
fn csrf_validation_is_required_only_for_existing_sessions() {
    let anonymous = http::Request::builder().body(Bytes::new()).unwrap();
    assert!(has_valid_csrf_token_for_cookies(
        &anonymous, None, "session", "csrf"
    ));

    let matching_header = http::Request::builder()
        .header(
            header::COOKIE,
            (Cookie::new("session", "sid-1")).to_string(),
        )
        .header(header::COOKIE, (Cookie::new("csrf", "csrf-1")).to_string())
        .header("x-csrf-token", " csrf-1 ")
        .body(Bytes::new())
        .unwrap();
    assert!(has_valid_csrf_token_for_cookies(
        &matching_header,
        None,
        "session",
        "csrf"
    ));

    let matching_fallback = http::Request::builder()
        .header(
            header::COOKIE,
            (Cookie::new("session", "sid-1")).to_string(),
        )
        .header(header::COOKIE, (Cookie::new("csrf", "csrf-1")).to_string())
        .body(Bytes::new())
        .unwrap();
    assert!(has_valid_csrf_token_for_cookies(
        &matching_fallback,
        Some("csrf-1"),
        "session",
        "csrf"
    ));

    let missing_csrf = http::Request::builder()
        .header(
            header::COOKIE,
            (Cookie::new("session", "sid-1")).to_string(),
        )
        .body(Bytes::new())
        .unwrap();
    assert!(!has_valid_csrf_token_for_cookies(
        &missing_csrf,
        Some("csrf-1"),
        "session",
        "csrf"
    ));

    let mismatched = http::Request::builder()
        .header(
            header::COOKIE,
            (Cookie::new("session", "sid-1")).to_string(),
        )
        .header(header::COOKIE, (Cookie::new("csrf", "csrf-1")).to_string())
        .header("x-csrf-token", "attacker-token")
        .body(Bytes::new())
        .unwrap();
    assert!(!has_valid_csrf_token_for_cookies(
        &mismatched,
        None,
        "session",
        "csrf"
    ));
}

#[test]
fn token_comparison_matches_only_equal_bytes() {
    assert!(constant_time_eq(b"csrf-token", b"csrf-token"));
    assert!(!constant_time_eq(b"csrf-token", b"csrf-tokee"));
    assert!(!constant_time_eq(b"csrf-token", b"short"));
}

#[test]
fn csrf_error_preserves_status_body_and_cache_headers() {
    let response = csrf_error();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert!(response.headers().get(header::PRAGMA).is_none());
    let body = response.into_body();
    let body: Value = serde_json::from_slice(&body).expect("CSRF error must be JSON");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
}
