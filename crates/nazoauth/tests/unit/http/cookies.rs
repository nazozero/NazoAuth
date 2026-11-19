use bytes::Bytes;
use http::{StatusCode, header};

use super::*;

#[test]
fn cookies_preserve_exact_security_attributes() {
    let cookie = make_cookie("sid", "value", true, 60, true);
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(60)));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));

    let cookie = clear_cookie("sid", true);
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(0)));
    assert_eq!(
        cookie.expires_datetime(),
        Some(cookie::time::OffsetDateTime::UNIX_EPOCH)
    );
}

#[test]
fn cookie_max_age_saturates_at_i64_max() {
    assert_eq!(
        make_cookie("sid", "value", true, u64::MAX, true).max_age(),
        Some(CookieDuration::seconds(i64::MAX))
    );
}

#[test]
fn cookie_headers_and_lookup_preserve_values() {
    let request = http::Request::builder()
        .header(
            header::COOKIE,
            (Cookie::new("sid", "session-value")).to_string(),
        )
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        cookie_value(&request, "sid").as_deref(),
        Some("session-value")
    );

    let response = with_cookie_headers(
        crate::http::empty_response(StatusCode::OK),
        &[make_cookie("sid", "session-value", true, 60, true)],
    );
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        1
    );
}

#[test]
fn cookie_lookup_decodes_values_and_keeps_first_match_across_headers() {
    let request = http::Request::builder()
        .header(header::COOKIE, "invalid; sid=first%2Fvalue")
        .header(header::COOKIE, "sid=second; csrf=token")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        cookie_value(&request, "sid").as_deref(),
        Some("first/value")
    );
    let mut request = request;
    request.headers_mut().append(
        header::COOKIE,
        HeaderValue::from_bytes(b"sid=\xff").unwrap(),
    );
    assert!(cookie_value(&request, "sid").is_none());
}
