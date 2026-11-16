use http::{HeaderMap, HeaderName, HeaderValue, header};

pub fn apply_security_headers(headers: &mut HeaderMap, is_check_session_iframe: bool) {
    if !is_check_session_iframe {
        insert_static_header(headers, header::X_FRAME_OPTIONS, "DENY");
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
        );
    } else {
        insert_static_header(
            headers,
            HeaderName::from_static("content-security-policy"),
            "base-uri 'none'; object-src 'none'",
        );
    }
    insert_static_header(
        headers,
        HeaderName::from_static("referrer-policy"),
        "no-referrer",
    );
    insert_static_header(
        headers,
        HeaderName::from_static("permissions-policy"),
        "interest-cohort=()",
    );
    // Browsers ignore HSTS received over plaintext HTTP, so emitting this at
    // the application boundary also covers deployments terminated by a
    // trusted TLS reverse proxy without affecting loopback development.
    insert_static_header(
        headers,
        HeaderName::from_static("strict-transport-security"),
        "max-age=31536000",
    );
    insert_static_header(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
}

fn insert_static_header(headers: &mut HeaderMap, name: HeaderName, value: &'static str) {
    if !headers.contains_key(&name) {
        headers.insert(name, HeaderValue::from_static(value));
    }
}
