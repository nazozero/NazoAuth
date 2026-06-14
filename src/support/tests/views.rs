use super::*;

#[test]
fn cross_site_fetch_detection_is_case_insensitive_and_fail_closed() {
    let mut headers = HeaderMap::new();
    let sec_fetch_site = header::HeaderName::from_static("sec-fetch-site");
    assert!(!is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site.clone(),
        HeaderValue::from_static("  Cross-Site  "),
    );
    assert!(is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site.clone(),
        HeaderValue::from_static("same-origin"),
    );
    assert!(!is_cross_site_fetch(&headers));

    headers.insert(
        sec_fetch_site,
        HeaderValue::from_bytes(b"\xff").expect("raw header value can contain non-UTF8 bytes"),
    );
    assert!(
        !is_cross_site_fetch(&headers),
        "malformed Fetch Metadata headers must not be treated as cross-site proof"
    );
}

#[test]
fn pagination_rejects_non_positive_values_and_caps_page_size() {
    let empty = HashMap::new();
    assert_eq!(pagination(&empty), (1, 20, 0));

    let mut query = HashMap::new();
    query.insert("page".to_owned(), "3".to_owned());
    query.insert("page_size".to_owned(), "50".to_owned());
    assert_eq!(pagination(&query), (3, 50, 100));

    query.insert("page".to_owned(), "0".to_owned());
    query.insert("page_size".to_owned(), "1000".to_owned());
    assert_eq!(pagination(&query), (1, 100, 0));

    query.insert("page".to_owned(), "-2".to_owned());
    query.insert("page_size".to_owned(), "-1".to_owned());
    assert_eq!(pagination(&query), (1, 20, 0));
}

#[test]
fn append_query_preserves_invalid_base_and_skips_empty_values() {
    assert_eq!(append_query("not a url", &[("state", "abc")]), "not a url");

    let url = append_query(
        "https://issuer.example/authorize?client_id=client-1",
        &[("state", "abc"), ("nonce", ""), ("scope", "openid profile")],
    );

    assert!(url.starts_with("https://issuer.example/authorize?"));
    assert!(url.contains("client_id=client-1"));
    assert!(url.contains("state=abc"));
    assert!(url.contains("scope=openid+profile"));
    assert!(
        !url.contains("nonce="),
        "empty query values must not be serialized"
    );
}
