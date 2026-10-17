use super::append_query;

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

#[test]
fn framework_boundary_transport_views_query_projection_semantics() {
    let query = vec![("state", "abc"), ("nonce", ""), ("scope", "openid profile")];
    assert_eq!(
        append_query(
            "https://issuer.example/authorize?client_id=client-1",
            &query
        ),
        "https://issuer.example/authorize?client_id=client-1&state=abc&scope=openid+profile"
    );
}
