use super::*;
use crate::support::OAuthJsonErrorFields;

#[test]
fn profile_text_trims_blank_values_and_enforces_byte_limit() {
    assert_eq!(profile_text(None, 8, "display_name").unwrap(), None);
    assert_eq!(
        profile_text(Some("   \t ".to_owned()), 8, "display_name").unwrap(),
        None
    );
    assert_eq!(
        profile_text(Some("  Alice  ".to_owned()), 8, "display_name").unwrap(),
        Some("Alice".to_owned())
    );

    let response = profile_text(Some("abcdefghi".to_owned()), 8, "display_name").unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_oauth_error(&response, "invalid_request");
}

#[test]
fn normalize_profile_url_accepts_only_absolute_http_urls_without_fallback() {
    assert_eq!(
        normalize_profile_url(
            Some(" https://profile.example/u/alice ".to_owned()),
            "profile_url"
        )
        .unwrap(),
        Some("https://profile.example/u/alice".to_owned())
    );
    assert_eq!(
        normalize_profile_url(Some("http://localhost/profile".to_owned()), "profile_url").unwrap(),
        Some("http://localhost/profile".to_owned())
    );
    assert_eq!(normalize_profile_url(None, "profile_url").unwrap(), None);
    assert_eq!(
        normalize_profile_url(Some("   ".to_owned()), "profile_url").unwrap(),
        None
    );

    for invalid in [
        "client.example/profile",
        "/relative/profile",
        "javascript:alert(1)",
        "mailto:user@example.com",
        "urn:example:profile",
    ] {
        let response = normalize_profile_url(Some(invalid.to_owned()), "profile_url").unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_oauth_error(&response, "invalid_request");
    }
}

fn assert_oauth_error(response: &HttpResponse, expected: &str) {
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some(expected)
    );
}
