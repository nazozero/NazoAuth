use super::{ClientPresentationError, active_client_presentation, append_query};
use nazo_auth::ClientPresentationMetadata;

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

#[test]
fn inactive_client_is_not_found_and_active_client_exposes_only_display_metadata() {
    let metadata = ClientPresentationMetadata {
        logo_uri: Some("https://client.example/logo.svg".to_owned()),
        policy_uri: Some("https://client.example/privacy".to_owned()),
        tos_uri: Some("https://client.example/terms".to_owned()),
    };
    assert_eq!(
        active_client_presentation(false, "Presentation Client", &metadata),
        Err(ClientPresentationError::NotFound)
    );
    let active = active_client_presentation(true, "Presentation Client", &metadata).unwrap();
    assert_eq!(active.client_name, "Presentation Client");
    assert_eq!(
        active.logo_uri.as_deref(),
        Some("https://client.example/logo.svg")
    );
    assert_eq!(
        active.policy_uri.as_deref(),
        Some("https://client.example/privacy")
    );
    assert_eq!(
        active.tos_uri.as_deref(),
        Some("https://client.example/terms")
    );
}
