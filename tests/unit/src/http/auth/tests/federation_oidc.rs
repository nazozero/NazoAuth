use super::*;
use crate::settings::OidcFederationSettings;

fn provider() -> OidcFederationSettings {
    OidcFederationSettings {
        provider_id: "oidc".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/authorize".to_owned(),
        token_endpoint: "https://issuer.example/token".to_owned(),
        jwks_url: "https://issuer.example/jwks".to_owned(),
        client_id: "client-1".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_uri: "https://auth.example/federation/oidc/callback".to_owned(),
        scopes: "openid email".to_owned(),
    }
}

#[test]
fn oidc_authorization_url_includes_all_required_params() {
    let provider = provider();
    let location = oidc_authorization_url(&provider, "state-1", "nonce-1", "verifier-1");
    let url = url::Url::parse(&location).unwrap();
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://issuer.example/authorize")
    );
    assert_eq!(params.get("response_type").map(|v| v.as_ref()), Some("code"));
    assert_eq!(params.get("client_id").map(|v| v.as_ref()), Some("client-1"));
    assert_eq!(
        params.get("redirect_uri").map(|v| v.as_ref()),
        Some("https://auth.example/federation/oidc/callback")
    );
    assert_eq!(params.get("scope").map(|v| v.as_ref()), Some("openid email"));
    assert_eq!(params.get("state").map(|v| v.as_ref()), Some("state-1"));
    assert_eq!(params.get("nonce").map(|v| v.as_ref()), Some("nonce-1"));
    assert_eq!(
        params.get("code_challenge_method").map(|v| v.as_ref()),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(|v| v.as_ref()),
        Some(pkce_s256("verifier-1").as_str())
    );
}

#[test]
fn oidc_state_key_includes_blake3_hash() {
    let key = oidc_state_key("state-value");
    assert!(key.starts_with("oauth:federation:oidc:state:"));
    assert_eq!(key.len(), 28 + 64);
}

#[test]
fn oidc_state_key_is_deterministic() {
    assert_eq!(oidc_state_key("same"), oidc_state_key("same"));
    assert_ne!(oidc_state_key("one"), oidc_state_key("two"));
}

#[test]
fn audience_contains_matches_string() {
    assert!(audience_contains(&json!("client-1"), "client-1"));
}

#[test]
fn audience_contains_rejects_string_mismatch() {
    assert!(!audience_contains(&json!("other"), "client-1"));
}

#[test]
fn audience_contains_matches_array_element() {
    let aud = json!(["client-1", "client-2"]);
    assert!(audience_contains(&aud, "client-1"));
    assert!(audience_contains(&aud, "client-2"));
}

#[test]
fn audience_contains_rejects_array_without_match() {
    assert!(!audience_contains(&json!(["other-1", "other-2"]), "client-1"));
}

#[test]
fn audience_contains_returns_false_for_non_string_non_array() {
    assert!(!audience_contains(&json!(null), "client-1"));
    assert!(!audience_contains(&json!(42), "client-1"));
    assert!(!audience_contains(&json!({"key": "value"}), "client-1"));
}
