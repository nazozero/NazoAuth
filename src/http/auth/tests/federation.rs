use super::*;
use crate::settings::{OidcFederationSettings, SamlGatewaySettings};

#[test]
fn federation_token_accepts_only_urlsafe_values() {
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_").is_some());
    assert!(normalize_federation_token("short").is_none());
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789+/").is_none());
}

#[test]
fn oidc_authorization_url_binds_state_nonce_and_s256_pkce() {
    let provider = OidcFederationSettings {
        provider_id: "oidc".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/authorize".to_owned(),
        token_endpoint: "https://issuer.example/token".to_owned(),
        jwks_url: "https://issuer.example/jwks".to_owned(),
        client_id: "client-1".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_uri: "https://auth.example/federation/oidc/callback".to_owned(),
        scopes: "openid email".to_owned(),
    };

    let location = oidc_authorization_url(&provider, "state-1", "nonce-1", "verifier-1");
    let url = url::Url::parse(&location).unwrap();
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://issuer.example/authorize")
    );
    assert_eq!(
        params.get("response_type").map(|value| value.as_ref()),
        Some("code")
    );
    assert_eq!(
        params.get("state").map(|value| value.as_ref()),
        Some("state-1")
    );
    assert_eq!(
        params.get("nonce").map(|value| value.as_ref()),
        Some("nonce-1")
    );
    assert_eq!(
        params
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(|value| value.as_ref()),
        Some(pkce_s256("verifier-1").as_str())
    );
}

#[test]
fn saml_gateway_signature_is_bound_to_assertion_fields() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "subject",
        "user@example.com",
        now,
        now + 60,
    );
    let assertion = SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: "subject".to_owned(),
        email: "user@example.com".to_owned(),
        name: None,
        iat: now,
        exp: now + 60,
        signature,
    };
    assert!(valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "user@example.com"
    ));
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "other@example.com"
    ));
}

#[test]
fn saml_gateway_assertion_rejects_correctly_signed_overlong_ttl() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "subject",
        "user@example.com",
        now,
        now + 301,
    );
    let assertion = SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: "subject".to_owned(),
        email: "user@example.com".to_owned(),
        name: None,
        iat: now,
        exp: now + 301,
        signature,
    };

    assert!(!valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "user@example.com"
    ));
}
