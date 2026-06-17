use super::*;
use crate::settings::{OidcFederationSettings, SamlGatewaySettings};

#[test]
fn federation_token_accepts_only_urlsafe_values() {
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_").is_some());
    assert!(normalize_federation_token("short").is_none());
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789+/").is_none());
}

#[test]
fn federation_token_trims_transport_whitespace_but_preserves_length_and_charset_limits() {
    let min = "A".repeat(32);
    let max = "b".repeat(256);

    assert_eq!(
        normalize_federation_token(&format!(" \t{min}\n")).as_deref(),
        Some(min.as_str())
    );
    assert_eq!(
        normalize_federation_token(&max).as_deref(),
        Some(max.as_str())
    );
    assert!(
        normalize_federation_token(&"c".repeat(31)).is_none(),
        "state tokens shorter than 256 bits of base64url-like entropy must fail closed"
    );
    assert!(
        normalize_federation_token(&"d".repeat(257)).is_none(),
        "oversized state tokens must not be accepted into Valkey keys"
    );
    assert!(
        normalize_federation_token(&format!("{}=", "e".repeat(32))).is_none(),
        "base64 padding is intentionally outside the accepted state-token alphabet"
    );
}

#[test]
fn oidc_callback_input_rejects_provider_error_before_code_or_state_processing() {
    let query = OidcCallbackQuery {
        code: Some("authorization-code".to_owned()),
        state: Some("A".repeat(32)),
        error: Some("access_denied".to_owned()),
    };
    let response = validate_oidc_callback_input(&query)
        .expect_err("upstream OIDC error must stop callback processing");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("access_denied")
    );
}

#[test]
fn oidc_callback_input_requires_urlsafe_state_and_bounded_non_empty_code() {
    let valid_state = "A".repeat(32);
    let valid = OidcCallbackQuery {
        code: Some(" code-1 ".to_owned()),
        state: Some(valid_state.clone()),
        error: None,
    };
    let input = validate_oidc_callback_input(&valid).expect("valid callback input should parse");
    assert_eq!(input.state_token, valid_state);
    assert_eq!(input.code, "code-1");

    for query in [
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: None,
            error: None,
        },
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some("not+urlsafe".to_owned()),
            error: None,
        },
    ] {
        let response = validate_oidc_callback_input(&query)
            .expect_err("missing or malformed state must fail before token exchange");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("invalid_request")
        );
    }

    for code in [None, Some("   ".to_owned()), Some("x".repeat(4097))] {
        let response = validate_oidc_callback_input(&OidcCallbackQuery {
            code,
            state: Some(valid_state.clone()),
            error: None,
        })
        .expect_err("missing, blank, or oversized authorization code must fail closed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("invalid_request")
        );
    }
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

fn saml_assertion(
    settings: &SamlGatewaySettings,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> SamlGatewayAssertion {
    SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: subject.to_owned(),
        email: email.to_owned(),
        name: None,
        iat,
        exp,
        signature: saml_gateway_signature(
            &settings.secret,
            &settings.issuer,
            &settings.audience,
            subject,
            email,
            iat,
            exp,
        ),
    }
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

#[test]
fn saml_gateway_assertion_rejects_wrong_issuer_audience_and_signature() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let mut wrong_issuer = saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_issuer.issuer = "other-gateway".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_issuer,
        "user@example.com"
    ));

    let mut wrong_audience =
        saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_audience.audience = "other-audience".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_audience,
        "user@example.com"
    ));

    let mut wrong_signature =
        saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_signature.signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "other-subject",
        "user@example.com",
        now,
        now + 60,
    );
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_signature,
        "user@example.com"
    ));
}

#[test]
fn saml_gateway_assertion_rejects_expired_or_future_assertions() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    for (iat, exp) in [(now - 600, now - 60), (now + 61, now + 120)] {
        let assertion = saml_assertion(&settings, "subject", "user@example.com", iat, exp);

        assert!(!valid_saml_gateway_assertion(
            &settings,
            &assertion,
            "user@example.com"
        ));
    }
}
