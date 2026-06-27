use super::*;

#[test]
fn default_dpop_nonce_policy_is_required() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
}

#[test]
fn baseline_profile_can_use_optional_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "optional")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Optional);
}

#[test]
fn fapi_profiles_force_required_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([
        ("AUTHORIZATION_SERVER_PROFILE", "fapi2-security"),
        ("DPOP_NONCE_POLICY", "optional"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
}

#[test]
fn invalid_dpop_nonce_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "sometimes")]);

    let Err(err) = Settings::from_config(&config) else {
        panic!("invalid DPoP nonce policy must be rejected");
    };

    assert_eq!(
        err.to_string(),
        "DPOP_NONCE_POLICY must be required or optional, got sometimes"
    );
}

#[test]
fn dpop_nonce_policy_rejects_legacy_compatibility_alias() {
    for value in ["compat", "compatible"] {
        let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", value)]);

        let Err(err) = Settings::from_config(&config) else {
            panic!("legacy DPoP nonce policy alias must be rejected");
        };

        assert_eq!(
            err.to_string(),
            format!("DPOP_NONCE_POLICY must be required or optional, got {value}")
        );
    }
}

#[test]
fn default_request_object_jti_policy_is_oidf_compatible() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.request_object_jti_policy,
        RequestObjectJtiPolicy::Optional
    );
}

#[test]
fn request_object_jti_policy_can_require_signed_jar_jti() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "required")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.request_object_jti_policy,
        RequestObjectJtiPolicy::RequiredForSignedJar
    );
}

#[test]
fn invalid_request_object_jti_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "always")]);

    assert!(Settings::from_config(&config).is_err());
}

#[test]
fn feature_gate_settings_default_closed_and_accept_explicit_enablement() {
    let defaults = Settings::from_config(&ConfigSource::default()).unwrap();
    assert!(!defaults.enable_request_object);
    assert!(!defaults.enable_request_uri_parameter);
    assert!(!defaults.enable_par_request_object);
    assert!(!defaults.enable_authorization_details);
    assert!(!defaults.enable_legacy_audience_param);

    let config = ConfigSource::from_pairs_for_test([
        ("ENABLE_REQUEST_OBJECT", "true"),
        ("ENABLE_REQUEST_URI_PARAMETER", "true"),
        ("ENABLE_PAR_REQUEST_OBJECT", "true"),
        ("ENABLE_AUTHORIZATION_DETAILS", "true"),
        ("ENABLE_LEGACY_AUDIENCE_PARAM", "true"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert!(settings.enable_request_object);
    assert!(settings.enable_request_uri_parameter);
    assert!(settings.enable_par_request_object);
    assert!(settings.enable_authorization_details);
    assert!(settings.enable_legacy_audience_param);
}

#[test]
fn signing_key_rotation_settings_default_to_automatic_lifecycle() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(settings.signing_key_rotation_interval_seconds, 7_776_000);
    assert_eq!(settings.signing_key_prepublish_seconds, 86_400);
}

#[test]
fn signing_key_rotation_settings_reject_unsafe_windows() {
    for (key, value, expected) in [
        (
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
            "0",
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS must be positive",
        ),
        (
            "SIGNING_KEY_PREPUBLISH_SECONDS",
            "0",
            "SIGNING_KEY_PREPUBLISH_SECONDS must be positive",
        ),
    ] {
        let config = ConfigSource::from_pairs_for_test([(key, value)]);
        let error = settings_error(&config, "invalid signing key lifecycle setting must fail");
        assert_eq!(error.to_string(), expected);
    }

    let config = ConfigSource::from_pairs_for_test([
        ("SIGNING_KEY_ROTATION_INTERVAL_SECONDS", "3600"),
        ("SIGNING_KEY_PREPUBLISH_SECONDS", "3600"),
    ]);
    let error = settings_error(
        &config,
        "prepublish window must be shorter than rotation interval",
    );
    assert_eq!(
        error.to_string(),
        "SIGNING_KEY_PREPUBLISH_SECONDS must be less than SIGNING_KEY_ROTATION_INTERVAL_SECONDS"
    );
}

#[test]
fn pairwise_subject_secret_must_be_configured_and_strong_enough() {
    let missing = ConfigSource::from_pairs_for_test([("SUBJECT_TYPE", "pairwise")]);
    let error = settings_error(
        &missing,
        "pairwise subject type must not start without a server secret",
    );
    assert_eq!(
        error.to_string(),
        "PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise"
    );

    let weak = ConfigSource::from_pairs_for_test([
        ("SUBJECT_TYPE", "public"),
        ("PAIRWISE_SUBJECT_SECRET", "short"),
    ]);
    let error = settings_error(&weak, "weak pairwise subject secret must fail startup");
    assert_eq!(
        error.to_string(),
        "pairwise_subject_secret must be at least 32 bytes"
    );
}

fn settings_error(config: &ConfigSource, expected_context: &str) -> anyhow::Error {
    match Settings::from_config(config) {
        Ok(_) => panic!("{expected_context}"),
        Err(error) => error,
    }
}

#[test]
fn smtp_delivery_requires_paired_credentials() {
    for (key, value) in [
        ("EMAIL_SMTP_USERNAME", "smtp-user"),
        ("EMAIL_SMTP_PASSWORD", "smtp-password"),
    ] {
        let config = ConfigSource::from_pairs_for_test([
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "smtp.example.test"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            (key, value),
        ]);

        let error = settings_error(
            &config,
            "SMTP must not start with only one authentication credential",
        );
        assert_eq!(
            error.to_string(),
            "EMAIL_SMTP_USERNAME and EMAIL_SMTP_PASSWORD must be configured together"
        );
    }
}

#[test]
fn smtp_delivery_rejects_invalid_sender_and_tls_mode() {
    let invalid_from = ConfigSource::from_pairs_for_test([
        ("EMAIL_DELIVERY", "smtp"),
        ("EMAIL_SMTP_HOST", "smtp.example.test"),
        ("EMAIL_FROM", "not a mailbox"),
    ]);

    let error = settings_error(
        &invalid_from,
        "SMTP sender must be a syntactically valid mailbox",
    );
    assert_eq!(error.to_string(), "EMAIL_FROM must be a valid mailbox");

    let invalid_tls = ConfigSource::from_pairs_for_test([
        ("EMAIL_DELIVERY", "smtp"),
        ("EMAIL_SMTP_HOST", "smtp.example.test"),
        ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
        ("EMAIL_SMTP_TLS", "opportunistic"),
    ]);

    let error = settings_error(&invalid_tls, "unknown SMTP TLS modes must fail closed");
    assert_eq!(
        error.to_string(),
        "EMAIL_SMTP_TLS must be starttls, implicit, or none, got opportunistic"
    );
}

#[test]
fn smtp_delivery_accepts_explicit_tls_modes_without_secret_leakage() {
    for (raw, expected) in [
        ("starttls", SmtpTlsMode::StartTls),
        ("implicit", SmtpTlsMode::ImplicitTls),
        ("tls", SmtpTlsMode::ImplicitTls),
        ("none", SmtpTlsMode::None),
        ("plain", SmtpTlsMode::None),
    ] {
        let config = ConfigSource::from_pairs_for_test([
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "smtp.example.test"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            ("EMAIL_SMTP_USERNAME", "smtp-user"),
            ("EMAIL_SMTP_PASSWORD", "smtp-password"),
            ("EMAIL_SMTP_TLS", raw),
        ]);

        let settings = Settings::from_config(&config).unwrap();
        let EmailDelivery::Smtp(smtp) = settings.email.delivery else {
            panic!("smtp delivery should be enabled");
        };
        assert_eq!(smtp.host, "smtp.example.test");
        assert_eq!(smtp.username.as_deref(), Some("smtp-user"));
        assert_eq!(smtp.password.as_deref(), Some("smtp-password"));
        assert!(matches!(
            (smtp.tls, expected),
            (SmtpTlsMode::StartTls, SmtpTlsMode::StartTls)
                | (SmtpTlsMode::ImplicitTls, SmtpTlsMode::ImplicitTls)
                | (SmtpTlsMode::None, SmtpTlsMode::None)
        ));
    }
}

fn oidc_federation_config_with(
    override_key: &'static str,
    override_value: &'static str,
) -> ConfigSource {
    ConfigSource::from_pairs_for_test([
        ("FEDERATION_OIDC_PROVIDER_ID", "oidc-upstream"),
        ("FEDERATION_OIDC_ISSUER", "https://idp.example.test"),
        (
            "FEDERATION_OIDC_AUTHORIZATION_ENDPOINT",
            "https://idp.example.test/authorize",
        ),
        (
            "FEDERATION_OIDC_TOKEN_ENDPOINT",
            "https://idp.example.test/token",
        ),
        ("FEDERATION_OIDC_JWKS_URL", "https://idp.example.test/jwks"),
        ("FEDERATION_OIDC_CLIENT_ID", "client-1"),
        ("FEDERATION_OIDC_CLIENT_SECRET", "secret-1"),
        (
            "FEDERATION_OIDC_REDIRECT_URI",
            "https://auth.example.test/auth/federation/oidc/callback",
        ),
        ("FEDERATION_OIDC_SCOPES", "openid email profile"),
        (override_key, override_value),
    ])
}

#[test]
fn oidc_federation_requires_all_or_none_configuration() {
    let config =
        ConfigSource::from_pairs_for_test([("FEDERATION_OIDC_ISSUER", "https://idp.example.test")]);

    let error = settings_error(
        &config,
        "partial OIDC federation config must fail closed at startup",
    );
    assert_eq!(
        error.to_string(),
        "FEDERATION_OIDC_PROVIDER_ID is required when OIDC federation is configured"
    );
}

#[test]
fn oidc_federation_rejects_insecure_runtime_urls() {
    for (key, value) in [
        ("FEDERATION_OIDC_ISSUER", "http://idp.example.test"),
        (
            "FEDERATION_OIDC_AUTHORIZATION_ENDPOINT",
            "http://idp.example.test/authorize",
        ),
        (
            "FEDERATION_OIDC_TOKEN_ENDPOINT",
            "http://idp.example.test/token",
        ),
        ("FEDERATION_OIDC_JWKS_URL", "http://idp.example.test/jwks"),
        (
            "FEDERATION_OIDC_REDIRECT_URI",
            "http://auth.example.test/auth/federation/oidc/callback",
        ),
    ] {
        let config = oidc_federation_config_with(key, value);

        let error = settings_error(
            &config,
            "OIDC federation URLs must remain HTTPS except loopback development URLs",
        );
        assert!(
            error.to_string().contains("https"),
            "unexpected error for {key}: {error}"
        );
    }
}

#[test]
fn oidc_federation_requires_openid_scope() {
    let config = oidc_federation_config_with("FEDERATION_OIDC_SCOPES", "email profile");

    let error = settings_error(
        &config,
        "OIDC federation without openid scope cannot produce an OIDC identity",
    );
    assert_eq!(
        error.to_string(),
        "FEDERATION_OIDC_SCOPES must include openid"
    );
}

#[test]
fn saml_gateway_requires_strong_shared_secret_when_enabled() {
    let config = ConfigSource::from_pairs_for_test([
        ("FEDERATION_SAML_GATEWAY_ENABLED", "true"),
        (
            "FEDERATION_SAML_GATEWAY_ISSUER",
            "https://auth.example.test",
        ),
        (
            "FEDERATION_SAML_GATEWAY_AUDIENCE",
            "https://sp.example.test",
        ),
        ("FEDERATION_SAML_GATEWAY_SECRET", "short"),
    ]);

    let error = settings_error(&config, "SAML gateway MAC secret must not be weak");
    assert_eq!(
        error.to_string(),
        "FEDERATION_SAML_GATEWAY_SECRET must be at least 32 bytes"
    );
}
