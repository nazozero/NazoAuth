use super::*;

fn settings_error(config: &ConfigSource, expected_context: &str) -> anyhow::Error {
    match Settings::from_config(config) {
        Ok(_) => panic!("{expected_context}"),
        Err(error) => error,
    }
}

#[test]
fn production_issuer_cannot_disable_secure_session_cookies() {
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://auth.example.test"),
        ("FRONTEND_BASE_URL", "https://app.example.test"),
        ("CORS_ALLOWED_ORIGINS", "https://app.example.test"),
        ("COOKIE_SECURE", "false"),
    ]);

    let error = settings_error(
        &config,
        "production HTTPS issuer must not allow insecure cookies",
    );

    assert_eq!(
        error.to_string(),
        "COOKIE_SECURE=false 只允许用于 loopback HTTP 本地开发 issuer"
    );
}

#[test]
fn pairwise_subject_type_requires_stable_secret_material() {
    let missing_secret = ConfigSource::from_pairs_for_test([("SUBJECT_TYPE", "pairwise")]);
    let error = settings_error(
        &missing_secret,
        "pairwise subject identifiers must not start without a secret",
    );
    assert_eq!(
        error.to_string(),
        "PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise"
    );

    let configured = ConfigSource::from_pairs_for_test([
        ("SUBJECT_TYPE", "pairwise"),
        ("PAIRWISE_SUBJECT_SECRET", "stable-pairwise-secret"),
    ]);
    let settings =
        Settings::from_config(&configured).expect("pairwise secret should satisfy startup policy");
    assert_eq!(settings.subject_type, SubjectType::Pairwise);
    assert_eq!(
        settings.pairwise_subject_secret.as_deref(),
        Some("stable-pairwise-secret")
    );
}

#[test]
fn fapi_profiles_force_par_and_cap_authorization_code_lifetime() {
    let excessive_ttl = ConfigSource::from_pairs_for_test([
        ("AUTHORIZATION_SERVER_PROFILE", "fapi2-security"),
        ("AUTH_CODE_TTL_SECONDS", "61"),
    ]);
    let error = settings_error(
        &excessive_ttl,
        "FAPI authorization codes must remain short lived",
    );
    assert_eq!(
        error.to_string(),
        "AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles"
    );

    let par_disabled = ConfigSource::from_pairs_for_test([
        (
            "AUTHORIZATION_SERVER_PROFILE",
            "fapi2-message-signing-authz-request",
        ),
        ("AUTH_CODE_TTL_SECONDS", "60"),
        ("REQUIRE_PUSHED_AUTHORIZATION_REQUESTS", "false"),
        ("DPOP_NONCE_POLICY", "optional"),
    ]);
    let settings = Settings::from_config(&par_disabled).expect("valid FAPI settings should load");
    assert_eq!(
        settings.authorization_server_profile,
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest
    );
    assert_eq!(settings.auth_code_ttl_seconds, 60);
    assert!(
        settings.require_pushed_authorization_requests,
        "FAPI profiles must force PAR even when the raw config tries to disable it"
    );
    assert_eq!(
        settings.dpop_nonce_policy,
        DpopNoncePolicy::Required,
        "FAPI profiles must not allow optional DPoP nonce policy"
    );
}

#[test]
fn external_signing_command_parser_trims_empty_segments_without_reordering_arguments() {
    let config = ConfigSource::from_pairs_for_test([(
        "SIGNING_EXTERNAL_COMMAND",
        " /usr/local/bin/signer , --kid , active-key , , --mode=detached ",
    )]);

    let settings = Settings::from_config(&config).expect("external signing command should parse");

    assert_eq!(
        settings.signing_external_command,
        vec![
            "/usr/local/bin/signer".to_owned(),
            "--kid".to_owned(),
            "active-key".to_owned(),
            "--mode=detached".to_owned(),
        ],
        "external signer argv must be deterministic and must not include empty shell fragments"
    );
}
