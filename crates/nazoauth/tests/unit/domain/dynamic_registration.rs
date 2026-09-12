use crate::{config::ConfigSource, settings::Settings};

#[test]
fn dynamic_registration_config_copies_security_and_rate_limit_settings() {
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("DEFAULT_AUDIENCE", "https://resource.example"),
        (
            "PAIRWISE_SUBJECT_SECRET",
            "pairwise-subject-secret-for-tests-000000000001",
        ),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        (
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
            "initial-access-token",
        ),
        ("RATE_LIMIT_WINDOW_SECONDS", "37"),
        ("TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS", "11"),
        ("TRANSPORT_MODE", "trusted-proxy"),
        ("TRUSTED_PROXY_CIDRS", "203.0.113.0/24"),
        ("MTLS_CERTIFICATE_SOURCE", "disabled"),
    ]);
    let settings = Settings::from_config(&config).expect("dynamic registration settings");
    let keyset = nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let dynamic = super::dynamic_registration_config(&settings, &keyset);

    assert_eq!(dynamic.issuer, "https://issuer.example");
    assert_eq!(dynamic.default_audience, "https://resource.example");
    assert_eq!(
        dynamic.pairwise_subject_secret.as_deref(),
        Some("pairwise-subject-secret-for-tests-000000000001")
    );
    assert_eq!(
        dynamic.initial_access_token.as_deref(),
        Some("initial-access-token")
    );
    assert_eq!(dynamic.rate_limit_window_seconds, 37);
    assert_eq!(dynamic.rate_limit_max_requests, 11);
    assert_eq!(settings.endpoint.trusted_proxy_cidrs.len(), 1);
}
