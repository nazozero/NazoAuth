use crate::config::{Configuration, IpCidr};

#[test]
fn dynamic_registration_config_copies_security_and_rate_limit_settings() {
    let mut settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "https://issuer.example",
        "client-secret-pepper-for-tests-000000000001",
    )
    .unwrap();
    settings.protocol.default_audience = "https://resource.example".to_owned();
    settings.protocol.pairwise_subject_secret =
        Some("pairwise-subject-secret-for-tests-000000000001".to_owned());
    settings
        .modules
        .dynamic_client_registration_initial_access_token = Some("initial-access-token".to_owned());
    settings.identity.rate_limit.window_seconds = 37;
    settings.identity.rate_limit.token_management_max_requests = 11;
    settings.endpoint.trusted_proxy_cidrs = vec![IpCidr::parse("203.0.113.0/24").unwrap()];
    let keyset = nazo_key_management::KeyManager::for_test(nazo_crypto::jwt::Algorithm::EdDSA);
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
