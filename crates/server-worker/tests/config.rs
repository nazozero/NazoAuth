use nazo_server_worker::{Ingress, WorkerConfiguration};

fn configuration() -> WorkerConfiguration {
    WorkerConfiguration {
        tenant: nazo_identity::TenantContext::default_system(),
        issuer: "https://auth.example.com".into(),
        frontend_base_url: "https://app.example.com".into(),
        ingress: Ingress::DirectCloudflare,
        cors_allowed_origins: vec![],
        modules: vec![],
    }
}

#[test]
fn unavailable_module_fails_before_composition() {
    let mut config = configuration();
    config
        .modules
        .push(nazo_runtime_modules::ModuleId::Openid4vciIssuer);
    assert!(config.application("p".repeat(32)).is_err());
}

#[test]
fn local_ingress_cannot_disable_public_ingress_authentication() {
    let mut config = configuration();
    config.ingress = Ingress::Local;
    assert!(config.application("p".repeat(32)).is_err());
    config.issuer = "http://localhost:8787".into();
    assert!(config.application("p".repeat(32)).is_ok());
}

#[test]
fn unknown_native_configuration_is_rejected() {
    assert!(
        serde_json::from_value::<WorkerConfiguration>(serde_json::json!({
            "tenant": nazo_identity::TenantContext::default_system(),
            "issuer": "https://auth.example.com", "frontend_base_url": "https://app.example.com",
            "ingress": "direct_cloudflare", "external_signer_command": "sign"
        }))
        .is_err()
    );
}

#[cfg(feature = "provisioning")]
#[test]
fn malformed_dummy_verifier_is_rejected_before_storage_initialization() {
    for malformed in [
        "$argon2id$v=19$m=19456,t=2,p=1$",
        "$argon2id$v=19$m=19456,t=2,p=1$c2hvcnQ$c2hvcnQ",
    ] {
        let result = futures_executor::block_on(nazo_server_worker::WorkerApplication::build(
            configuration(),
            nazo_oauth_server_d1::Database::in_memory().unwrap(),
            "p".repeat(32),
            nazo_key_management::SigningKeyWrappingKeyRing::new("test", [7; 32], None).unwrap(),
            malformed.into(),
        ));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("malformed dummy verifier was accepted"),
        };
        assert_eq!(
            error.to_string(),
            "dummy verifier must use the deployment's Argon2id password policy"
        );
    }
}

#[test]
fn issuer_with_unroutable_path_is_rejected() {
    let mut config = configuration();
    config.issuer = "https://auth.example.com/nazo".into();
    assert!(config.application("p".repeat(32)).is_err());
}

#[test]
fn authority_rejects_userinfo_and_malformed_explicit_ports() {
    let config = configuration();
    for invalid in [
        "attacker@auth.example.com",
        "auth.example.com:65536",
        "auth.example.com:abc",
        "auth.example.com:",
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert("host", invalid.parse().unwrap());
        assert!(
            !config.accepts_authority(&"https://auth.example.com/token".parse().unwrap(), &headers),
            "{invalid}"
        );
        if let Ok(uri) = format!("https://{invalid}/token").parse() {
            assert!(
                !config.accepts_authority(&uri, &http::HeaderMap::new()),
                "{invalid}"
            );
        }
    }
}

#[test]
fn authority_admission_ignores_forwarding_headers_and_rejects_conflicting_host() {
    let config = configuration();
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-host", "auth.example.com".parse().unwrap());
    assert!(!config.accepts_authority(&"https://other.example/token".parse().unwrap(), &headers));
    assert!(config.accepts_authority(
        &"https://AUTH.example.com:443/token".parse().unwrap(),
        &headers
    ));
    headers.insert("host", "other.example".parse().unwrap());
    assert!(
        !config.accepts_authority(&"https://auth.example.com/token".parse().unwrap(), &headers)
    );
    assert!(!config.accepts_authority(
        &"http://auth.example.com/token".parse().unwrap(),
        &http::HeaderMap::new()
    ));
    assert!(!config.accepts_authority(&"/token".parse().unwrap(), &http::HeaderMap::new()));
}
