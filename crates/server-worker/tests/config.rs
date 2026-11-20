use nazo_server_worker::{Ingress, WorkerConfiguration};

#[cfg(feature = "provisioning")]
fn wrapping_keys() -> nazo_key_management::SigningKeyWrappingKeyRing {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let key = URL_SAFE_NO_PAD
        .decode(nazo_oauth_server::crypto::random_urlsafe_token())
        .unwrap()
        .try_into()
        .unwrap();
    nazo_key_management::SigningKeyWrappingKeyRing::new("test", key, None).unwrap()
}

fn configuration() -> WorkerConfiguration {
    WorkerConfiguration {
        tenant: nazo_identity::TenantContext::default_system(),
        issuer: "https://auth.example.com".into(),
        frontend_base_url: "https://app.example.com".into(),
        ingress: Ingress::DirectCloudflare,
        cors_allowed_origins: vec![],
        modules: vec![],
        machine_only: false,
        passkey_only: false,
        services: Default::default(),
    }
}

#[test]
fn free_profile_limits_routes_and_modules() {
    let mut config = configuration();
    config.machine_only = true;
    for (method, path) in [
        (http::Method::GET, "/.well-known/oauth-authorization-server"),
        (http::Method::GET, "/jwks.json"),
        (http::Method::POST, "/token"),
        (http::Method::POST, "/revoke"),
    ] {
        assert!(config.allows_route(&method, path), "{path}");
    }
    for (method, path) in [
        (http::Method::POST, "/auth/login"),
        (http::Method::POST, "/auth/register"),
        (http::Method::GET, "/authorize"),
        (http::Method::GET, "/userinfo"),
        (http::Method::GET, "/.well-known/openid-configuration"),
    ] {
        assert!(!config.allows_route(&method, path), "{path}");
    }
    let metadata = config.machine_metadata();
    assert_eq!(
        metadata["grant_types_supported"],
        serde_json::json!(["client_credentials"])
    );
    assert_eq!(metadata["token_endpoint"], "https://auth.example.com/token");
    assert!(metadata.get("authorization_endpoint").is_none());
    config
        .modules
        .push(nazo_runtime_modules::ModuleId::SessionManagement);
    assert!(config.application("p".repeat(32)).is_err());
}

#[test]
fn free_passkey_profile_never_exposes_password_authentication() {
    let mut config = configuration();
    config.passkey_only = true;
    config
        .modules
        .push(nazo_runtime_modules::ModuleId::DeviceAuthorization);
    for (method, path) in [
        (http::Method::GET, "/.well-known/openid-configuration"),
        (http::Method::GET, "/authorize"),
        (http::Method::GET, "/auth/setup"),
        (http::Method::POST, "/auth/passkey/begin"),
        (http::Method::POST, "/auth/passkey/finish"),
        (http::Method::POST, "/auth/mfa/verify"),
        (http::Method::OPTIONS, "/auth/mfa/verify"),
        (http::Method::POST, "/auth/me/mfa/totp/begin"),
        (http::Method::POST, "/auth/me/mfa/totp/confirm"),
        (http::Method::POST, "/auth/me/mfa/step-up"),
        (http::Method::POST, "/auth/me/mfa/backup-codes/regenerate"),
        (http::Method::POST, "/auth/me/mfa/disable"),
        (http::Method::POST, "/auth/me/passkeys/registration/begin"),
        (http::Method::POST, "/auth/me/passkeys/registration/finish"),
        (http::Method::POST, "/auth/setup/claim"),
        (http::Method::PATCH, "/auth/me"),
        (http::Method::OPTIONS, "/auth/me"),
        (http::Method::POST, "/device_authorization"),
        (http::Method::GET, "/device"),
        (http::Method::GET, "/device/verification"),
        (http::Method::POST, "/device/decision"),
    ] {
        assert!(config.allows_route(&method, path), "{path}");
    }
    for (method, path) in [
        (http::Method::POST, "/auth/login"),
        (http::Method::POST, "/auth/register"),
        (http::Method::GET, "/auth/mfa/verify"),
        (http::Method::POST, "/auth/me/mfa/unknown"),
        (http::Method::POST, "/auth/me/mfa/totp/begin/nested"),
        (http::Method::GET, "/admin/users"),
        (http::Method::GET, "/auth/me/applications"),
        (http::Method::POST, "/auth/setup"),
    ] {
        assert!(!config.allows_route(&method, path), "{path}");
    }
    config.machine_only = true;
    assert!(config.application("p".repeat(32)).is_err());
}

#[test]
fn all_shared_modules_are_admitted_by_the_host_profile() {
    let mut config = configuration();
    config.modules = nazo_runtime_modules::ModuleId::ALL.to_vec();
    assert!(config.application("p".repeat(32)).is_ok());
    config.services.mtls = true;
    assert!(config.application("p".repeat(32)).is_ok());
    let metadata = config.machine_metadata();
    assert_eq!(metadata["tls_client_certificate_bound_access_tokens"], true);
    assert!(
        metadata["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("tls_client_auth"))
    );
}

#[test]
fn portable_extensions_and_service_metadata_follow_the_selected_modules() {
    use nazo_runtime_modules::ModuleId;
    let mut config = configuration();
    config.modules = vec![
        ModuleId::DeviceAuthorization,
        ModuleId::TokenExchange,
        ModuleId::JwtBearerGrant,
        ModuleId::NativeSso,
        ModuleId::FrontchannelLogout,
        ModuleId::HttpMessageSignatures,
        ModuleId::SessionManagement,
    ];
    config.passkey_only = true;
    assert!(config.application("p".repeat(32)).is_ok());
    for (method, path) in [
        (http::Method::GET, "/check_session"),
        (http::Method::GET, "/check_session/status"),
        (http::Method::POST, "/logout"),
        (http::Method::GET, "/fapi/resource"),
        (http::Method::POST, "/fapi/resource"),
        (http::Method::OPTIONS, "/token"),
        (http::Method::OPTIONS, "/userinfo"),
    ] {
        assert!(config.allows_route(&method, path), "{path}");
    }
    assert!(!config.allows_route(&http::Method::OPTIONS, "/auth/login"));
    assert!(!config.allows_route(&http::Method::OPTIONS, "/admin/users"));
    config.passkey_only = false;
    config.machine_only = true;
    config.modules = vec![ModuleId::TokenExchange, ModuleId::JwtBearerGrant];
    assert!(config.application("p".repeat(32)).is_ok());
    assert_eq!(
        config.machine_metadata()["grant_types_supported"],
        serde_json::json!([
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ])
    );
    assert!(config.allows_route(&http::Method::OPTIONS, "/token"));
    assert!(!config.allows_route(&http::Method::OPTIONS, "/authorize"));
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
            wrapping_keys(),
            malformed.into(),
            None,
            Default::default(),
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

#[cfg(feature = "provisioning")]
#[test]
fn dynamic_registration_requires_a_separate_initial_access_secret() {
    for secret in [None, Some("short".to_owned()), Some("x".repeat(32))] {
        let mut config = configuration();
        config.modules = vec![nazo_runtime_modules::ModuleId::DynamicClientRegistration];
        let meets_length = secret.as_ref().is_some_and(|secret| secret.len() >= 32);
        let result = futures_executor::block_on(nazo_server_worker::WorkerApplication::build(
            config,
            nazo_oauth_server_d1::Database::in_memory().unwrap(),
            "p".repeat(32),
            wrapping_keys(),
            "invalid-dummy-verifier".into(),
            secret,
            Default::default(),
        ));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid deployment was accepted"),
        };
        assert_eq!(
            error.to_string(),
            if meets_length {
                "dummy verifier must use the deployment's Argon2id password policy"
            } else {
                "dynamic client registration requires an initial access token of at least 32 bytes"
            }
        );
    }
}

#[cfg(feature = "provisioning")]
#[test]
fn worker_import_rejects_iaca_private_material_before_storage_access() {
    for private in [
        serde_json::json!({}),
        serde_json::json!({"issuer": "private fixture rejected before parsing"}),
    ] {
        let has_private = !private.as_object().unwrap().is_empty();
        let secrets = serde_json::from_value(serde_json::json!({
            "openid4vc_import": {
                "expected_revision": 1,
                "material": {
                    "public": {"signing_kid": "fixture", "certificate_chain_pem": "", "trust_anchors_pem": "", "revocation_snapshot": null},
                    "iaca_private_materials": private
                },
                "signing_key_pem": null
            }
        })).unwrap();
        let result = futures_executor::block_on(nazo_server_worker::WorkerApplication::build(
            configuration(),
            nazo_oauth_server_d1::Database::in_memory().unwrap(),
            "p".repeat(32),
            wrapping_keys(),
            "invalid-dummy-verifier".into(),
            None,
            secrets,
        ));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid fixture was accepted"),
        };
        assert_eq!(
            error.to_string(),
            if has_private {
                "IACA private keys must remain outside the Worker"
            } else {
                "dummy verifier must use the deployment's Argon2id password policy"
            }
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

#[test]
fn native_sso_requires_its_shared_exchange_module() {
    let mut config = configuration();
    config.modules = vec![nazo_runtime_modules::ModuleId::NativeSso];
    assert!(config.application("p".repeat(32)).is_err());
    config
        .modules
        .push(nazo_runtime_modules::ModuleId::TokenExchange);
    assert!(config.application("p".repeat(32)).is_ok());
}

#[test]
fn registration_admission_follows_the_deployment_capabilities() {
    use nazo_runtime_modules::ModuleId;
    let mut config = configuration();
    config.passkey_only = true;
    assert!(!config.allows_route(&http::Method::POST, "/register"));
    assert!(!config.allows_route(&http::Method::GET, "/device"));
    config.modules = vec![
        ModuleId::DynamicClientRegistration,
        ModuleId::DeviceAuthorization,
    ];
    for (method, path) in [
        (http::Method::POST, "/register"),
        (http::Method::GET, "/register/client"),
        (http::Method::PUT, "/register/client"),
        (http::Method::DELETE, "/register/client"),
        (http::Method::GET, "/device"),
    ] {
        assert!(config.allows_route(&method, path), "{path}");
    }
    assert!(!config.allows_route(&http::Method::GET, "/register/client/nested"));
    let settings = config.application("p".repeat(32)).unwrap();
    let capabilities = settings.modules.dynamic_client_registration_capabilities;
    assert!(
        !capabilities.remote_documents && !capabilities.mtls && !capabilities.backchannel_logout
    );
    let grants = capabilities.grant_types.unwrap();
    assert!(
        grants
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:device_code")
    );
    assert!(
        !grants
            .iter()
            .any(|grant| grant == "urn:ietf:params:oauth:grant-type:token-exchange")
    );
    config.passkey_only = false;
    config.machine_only = true;
    config.modules = vec![ModuleId::DynamicClientRegistration];
    let settings = config.application("p".repeat(32)).unwrap();
    assert_eq!(
        settings
            .modules
            .dynamic_client_registration_capabilities
            .grant_types
            .unwrap(),
        vec!["client_credentials"]
    );
    assert_eq!(
        config.machine_metadata()["registration_endpoint"],
        "https://auth.example.com/register"
    );
}
