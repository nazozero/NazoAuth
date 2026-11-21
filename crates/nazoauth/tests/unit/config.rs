use crate::config::{
    AuthorizationServerProfile, Configuration, MtlsCertificateSourceMode,
    Openid4vcRevocationPolicy, parse_trusted_proxy_cidrs,
};

type InvalidConfiguration = (fn(&mut Configuration), &'static str);

fn configuration() -> Configuration {
    Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "https://auth.example",
        "client-secret-pepper-at-least-thirty-two-bytes",
    )
    .unwrap()
}

#[test]
fn product_defaults_preserve_native_policy() {
    let settings = configuration();
    settings.validate().unwrap();
    assert_eq!(settings.protocol.fapi_http_signature_max_age_seconds, 60);
    assert_eq!(settings.session.pending_mfa_session_ttl_seconds, 600);
    assert_eq!(settings.protocol.access_token_ttl_seconds, 300);
    assert_eq!(settings.protocol.id_token_ttl_seconds, 600);
    assert_eq!(settings.identity.rate_limit.auth_max_requests, 100_000);
    assert_eq!(
        settings
            .identity
            .rate_limit
            .login_failure_ip_email_max_attempts,
        5
    );
    assert_eq!(
        settings.session.session_cookie_name,
        "__Host-nazo_oauth_session"
    );
    assert!(!settings.modules.enable_openid4vci_issuer);
    assert!(!settings.modules.enable_openid4vp_verifier);

    let local = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://localhost:8000/tenant",
        "client-secret-pepper-at-least-thirty-two-bytes",
    )
    .unwrap();
    local.validate().unwrap();
    assert!(!local.session.cookie_secure);
    assert_eq!(local.identity.passkey.origin, "http://localhost:8000");
}

#[test]
fn issuer_defaults_allow_passkey_overrides_before_complete_validation() {
    let mut settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "http://[::1]:8080",
        "client-secret-pepper-at-least-thirty-two-bytes",
    )
    .expect("an IPv6 issuer can use a separately configured passkey origin");
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("PASSKEY_RP_ID")
    );
    settings.identity.passkey.origin = "http://localhost:8080".to_owned();
    settings.identity.passkey.rp_id = "localhost".to_owned();
    settings.validate().unwrap();
    assert_eq!(settings.endpoint.issuer, "http://[::1]:8080");
}

#[test]
fn mutable_configuration_is_revalidated_at_product_boundary() {
    let cases: &[InvalidConfiguration] = &[
        (
            |c| c.endpoint.issuer = "http://public.example".into(),
            "https",
        ),
        (
            |c| c.endpoint.cors_allowed_origins = vec!["https://app.example/path".into()],
            "CORS_ALLOWED_ORIGINS",
        ),
        (|c| c.session.cookie_secure = false, "COOKIE_SECURE=false"),
        (
            |c| c.protocol.client_secret_pepper = "short".into(),
            "CLIENT_SECRET_PEPPER",
        ),
        (
            |c| c.protocol.pairwise_subject_secret = Some("short".into()),
            "pairwise_subject_secret",
        ),
        (
            |c| c.protocol.additional_scopes_supported = vec!["contains space".into()],
            "ADDITIONAL_SCOPES_SUPPORTED",
        ),
        (
            |c| c.identity.rate_limit.auth_max_requests = 0,
            "rate limit request caps",
        ),
        (
            |c| c.identity.rate_limit.window_seconds = 0,
            "rate limit windows",
        ),
        (
            |c| c.identity.email.code_ttl_seconds = 0,
            "EMAIL_CODE_TTL_SECONDS",
        ),
        (
            |c| c.identity.passkey.rp_id = "https://auth.example".into(),
            "PASSKEY_RP_ID",
        ),
        (
            |c| c.identity.passkey.origin = "https://auth.example/path".into(),
            "PASSKEY_ORIGIN",
        ),
        (
            |c| c.identity.passkey.origin = "https://different.example".into(),
            "PASSKEY_RP_ID",
        ),
        (
            |c| c.endpoint.mtls_certificate_source = MtlsCertificateSourceMode::Rfc9440,
            "TRUSTED_PROXY_CIDRS",
        ),
    ];
    for (mutate, expected) in cases {
        let mut settings = configuration();
        mutate(&mut settings);
        let error = settings.validate().unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{error}: expected {expected}"
        );
    }
    let mut proxy = configuration();
    proxy.endpoint.mtls_certificate_source = MtlsCertificateSourceMode::Rfc9440;
    proxy.endpoint.trusted_proxy_cidrs = parse_trusted_proxy_cidrs(Some("127.0.0.1/32")).unwrap();
    proxy.validate().unwrap();
}

#[test]
fn existing_lifetime_bounds_apply_to_embedded_hosts() {
    let cases: &[InvalidConfiguration] = &[
        (
            |c| c.protocol.access_token_ttl_seconds = 3_601,
            "ACCESS_TOKEN_TTL_SECONDS",
        ),
        (
            |c| c.protocol.id_token_ttl_seconds = 3_601,
            "ID_TOKEN_TTL_SECONDS",
        ),
        (
            |c| c.protocol.refresh_token_ttl_seconds = 0,
            "REFRESH_TOKEN_TTL_SECONDS",
        ),
        (
            |c| c.protocol.auth_code_ttl_seconds = 0,
            "AUTH_CODE_TTL_SECONDS",
        ),
        (|c| c.protocol.par_ttl_seconds = 0, "PAR_TTL_SECONDS"),
        (
            |c| c.session.pending_mfa_session_ttl_seconds = c.session.session_ttl_seconds,
            "PENDING_MFA_SESSION_TTL_SECONDS",
        ),
        (
            |c| {
                c.device.device_authorization_poll_interval_seconds =
                    c.device.device_authorization_ttl_seconds
            },
            "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
        ),
        (
            |c| c.ciba.ciba_poll_interval_seconds = c.ciba.ciba_auth_req_id_ttl_seconds,
            "CIBA_POLL_INTERVAL_SECONDS",
        ),
        (
            |c| c.protocol.fapi_http_signature_max_age_seconds = 301,
            "FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS",
        ),
        (
            |c| c.storage.scim_event_retention_seconds = 3_599,
            "SCIM_EVENT_RETENTION_SECONDS",
        ),
    ];
    for (mutate, expected) in cases {
        let mut settings = configuration();
        mutate(&mut settings);
        assert!(
            settings
                .validate()
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }
    let mut baseline = configuration();
    baseline.protocol.auth_code_ttl_seconds = 61;
    baseline.protocol.par_ttl_seconds = 600;
    baseline.validate().unwrap();
    baseline.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    assert!(
        baseline
            .validate()
            .unwrap_err()
            .to_string()
            .contains("AUTH_CODE_TTL_SECONDS")
    );
    baseline.protocol.auth_code_ttl_seconds = 60;
    assert!(
        baseline
            .validate()
            .unwrap_err()
            .to_string()
            .contains("PAR_TTL_SECONDS")
    );
    baseline.protocol.par_ttl_seconds = 599;
    baseline.validate().unwrap();
}

#[test]
fn enabled_credential_roles_require_complete_separate_security_material() {
    let mut settings = configuration();
    settings.modules.enable_openid4vci_issuer = true;
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("data encryption root")
    );
    settings.openid4vc.data_encryption_key = Some([1; 32]);
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("ISSUER_MANAGEMENT_TOKEN")
    );
    settings.openid4vc.issuer_management_token =
        Some("issuer-management-token-at-least-thirty-two-bytes".into());
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("CREDENTIAL_CONFIGURATIONS")
    );
    settings.openid4vc.credential_configurations = serde_json::from_value(serde_json::json!({
        "pid": {
            "format": "dc+sd-jwt", "scope": "pid", "vct": "https://auth.example/pid",
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}
        }
    }))
    .unwrap();
    settings.validate().unwrap();
    settings
        .openid4vc
        .deferred_credential_configurations
        .insert("missing".into());
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("DEFERRED_CREDENTIAL_CONFIGURATIONS")
    );
    settings
        .openid4vc
        .deferred_credential_configurations
        .clear();
    settings.modules.enable_openid4vp_verifier = true;
    settings.openid4vc.verifier_management_token =
        settings.openid4vc.issuer_management_token.clone();
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must differ")
    );
    settings.openid4vc.verifier_management_token =
        Some("verifier-management-token-at-least-thirty-two-bytes".into());
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("REVOCATION_POLICY=required")
    );
    settings.openid4vc.revocation_policy = Openid4vcRevocationPolicy::Required;
    // An empty static wallet list remains closed; tenant trust can be provisioned at runtime.
    settings.validate().unwrap();
}

#[test]
fn attestation_trust_rejects_private_material_and_wrong_key_purpose() {
    let mut settings = configuration();
    settings.openid4vc.client_attestation_issuer = Some("https://wallet.example".into());
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("CLIENT_ATTESTATION_JWKS_JSON")
    );
    settings.openid4vc.client_attestation_jwks = Some(serde_json::json!({"keys": [
        {"kid": "one", "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"}
    ]}));
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("public verification keys only")
    );
    let holder_keys = serde_json::json!({"keys": [
        {"kid": "one", "kty": "OKP", "crv": "Ed25519", "x": "x"}
    ]});
    settings.openid4vc.client_attestation_jwks = Some(holder_keys.clone());
    assert!(
        settings
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported for client attestation")
    );
    settings.openid4vc.client_attestation_issuer = None;
    settings.openid4vc.client_attestation_jwks = None;
    settings.openid4vc.key_attestation_jwks = Some(holder_keys);
    settings.validate().unwrap();
}

#[test]
fn typed_federation_registry_keeps_json_configuration_admission_rules() {
    use crate::config::federation::{
        ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
        OidcFederationSettings,
    };
    let mut provider = ExternalLoginProvider {
        provider_id: "oidc".into(),
        enabled: true,
        display_name: "Identity provider".into(),
        icon: None,
        display_order: 0,
        adapter: ExternalLoginProviderAdapter::Oidc(OidcFederationSettings {
            discovery: false,
            backchannel_logout: false,
            id_token_signed_response_alg: None,
            post_logout_redirect_uri: None,
            provider_id: "oidc".into(),
            issuer: "https://identity.example".into(),
            authorization_endpoint: "https://identity.example/authorize".into(),
            token_endpoint: "https://identity.example/token".into(),
            jwks_url: "https://identity.example/jwks".into(),
            userinfo_endpoint: None,
            client_id: "nazoauth".into(),
            client_secret: "provider-secret".into(),
            redirect_uri: "https://auth.example/auth/federation/oidc/callback".into(),
            scopes: "openid profile".into(),
        }),
    };
    FederationProviderRegistry::new(vec![provider.clone()]).unwrap();
    if let ExternalLoginProviderAdapter::Oidc(settings) = &mut provider.adapter {
        settings.token_endpoint = "http://identity.example/token".into();
    }
    assert!(FederationProviderRegistry::new(vec![provider.clone()]).is_err());
    if let ExternalLoginProviderAdapter::Oidc(settings) = &mut provider.adapter {
        settings.token_endpoint = "https://identity.example/token".into();
        settings.client_secret.clear();
    }
    assert!(FederationProviderRegistry::new(vec![provider]).is_err());
}

#[test]
fn oidc_provider_issuer_preserves_trailing_slash_and_rejects_url_credentials() {
    let mut provider = serde_json::json!({
        "provider_id": "oidf-rp-test",
        "enabled": true,
        "display_name": "OIDF RP test",
        "adapter_type": "oidc",
        "issuer": "https://localhost:8443/test/a/nazo-issue202/",
        "authorization_endpoint": "https://localhost:8443/test/a/nazo-issue202/authorize",
        "token_endpoint": "https://localhost:8443/test/a/nazo-issue202/token",
        "jwks_url": "https://localhost:8443/test/a/nazo-issue202/jwks",
        "client_id": "nazoauth-issue202",
        "client_secret": "test-secret",
        "redirect_uri": "https://localhost:8443/rp/auth/federation/oidf-rp-test/callback",
        "scopes": "openid email profile"
    });
    let registry = crate::config::FederationProviderRegistry::from_json(
        &serde_json::json!([provider]).to_string(),
    )
    .expect("an external OP issuer may end in a slash");
    let crate::config::ExternalLoginProviderAdapter::Oidc(settings) =
        &registry.enabled_provider("oidf-rp-test").unwrap().adapter
    else {
        panic!("OIDC provider expected");
    };
    assert_eq!(
        settings.issuer,
        "https://localhost:8443/test/a/nazo-issue202/"
    );
    for invalid in [
        "https://localhost:8443/?query=1",
        "https://localhost:8443/#fragment",
        "https://user:secret@localhost:8443/",
        "http://public.example/",
    ] {
        provider["issuer"] = serde_json::json!(invalid);
        assert!(
            crate::config::FederationProviderRegistry::from_json(
                &serde_json::json!([provider]).to_string(),
            )
            .is_err(),
            "invalid issuer accepted: {invalid}"
        );
    }
}

#[test]
fn oidc_userinfo_endpoint_is_optional_and_uses_endpoint_admission() {
    use crate::config::{ExternalLoginProviderAdapter, FederationProviderRegistry};

    let mut provider = serde_json::json!({
        "provider_id": "oidc",
        "enabled": true,
        "display_name": "Identity provider",
        "adapter_type": "oidc",
        "issuer": "https://identity.example",
        "authorization_endpoint": "https://identity.example/authorize",
        "token_endpoint": "https://identity.example/token",
        "jwks_url": "https://identity.example/jwks",
        "client_id": "nazoauth",
        "client_secret": "provider-secret",
        "redirect_uri": "https://auth.example/auth/federation/oidc/callback"
    });
    let registry =
        FederationProviderRegistry::from_json(&serde_json::json!([provider]).to_string()).unwrap();
    let ExternalLoginProviderAdapter::Oidc(settings) =
        &registry.enabled_provider("oidc").unwrap().adapter
    else {
        panic!("OIDC provider expected");
    };
    assert!(settings.userinfo_endpoint.is_none());

    for endpoint in [
        "https://identity.example/userinfo/?tenant=example",
        "http://127.0.0.1:8443/userinfo",
    ] {
        provider["userinfo_endpoint"] = serde_json::json!(endpoint);
        let registry =
            FederationProviderRegistry::from_json(&serde_json::json!([provider]).to_string())
                .unwrap();
        let ExternalLoginProviderAdapter::Oidc(settings) =
            &registry.enabled_provider("oidc").unwrap().adapter
        else {
            panic!("OIDC provider expected");
        };
        assert_eq!(settings.userinfo_endpoint.as_deref(), Some(endpoint));
    }

    for endpoint in [
        "http://identity.example/userinfo",
        "https://user:secret@identity.example/userinfo",
        "https://identity.example/userinfo#fragment",
    ] {
        provider["userinfo_endpoint"] = serde_json::json!(endpoint);
        assert!(
            FederationProviderRegistry::from_json(&serde_json::json!([provider]).to_string(),)
                .is_err(),
            "invalid UserInfo endpoint accepted: {endpoint}"
        );
    }
}
