use super::*;

fn configuration(prefix: &str) -> Configuration {
    Configuration::new(
        nazo_identity::TenantContext::default_system(),
        format!("https://issuer.example{}", prefix.trim_end_matches('/')),
        "client-secret-pepper-at-least-thirty-two-bytes",
    )
    .unwrap()
}

#[test]
fn issuer_and_resource_determine_exact_discovery_locations() {
    for prefix in ["/", "/testauth", "/services/auth"] {
        let mut settings = configuration(prefix);
        settings.modules.enable_openid4vci_issuer = true;
        settings.modules.register_openid4vci_routes = true;
        let mount = Mount::new(&settings, prefix).unwrap();
        let suffix = prefix.trim_end_matches('/');
        for (path, endpoint) in [
            (format!("{suffix}/token"), Endpoint::Token),
            (
                format!("{suffix}/.well-known/openid-configuration"),
                Endpoint::Discovery,
            ),
            (
                format!("/.well-known/oauth-authorization-server{suffix}"),
                Endpoint::OauthAuthorizationServerMetadata,
            ),
            (
                format!("/.well-known/openid-credential-issuer{suffix}"),
                Endpoint::CredentialIssuerMetadata,
            ),
            (
                format!("/.well-known/oauth-protected-resource{suffix}/fapi/resource"),
                Endpoint::OauthProtectedResourceMetadata,
            ),
        ] {
            assert_eq!(
                mount.route_for_path(&path).unwrap().methods[0].endpoint,
                endpoint,
                "{path}"
            );
        }
        for route in super::super::routes() {
            if let Some(path) = mount.route_path(route) {
                assert!(mount.owns_path(&path), "{path}");
            }
        }
        assert!(
            mount
                .route_for_path(&format!(
                    "{suffix}/.well-known/oauth-protected-resource/wrong"
                ))
                .is_none()
        );
        if !suffix.is_empty() {
            for path in [
                "/token".to_owned(),
                format!("{suffix}2/token"),
                format!("{suffix}/.well-known/oauth-authorization-server"),
            ] {
                assert!(mount.route_for_path(&path).is_none(), "{path}");
            }
        }
    }
}

#[test]
fn raw_prefix_boundaries_and_borrowed_route_views_preserve_signed_requests() {
    let mount = Mount::new(&configuration("/testauth"), "/testauth/").unwrap();
    assert_eq!(mount.path(), "/testauth");
    let uri: http::Uri = "https://issuer.example/testauth/admin/clients/a%2Fb?x=1&x=2"
        .parse()
        .unwrap();
    let path = mount.routing_path(uri.path()).unwrap();
    assert!(matches!(path, Cow::Borrowed(_)));
    assert_eq!(path.as_ptr(), uri.path()[9..].as_ptr());
    let (_, params) = crate::routes::match_path(&path).unwrap();
    assert_eq!(params.get("client_id"), Some("a%2Fb"));
    assert_eq!(
        uri.to_string(),
        "https://issuer.example/testauth/admin/clients/a%2Fb?x=1&x=2"
    );
    assert_eq!(
        mount.route_for_path("/testauth/%74oken").unwrap().methods[0].endpoint,
        Endpoint::Token
    );
    for path in [
        "/%74estauth/token",
        "/testauth%2Ftoken",
        "/testauth2/token",
        "/testauth/../token",
        "/testauth/%2e%2e/token",
        "/testauth/token/",
        "/testauth//token",
    ] {
        assert!(mount.route_for_path(path).is_none(), "{path}");
    }
    assert!(mount.owns_path("/testauth/unknown"));
    assert!(!mount.owns_path("/testauth/ui/index.html"));
    assert!(mount.owns_path("/testauth/ui-other"));
}

#[test]
fn bad_prefixes_and_incompatible_configuration_fail_before_construction() {
    for prefix in [
        "",
        "relative",
        "//",
        "/auth//",
        "/auth//nested",
        "/auth/../nested",
        "/%61uth",
        "/auth?x=1",
        "/auth#frag",
        "/auth\\nested",
        "/auth/{tenant}",
    ] {
        assert!(
            Mount::new(&configuration("/auth"), prefix).is_err(),
            "{prefix}"
        );
    }
    assert!(Mount::new(&configuration("/auth"), "/").is_err());
    let mut normalized = configuration("/base/../auth");
    assert!(Mount::new(&normalized, "/auth").is_err());
    normalized = configuration("/auth");
    normalized.protocol.protected_resource_identifier =
        "https://issuer.example/base/../resource".into();
    assert!(Mount::new(&normalized, "/auth").is_err());
    let mut settings = configuration("/auth");
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example/other".into();
    assert!(Mount::new(&settings, "/auth").is_err());
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example/auth".into();
    settings.protocol.protected_resource_identifier = "https://resource.example/api".into();
    assert!(Mount::new(&settings, "/auth").is_err());
    settings.protocol.protected_resource_identifier =
        "https://issuer.example/api?resource=one".into();
    assert!(Mount::new(&settings, "/auth").is_err());
}

#[test]
fn host_namespaces_and_required_discovery_cannot_overlap() {
    let mount = Mount::new(&configuration("/team/auth"), "/team/auth").unwrap();
    for reserved in [
        "/",
        "/team",
        "/team/auth",
        "/team/auth/token",
        "/.well-known",
        "/.well-known/oauth-authorization-server/team/auth",
        "/.well-known/oauth-protected-resource/team/auth/fapi/resource",
    ] {
        assert!(mount.check_conflicts(&[reserved]).is_err(), "{reserved}");
    }
    mount
        .check_conflicts(&[
            "/api",
            "/users",
            "/team/auth2",
            "/team/auth/ui",
            "/.well-known/oauth-authorization-server/other",
        ])
        .unwrap();
    let root = Mount::new(&configuration("/"), "/").unwrap();
    root.check_conflicts(&["/api", "/users", "/ui"]).unwrap();
    root.check_conflicts(&["/.well-known/oauth-protected-resource/other"])
        .unwrap();
    for reserved in [
        "/",
        "/token",
        "/auth",
        "/admin/clients/custom",
        "/.well-known/oauth-protected-resource/fapi/resource",
    ] {
        assert!(root.check_conflicts(&[reserved]).is_err(), "{reserved}");
    }
}

#[test]
fn host_reservations_reject_decoded_aliases_without_decoding_separators() {
    let root = Mount::new(&configuration("/"), "/").unwrap();
    for reserved in ["/%74oken", "/auth/%6De", "/admin/%63lients/custom"] {
        assert!(root.check_conflicts(&[reserved]).is_err(), "{reserved}");
    }
    let mut settings = configuration("/testauth");
    let mount = Mount::new(&settings, "/testauth").unwrap();
    assert!(mount.check_conflicts(&["/%74estauth"]).is_err());
    mount.check_conflicts(&["/testauth%2Ftoken"]).unwrap();
    for (resource, alias) in [("/api%61", "/apia"), ("/api*", "/api%2A")] {
        settings.protocol.protected_resource_identifier =
            format!("https://issuer.example{resource}");
        let mount = Mount::new(&settings, "/testauth").unwrap();
        let reserved = format!("/.well-known/oauth-protected-resource{alias}");
        assert!(mount.check_conflicts(&[&reserved]).is_err(), "{reserved}");
    }
    settings.protocol.protected_resource_identifier = "https://issuer.example/api%2Fone".into();
    Mount::new(&settings, "/testauth")
        .unwrap()
        .check_conflicts(&["/.well-known/oauth-protected-resource/api/one"])
        .unwrap();
}

#[test]
fn resource_path_is_exact_including_trailing_slash() {
    let mut settings = configuration("/auth");
    settings.protocol.protected_resource_identifier = "https://issuer.example/api/".into();
    let mount = Mount::new(&settings, "/auth").unwrap();
    assert!(
        mount
            .route_for_path("/.well-known/oauth-protected-resource/api/")
            .is_some()
    );
    assert!(
        mount
            .route_for_path("/.well-known/oauth-protected-resource/api")
            .is_none()
    );
}

#[test]
fn other_mounts_reserve_their_exact_discovery_paths() {
    let mut first_settings = configuration("/first");
    first_settings.protocol.protected_resource_identifier =
        "https://issuer.example/assets/a%2Fb:version*".into();
    let first = Mount::new(&first_settings, "/first").unwrap();
    let reserved: Vec<_> = std::iter::once(first.path())
        .chain(first.discovery_paths())
        .collect();
    let mut second_settings = configuration("/second");
    Mount::new(&second_settings, "/second")
        .unwrap()
        .check_conflicts(&reserved)
        .unwrap();
    second_settings.protocol.protected_resource_identifier =
        first_settings.protocol.protected_resource_identifier;
    assert!(
        Mount::new(&second_settings, "/second")
            .unwrap()
            .check_conflicts(&reserved)
            .is_err()
    );
}

#[test]
fn exact_discovery_takes_precedence_over_the_host_ui_subtree() {
    let prefix = "/.well-known/oauth-protected-resource";
    let mut settings = configuration(prefix);
    settings.protocol.protected_resource_identifier = "https://issuer.example/ui/resource".into();
    let mount = Mount::new(&settings, prefix).unwrap();
    let discovery = format!("{prefix}/ui/resource");
    assert!(mount.owns_path(&discovery));
    assert!(mount.route_for_path(&discovery).is_some());
    assert!(mount.check_conflicts(&[&format!("{prefix}/ui")]).is_err());
}

#[test]
fn optional_credential_metadata_requires_both_registration_and_capability() {
    for enabled in [false, true] {
        for registered in [false, true] {
            let mut settings = configuration("/auth");
            settings.modules.enable_openid4vci_issuer = enabled;
            settings.modules.register_openid4vci_routes = registered;
            let mount = Mount::new(&settings, "/auth").unwrap();
            assert_eq!(
                mount
                    .route_for_path("/.well-known/openid-credential-issuer/auth")
                    .is_some(),
                enabled && registered
            );
            assert!(
                mount
                    .route_for_path("/auth/.well-known/openid-credential-issuer")
                    .is_none()
            );
        }
    }
}

#[test]
fn federation_callback_and_provider_start_url_follow_the_configured_issuer() {
    let mut settings = Configuration::new(
        nazo_identity::TenantContext::default_system(),
        "https://auth.example/tenant/auth",
        "client-secret-pepper-at-least-thirty-two-bytes",
    )
    .unwrap();
    let mut provider = serde_json::json!({
        "provider_id": "external", "enabled": true, "display_name": "External",
        "adapter_type": "oidc", "issuer": "https://identity.example",
        "discovery": true, "client_id": "client", "client_secret": "secret",
        "redirect_uri": "https://auth.example/tenant/auth/auth/federation/external/callback",
        "scopes": "openid profile"
    });
    settings.identity.federation.providers = crate::config::FederationProviderRegistry::from_json(
        &serde_json::json!([provider.clone()]).to_string(),
    )
    .unwrap();
    Mount::new(&settings, "/tenant/auth").unwrap();
    let configured = settings
        .identity
        .federation
        .providers
        .enabled_public_providers()
        .next()
        .unwrap();
    let view = crate::endpoints::auth::federation::provider_view(configured, "/tenant/auth");
    assert_eq!(
        view.start_url,
        "/tenant/auth/auth/federation/external/start"
    );
    provider["redirect_uri"] =
        serde_json::json!("https://auth.example/auth/federation/external/callback");
    settings.identity.federation.providers = crate::config::FederationProviderRegistry::from_json(
        &serde_json::json!([provider]).to_string(),
    )
    .unwrap();
    assert!(
        Mount::new(&settings, "/tenant/auth")
            .unwrap_err()
            .to_string()
            .contains("mounted callback")
    );
}
