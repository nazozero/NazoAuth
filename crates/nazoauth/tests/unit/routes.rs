use super::*;

#[test]
fn literal_resources_win_over_parameter_routes() {
    let templates = resolve(&Method::GET, "/admin/clients/templates").unwrap();
    assert_eq!(templates.method.endpoint, Endpoint::AdminClientTemplates);
    let events = resolve(&Method::GET, "/admin/runtime-modules/events").unwrap();
    assert_eq!(events.method.endpoint, Endpoint::AdminRuntimeModuleEvents);

    let path = "/admin/clients/client%2Fone";
    let client = resolve(&Method::GET, path).unwrap();
    assert_eq!(client.method.endpoint, Endpoint::AdminGetClient);
    assert_eq!(client.params.get("client_id"), Some("client%2Fone"));
    let capture = client.params.get("client_id").unwrap();
    assert_eq!(capture.as_ptr(), path[15..].as_ptr());
}

#[test]
fn routing_decodes_escaped_literals_without_changing_signed_target_or_separators() {
    let target = http::Uri::from_static("/%61uth/login?state=%2F&state=two");
    let path = routing_path(target.path());
    assert_eq!(
        resolve(&Method::POST, &path).unwrap().method.endpoint,
        Endpoint::Login
    );
    assert_eq!(target.to_string(), "/%61uth/login?state=%2F&state=two");
    for path in [
        "/auth/login",
        "/admin/clients/a%2Fb%25c%2Bd",
        "/admin/clients/a%XZ",
    ] {
        assert!(matches!(routing_path(path), Cow::Borrowed(_)));
    }
    assert_eq!(
        routing_path("/admin/%63lients/a%2fb%25c%2bd"),
        "/admin/clients/a%2fb%25c%2bd"
    );
    assert_eq!(
        routing_path("/admin/clients/%FF"),
        "/admin/clients/\u{fffd}"
    );
}

#[test]
fn scope_policies_and_control_precedence_apply_to_unknown_paths() {
    assert_eq!(
        unmatched_policy("/auth/me/missing"),
        (CorsPolicy::AuthApi, RouteGuard::None)
    );
    assert_eq!(
        unmatched_policy("/auth/meal"),
        (CorsPolicy::None, RouteGuard::None)
    );
    assert_eq!(
        unmatched_policy("/admin/openid4vci/missing"),
        (CorsPolicy::Admin, RouteGuard::Openid4vci)
    );
    assert_eq!(
        unmatched_policy("/admin/controller-registry/missing"),
        (CorsPolicy::Admin, RouteGuard::ControlTenant)
    );
    assert!(guard_precedes_cors("/.well-known/nazoauth-control"));
    assert!(guard_precedes_cors("/admin/controller-registry/missing"));
    assert!(!guard_precedes_cors(
        "/admin/tenants/tenant/users/user/admin"
    ));
    assert!(!guard_precedes_cors(
        "/.well-known/openid-credential-issuer"
    ));
}

#[test]
fn protected_resource_suffix_and_mdoc_issuer_capture_are_preserved() {
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/",
        "/.well-known/oauth-protected-resource/api/one",
    ] {
        assert_eq!(
            resolve(&Method::GET, path).unwrap().method.endpoint,
            Endpoint::OauthProtectedResourceMetadata,
        );
    }
    let crl = resolve(&Method::GET, "/.well-known/mdoc/issuer-a.crl").unwrap();
    assert_eq!(crl.method.endpoint, Endpoint::MdocCrl);
    assert_eq!(crl.params.get("issuer_id"), Some("issuer-a"));
    assert_eq!(
        resolve(&Method::GET, "/.well-known/mdoc/issuer-a")
            .unwrap_err()
            .status(),
        StatusCode::NOT_FOUND,
    );
}

#[test]
fn controller_slot_list_has_one_control_tenant_route_and_no_admin_get_alias() {
    let control = resolve(&Method::GET, "/controller-registry/slots").unwrap();
    assert_eq!(control.method.endpoint, Endpoint::ControllerSlots);
    assert_eq!(control.route.guard, RouteGuard::ControlTenant);

    let old_admin_get = resolve(&Method::GET, "/admin/controller-registry/slots").unwrap_err();
    assert_eq!(old_admin_get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(old_admin_get.headers().get(header::ALLOW).unwrap(), "POST");
}

#[test]
fn retired_bootstrap_admin_endpoint_stays_unreachable() {
    for method in [Method::GET, Method::POST] {
        assert_eq!(
            resolve(&method, "/bootstrap-admin").unwrap_err().status(),
            StatusCode::NOT_FOUND,
        );
    }
}

#[test]
fn retired_perf_collection_endpoint_is_unreachable() {
    assert_eq!(
        resolve(&Method::GET, "/__perf/metrics")
            .unwrap_err()
            .status(),
        StatusCode::NOT_FOUND,
    );
}

#[test]
fn known_path_method_rejections_preserve_allow_and_do_not_invent_head() {
    let wrong = resolve(&Method::PATCH, "/userinfo").unwrap_err();
    assert_eq!(wrong.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong.headers().get(header::ALLOW).unwrap(), "GET, POST");
    let head = resolve(&Method::HEAD, "/.well-known/openid-configuration").unwrap_err();
    assert_eq!(head.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(head.headers().get(header::ALLOW).unwrap(), "GET");
}

#[test]
fn mfa_options_and_rejections_keep_their_protocol_response() {
    for path in [
        "/auth/mfa/verify",
        "/auth/me/mfa/totp/begin",
        "/auth/me/mfa/totp/confirm",
        "/auth/me/mfa/step-up",
        "/auth/me/mfa/backup-codes/regenerate",
        "/auth/me/mfa/disable",
    ] {
        assert_eq!(
            resolve(&Method::OPTIONS, path).unwrap().method.endpoint,
            Endpoint::MfaOptions
        );
        let wrong = resolve(&Method::GET, path).unwrap_err();
        assert_eq!(wrong.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            wrong.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(wrong.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert!(!wrong.headers().contains_key(header::ALLOW));
        let body: serde_json::Value = serde_json::from_slice(wrong.body()).unwrap();
        assert_eq!(body["error"], "invalid_request");
        assert_eq!(body["error_description"], "HTTP method is not allowed.");
    }
}

#[test]
fn body_budgets_follow_the_actual_extractor_and_stream_contracts() {
    let body = |method, path| resolve(&method, path).unwrap().method.body;
    assert_eq!(body(Method::POST, "/token").limit(), Some(256 * 1024));
    assert_eq!(
        body(Method::POST, "/authorize/decision").limit(),
        Some(32 * 1024)
    );
    assert_eq!(
        body(Method::POST, "/register").limit(),
        Some(2 * 1024 * 1024)
    );
    assert_eq!(
        body(Method::PUT, "/register/client-a").limit(),
        Some(2 * 1024 * 1024)
    );
    assert_eq!(
        body(Method::POST, "/.well-known/nazoauth-control").limit(),
        Some(2 * 1024)
    );
    assert_eq!(
        body(Method::POST, "/controller-recovery/recover").limit(),
        Some(8 * 1024)
    );
    for path in ["/bc-authorize", "/logout"] {
        let raw = body(Method::POST, path);
        assert_eq!(raw.limit(), Some(16 * 1024));
        assert!(!raw.decode_content());
    }
    assert_eq!(body(Method::GET, "/logout"), BodyMode::None);
    assert_eq!(body(Method::POST, "/auth/me/avatar"), BodyMode::Multipart);
    assert_eq!(body(Method::POST, "/auth/me/avatar").limit(), None);
}

#[test]
fn only_public_metadata_resources_can_omit_connection_facts() {
    const METADATA_PATHS: [&str; 6] = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/",
        "/.well-known/oauth-protected-resource/{*tail}",
        "/jwks.json",
    ];
    let without_facts = routes()
        .iter()
        .filter(|route| !route.needs_connection_facts())
        .map(|route| route.path)
        .collect::<Vec<_>>();
    assert_eq!(without_facts, METADATA_PATHS);
    let projected_headers = routes()
        .iter()
        .filter_map(|route| {
            route.request_headers().map(|headers| {
                assert_eq!(
                    headers,
                    [
                        header::ORIGIN,
                        header::ACCESS_CONTROL_REQUEST_METHOD,
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                    ]
                );
                route.path
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(projected_headers, METADATA_PATHS);
    assert_eq!(
        routes()
            .iter()
            .filter(|route| route.needs_nonce_admission())
            .map(|route| route.path)
            .collect::<Vec<_>>(),
        ["/openid4vci/nonce"]
    );

    // This resource has no body, but its IP budget precedes method rejection.
    let nonce = match_path("/openid4vci/nonce").unwrap().0;
    assert_eq!(nonce.body(&Method::GET), BodyMode::None);
    assert_eq!(
        nonce.resolve_method(&Method::GET).unwrap_err().status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert!(nonce.needs_connection_facts());
    assert!(nonce.request_headers().is_none());
    assert!(nonce.needs_nonce_admission());
}

#[test]
fn optional_protocols_keep_independent_registration_guards() {
    for path in [
        "/.well-known/openid-credential-issuer",
        "/openid4vci/nonce",
        "/admin/openid4vci/credential-datasets/subject/configuration",
    ] {
        assert_eq!(match_path(path).unwrap().0.guard, RouteGuard::Openid4vci);
    }
    assert_eq!(
        match_path("/openid4vp/presentations").unwrap().0.guard,
        RouteGuard::Openid4vp
    );
    assert_eq!(
        match_path("/admin/users").unwrap().0.guard,
        RouteGuard::None
    );
    assert_eq!(
        match_path("/admin/runtime-modules").unwrap().0.guard,
        RouteGuard::None
    );
}
