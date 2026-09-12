#[test]
fn token_management_request_facts_preserve_the_exact_endpoint_path() {
    let settings = crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    let extractor = super::ServerTokenManagementRequestFactsExtractor::new(
        nazo_http_actix::ClientIpConfig::new(
            &settings.endpoint.trusted_proxy_cidrs,
            settings.endpoint.client_ip_header_mode,
        ),
    );
    let request = actix_web::test::TestRequest::post()
        .uri("/introspect")
        .peer_addr("203.0.113.9:443".parse().unwrap())
        .to_http_request();
    let facts =
        nazo_http_actix::TokenManagementRequestFactsExtractor::extract(&extractor, &request);
    assert_eq!(facts.endpoint_path, "/introspect");
    assert_eq!(facts.source_ip, "203.0.113.9");
    assert!(facts.client_certificate.is_none());
}

fn function_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let source = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing boundary start {start}"))
        .1;
    if end.is_empty() {
        return source;
    }
    source
        .split_once(end)
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("missing boundary end {end}"))
}

#[test]
fn production_token_dispatch_and_grants_do_not_receive_app_state() {
    let dispatch = include_str!("../../../../src/http/token/dispatch/mod.rs");
    let dispatch = function_body(
        dispatch,
        "pub(crate) async fn token_with_service(",
        "pub(crate) use token_with_service as token;",
    );
    assert_eq!(
        include_str!("../../../../src/http/token/dispatch/mod.rs")
            .matches("pub(crate) use token_with_service as token;")
            .count(),
        1,
        "token dispatch must expose exactly one production entry point"
    );
    for forbidden in [
        "Data<TestInfrastructure>",
        "state.settings",
        "state.diesel_db",
        "state.valkey_connection()",
        "TokenIssuanceRepository::new",
        "AuthorizationStore::new",
        "ReplayStore::new",
    ] {
        assert!(
            !dispatch.contains(forbidden),
            "production token dispatch reintroduced {forbidden}"
        );
    }

    for (name, source, start, end) in [
        (
            "authorization_code",
            include_str!("../../../../../authorization-server/src/token/authorization_code.rs"),
            "pub async fn token_authorization_code_with_service(",
            "pub fn validate_pending_authorization_code_request(",
        ),
        (
            "refresh_token",
            include_str!("../../../../../authorization-server/src/token/refresh.rs"),
            "pub async fn token_refresh_with_service(",
            "",
        ),
        (
            "native_sso",
            include_str!("../../../../../authorization-server/src/token/native_sso.rs"),
            "pub async fn token_native_sso_exchange(",
            "",
        ),
        (
            "ciba",
            include_str!("../../../../../authorization-server/src/token/ciba/poll.rs"),
            "pub async fn token_ciba(",
            "fn ciba_auth_req_id_client_error(",
        ),
    ] {
        let body = function_body(source, start, end);
        for forbidden in [
            "TestInfrastructure",
            "state.settings",
            "state.diesel_db",
            "state.valkey_connection()",
            "TokenRepository::new",
            "TokenStateStore::new",
            "ReplayStore::new",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} production grant reintroduced {forbidden}"
            );
        }
    }
}

#[test]
fn userinfo_transport_does_not_construct_storage_adapters() {
    let source = include_str!("../../../../../http-actix/src/userinfo.rs");
    assert!(source.contains("endpoint: Data<UserinfoEndpoint>"));
    for forbidden in [
        "Data<TestInfrastructure>",
        "Settings",
        "KeyManager",
        "nazo_postgres",
        "nazo_valkey",
        "diesel_db",
        "TokenRepository::new",
        "OAuthClientRepository::new",
        "UserRepository::new",
        "TokenStateStore::new",
    ] {
        assert!(
            !source.contains(forbidden),
            "userinfo handler reintroduced forbidden dependency {forbidden}"
        );
    }
}

#[test]
fn client_authentication_handlers_use_the_focused_authorization_boundary() {
    for (name, source) in [
        (
            "token",
            include_str!("../../../../src/http/token/dispatch/mod.rs"),
        ),
        ("ciba", include_str!("../../../../src/http/token/ciba.rs")),
        (
            "device",
            include_str!("../../../../src/http/token/device.rs"),
        ),
        (
            "par",
            include_str!("../../../../src/http/authorization/par.rs"),
        ),
    ] {
        assert!(
            !source.contains("OAuthClientRepository::new"),
            "{name} reintroduced a direct PostgreSQL client-auth dependency"
        );
    }
    let auth_source = include_str!("../../../../../authorization-server/src/token/client_auth.rs");
    for forbidden in [
        "match client.token_endpoint_auth_method.as_str()",
        ".expect(\"private_key_jwt",
        ".expect(\"secret-based client credentials",
        ".expect(\"mTLS client credentials",
    ] {
        assert!(
            !auth_source.contains(forbidden),
            "client authentication adapter reintroduced policy or panic: {forbidden}"
        );
    }
}

#[test]
fn ciba_transport_uses_composition_root_handles() {
    let source = include_str!("../../../../src/http/token/ciba.rs");
    for forbidden in [
        "CibaStore::new",
        "OAuthClientRepository::new",
        "UserRepository::new",
        "state.diesel_db",
        "state.valkey_connection()",
    ] {
        assert!(
            !source.contains(forbidden),
            "CIBA transport reintroduced composition dependency {forbidden}"
        );
    }
    assert!(!source.contains(
        "pub(crate) async fn backchannel_authentication(\n    state: Data<TestInfrastructure>"
    ));
    assert!(
        !source.contains(
            "pub(crate) async fn ciba_verification(\n    state: Data<TestInfrastructure>"
        )
    );
}

#[test]
fn shared_issuance_core_uses_typed_context_and_existing_service() {
    let source = include_str!("../../../../../authorization-server/src/token/issue_grant.rs");
    let core = source
        .split("pub async fn issue_token_response(")
        .nth(1)
        .and_then(|source| source.split("#[cfg(test)]").next())
        .expect("issuance core must precede test-only fixture adapters");
    for forbidden in [
        "TestInfrastructure",
        "state.settings",
        "state.diesel_db",
        "state.valkey_connection",
        "TokenIssuanceRepository::new",
        "TokenIssuanceStateAdapter::new",
    ] {
        assert!(
            !core.contains(forbidden),
            "shared issuance core reintroduced {forbidden}"
        );
    }
}

#[test]
fn device_transport_uses_focused_composition_root_dependencies() {
    let source = include_str!("../../../../src/http/token/device.rs");
    for forbidden in [
        "Data<TestInfrastructure>",
        "Settings",
        "DeviceStore::new",
        "AuthorizationFlowRepository::new",
        "state.diesel_db",
        "state.valkey_connection()",
    ] {
        assert!(
            !source.contains(forbidden),
            "device transport reintroduced composition dependency {forbidden}"
        );
    }
    for required in [
        "Data<DeviceDecisionHandles>",
        "Data<DeviceHttpConfig>",
        "Data<SessionProfileHandles>",
        "handles.enforce_creation_rate_limit(&source_ip)",
        "handles.check_admission(",
        ".create(prepared, credentials, auth_request, &source_ip)",
        ".decide(&form.user_code, &form.decision, session, &source_ip)",
        "sessions.current_session_or_login_required(&req)",
    ] {
        assert!(
            source.contains(required),
            "device transport lost focused dependency {required}"
        );
    }
    let application = include_str!("../../../../../authorization-server/src/token/device.rs");
    for required in [
        "device_service: Arc<ServerDeviceGrantService>",
        "runtime: Arc<SnapshotStore>",
        "limiter: Arc<TokenManagementRequestLimiter>",
        "grant_repository: Arc<dyn DeviceGrantRepositoryPort>",
        "session: CurrentSession",
    ] {
        assert!(
            application.contains(required),
            "device application lost owned capability {required}"
        );
    }
    for forbidden in [
        "Data<ServerDeviceGrantService>",
        "Data<TokenManagementRequestLimiter>",
        "Data<ServerRuntimeModuleRegistry>",
    ] {
        assert!(
            !source.contains(forbidden),
            "device transport reclaimed application capability {forbidden}"
        );
    }
}

#[test]
fn ciba_decision_transport_uses_focused_composition_root_dependencies() {
    let source = [
        include_str!("../../../../src/http/token/ciba.rs"),
        include_str!("../../../../src/http/token/ciba/decision.rs"),
        include_str!("../../../../../authorization-server/src/token/ciba/poll.rs"),
    ]
    .concat();
    for forbidden in [
        "Data<TestInfrastructure>",
        "state.permits_existing_module_transaction",
        "client_ip(&req, &state.settings)",
        "has_valid_csrf_token(&state",
        "current_user_or_login_required(&state",
    ] {
        assert!(
            !source.contains(forbidden),
            "CIBA decision transport reintroduced composition dependency {forbidden}"
        );
    }
    for required in [
        "Data<CibaApplication>",
        "Data<AdminSessionHandles>",
        "Data<ClientIpConfig>",
        "application.check_admission(",
        "application.verification(&auth_req_id, &session)",
        "sessions.current_session_or_login_required(&req)",
        "has_valid_csrf_token_for_cookies(",
        "client_ip_with_config(&req, &client_ip)",
    ] {
        assert!(
            source.contains(required),
            "CIBA decision transport lost focused dependency {required}"
        );
    }
    let application =
        include_str!("../../../../../authorization-server/src/token/ciba/application.rs");
    for required in [
        "handles: Arc<CibaTokenHandles>",
        "snapshots: Arc<nazo_runtime_modules::SnapshotStore>",
        "security_audit: Arc<dyn SecurityAudit>",
    ] {
        assert!(
            application.contains(required),
            "CIBA application lost owned capability {required}"
        );
    }
    let decision = include_str!("../../../../../authorization-server/src/token/ciba/decision.rs");
    assert!(decision.contains("session: &CurrentSession"));
    assert!(decision.contains("expected_user_id: Some(session.user.id())"));
    for forbidden in [
        "Data<ServerCibaService>",
        "Data<CibaConfig>",
        "Data<ServerRuntimeModuleRegistry>",
    ] {
        assert!(
            !source.contains(forbidden),
            "CIBA transport reclaimed application capability {forbidden}"
        );
    }
}

#[test]
fn device_token_issuance_handoff_uses_focused_context_and_services() {
    let source = include_str!("../../../../../authorization-server/src/token/device_issuance.rs");
    assert!(source.contains("device_service: &ServerDeviceGrantService"));
    assert!(source.contains("token_service: &ServerTokenService"));
    assert!(source.contains("issuance: &TokenIssuanceContext<'_>"));
    assert!(source.contains("issue_token_response("));
    assert!(source.contains("validate_token_sender_constraints"));
    assert!(source.contains("consume_token_client_assertion_with_authorization_service"));
    for forbidden in [
        "TestInfrastructure",
        "Settings",
        "state.settings",
        "DeviceStore::new",
        "DeviceGrantService::new",
        "TokenIssuanceRepository::new",
        "TokenIssuanceStateAdapter::new",
        "nazo_postgres",
        "nazo_valkey",
    ] {
        assert!(
            !source.contains(forbidden),
            "device issuance handoff reintroduced direct infrastructure {forbidden}"
        );
    }
}
