use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use super::*;

use crate::config::ConfigSource;
use nazo_oauth_server::token::device_issuance::token_device_code_with_service;

use crate::http::token::{TokenForm, device_config::DeviceHttpConfig};
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;
use actix_web::test::TestRequest;
use chrono::Duration;
use chrono::Utc;
use diesel::sql_query;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike as _;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_identity::DEFAULT_ORGANIZATION_ID;
use nazo_identity::DEFAULT_REALM_ID;
use nazo_identity::DEFAULT_TENANT_ID;
use nazo_oauth_server::domain::rows::ClientRow;
use nazo_oauth_server::rate_limit::TokenManagementRequestLimiter;
use nazo_oauth_server::services::ServerDeviceGrantService;
use nazo_oauth_server::services::ServerTokenService;
use nazo_oauth_server::token::DEVICE_CODE_GRANT_TYPE;
use nazo_oauth_server::token::issue::TokenIssuanceContext;
use nazo_postgres::{create_pool, get_conn};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;

use crate::test_support::valkey::valkey_set_ex;

fn device_grant_service(state: &TestInfrastructure) -> Data<ServerDeviceGrantService> {
    Data::new(ServerDeviceGrantService::new(std::sync::Arc::new(
        nazo_valkey::DeviceStore::new(&state.valkey_connection()),
    )))
}

fn token_management_limiter(state: &TestInfrastructure) -> Data<TokenManagementRequestLimiter> {
    let rate_limit = &state.settings.identity.rate_limit;
    Data::new(TokenManagementRequestLimiter::new(
        std::sync::Arc::new(nazo_valkey::RateLimitStore::new(&state.valkey_connection())),
        rate_limit.window_seconds,
        rate_limit.token_management_max_requests,
    ))
}

fn decision_handles(
    state: &TestInfrastructure,
    device_service: Arc<ServerDeviceGrantService>,
    runtime: Arc<nazo_runtime_modules::SnapshotStore>,
) -> Data<DeviceDecisionHandles> {
    Data::new(DeviceDecisionHandles::new(
        Arc::new(crate::http::token::issue::test_support::test_authorization_service(state)),
        device_service,
        Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            DEFAULT_TENANT_ID,
        )),
        Arc::new(
            crate::http::token::device_config::device_config_from_settings(state.settings.as_ref()),
        ),
        runtime,
        Arc::new(
            crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                .expect("empty resolver should build"),
        ),
        token_management_limiter(state).into_inner(),
        Arc::new(crate::adapters::audit::TenantSecurityAudit::new(
            state.settings.tenant.context.tenant_id,
        )),
    ))
}

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

fn device_client() -> ClientRow {
    let mut client = client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "device-client".to_owned(),
        client_name: "Device Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "profile", "offline_access"]),
        allowed_audiences: json!(["resource://default", "https://api.example.com"]),
        grant_types: json!([DEVICE_CODE_GRANT_TYPE]),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        is_active: true,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    };
    client.security_policy.allow_cross_device_flows = true;
    client
}

fn device_settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.device.device_authorization_ttl_seconds = 600;
    settings.device.device_authorization_poll_interval_seconds = 5;
    settings
}

fn disabled_state() -> TestInfrastructure {
    state_with_settings(Settings::from_config(&ConfigSource::default()).expect("settings"))
}

fn state_with_settings(settings: Settings) -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_device_test_invalid:nazo_device_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn device_token_form(device_code: Option<&str>) -> TokenForm {
    TokenForm {
        grant_type: DEVICE_CODE_GRANT_TYPE.to_owned(),
        code: None,
        device_code: device_code.map(ToOwned::to_owned),
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("device-client".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

async fn live_device_replay_state() -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut valkey = ValkeyBuilder::from_config(
        ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
    );
    valkey.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    valkey.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = valkey.build().expect("device test Valkey should build");
    valkey
        .init()
        .await
        .expect("device test Valkey should connect");

    Some(TestInfrastructure {
        diesel_db: create_pool(database_url, 2).expect("device test database should build"),
        valkey,
        settings: Arc::new(device_settings()),
        keyset: crate::test_support::test_key_manager(),
    })
}

async fn insert_device_user(state: &TestInfrastructure, user_id: Uuid) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("device test database connection should be available");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("device test user cleanup should succeed");
    sql_query(
        "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash,\
            is_active, mfa_enabled, email_verified, role, admin_level\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, FALSE, TRUE, 'user', 0)",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("device-user-{user_id}"))
    .bind::<Text, _>(format!("device-user-{user_id}@example.test"))
    .bind::<Text, _>("device-test-password-hash")
    .execute(&mut connection)
    .await
    .expect("device test user should insert");
}

async fn store_device_session(state: &TestInfrastructure, session_id: &str, user_id: Uuid) {
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id,
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("device-oidc-{session_id}")),
    };
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{session_id}")),
        serde_json::to_string(&payload).expect("device session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("device session should store");
}

async fn call_device_token_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    device_code: &str,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
        state.keyset.clone(),
    );
    let issuance_config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(state);
    let issuance = TokenIssuanceContext {
        config: &issuance_config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    let device_service = ServerDeviceGrantService::new(std::sync::Arc::new(
        nazo_valkey::DeviceStore::new(&connection),
    ));
    let request = TestRequest::post().uri("/token").to_http_request();
    crate::http::token::issue::test_support::present_token_result(
        token_device_code_with_service(
            &token_service,
            &issuance,
            &device_service,
            &crate::http::token::issue::test_support::token_request_facts(
                &request,
                state.settings.as_ref(),
            ),
            client,
            &device_token_form(Some(device_code)),
            None,
        )
        .await,
    )
}

#[test]
fn device_authorization_form_parses_scope_resource_and_auth_fields() {
    let req = form_request();

    let form = parse_device_authorization_form(
        &req,
        &Bytes::from_static(
            b"client_id=device-client&scope=openid%20profile&resource=https%3A%2F%2Fapi.example.com&client_secret=secret",
        ),
    )
    .expect("device authorization request should parse");

    assert_eq!(form.client_id.as_deref(), Some("device-client"));
    assert_eq!(form.scope.as_deref(), Some("openid profile"));
    assert_eq!(form.resources, vec!["https://api.example.com"]);
    assert_eq!(form.client_secret.as_deref(), Some("secret"));
}

#[test]
fn device_authorization_form_rejects_transport_and_parameter_boundary_violations() {
    let wrong_content_type = TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    assert!(matches!(
        parse_device_authorization_form(&wrong_content_type, &Bytes::from_static(b"{}")),
        Err(DeviceAuthorizationFormError::InvalidContentType)
    ));

    let valid_request = form_request();
    assert!(matches!(
        parse_device_authorization_form(&valid_request, &Bytes::from_static(b"\xff")),
        Err(DeviceAuthorizationFormError::InvalidEncoding)
    ));
    assert!(matches!(
        parse_device_authorization_form(
            &valid_request,
            &Bytes::from_static(b"client_id=one&client_id=two"),
        ),
        Err(DeviceAuthorizationFormError::DuplicateParameter)
    ));
    assert!(matches!(
        parse_device_authorization_form(
            &valid_request,
            &Bytes::from_static(b"client_id=one&resource=https%3A%2F%2Fapi.example%2F%23fragment"),
        ),
        Err(DeviceAuthorizationFormError::InvalidResourceParameter)
    ));
}

#[test]
fn device_authorization_verification_uri_targets_frontend_device_page() {
    let mut settings = device_settings();
    settings.endpoint.frontend_base_url = "https://auth.example.test/ui/".to_owned();

    assert_eq!(
        device_verification_uri(&DeviceHttpConfig::from(&settings)),
        "https://auth.example.test/ui/device"
    );
}

#[actix_web::test]
async fn legacy_device_verification_path_redirects_to_frontend_without_html() {
    let config = DeviceHttpConfig::from(&device_settings());
    let response = redirect_to_device_verification_ui(&config, "ABCD 1234");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://127.0.0.1:8000/ui/device?user_code=ABCD%201234"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[actix_web::test]
async fn device_authorization_endpoint_disabled_fails_before_client_lookup() {
    let state = Data::new(disabled_state());
    let req = form_request();

    let runtime =
        crate::runtime_modules::test_support::runtime_module_registry_with_modules_for_test(
            state.diesel_db.clone(),
            state.settings.as_ref(),
            Default::default(),
        )
        .expect("disabled runtime should build");
    let response = device_authorization(
        decision_handles(
            &state,
            device_grant_service(&state).into_inner(),
            runtime.snapshot_store(),
        ),
        Data::new(DeviceHttpConfig::from(state.settings.as_ref())),
        req,
        Bytes::from_static(b"client_id=device-client&scope=openid"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn device_denial_consumes_pending_request_after_audited_user_decision() {
    let Some(state) = live_device_replay_state().await else {
        return;
    };
    let user_id = Uuid::now_v7();
    insert_device_user(&state, user_id).await;
    let session_id = format!("device-session-{}", Uuid::now_v7());
    store_device_session(&state, &session_id, user_id).await;

    let now = Utc::now();
    let payload = DeviceAuthorizationPayload {
        client_id: "device-client".to_owned(),
        client_name: "Device Client".to_owned(),
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        interval_seconds: 5,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
    };
    let device_service = ServerDeviceGrantService::new(std::sync::Arc::new(
        nazo_valkey::DeviceStore::new(&state.valkey_connection()),
    ));
    let device_code = format!("device-code-{}", Uuid::now_v7());
    let user_code = format!("DEVICE-{}", Uuid::now_v7().simple());
    let (_, stored_user_code) = device_service
        .create_unique(&payload, 600, || device_code.clone(), || user_code.clone())
        .await
        .expect("device request should be stored");

    // Install the durable audit dependency before entering the required-intent
    // boundary.  The decision must not mutate Valkey until this succeeds.
    crate::test_support::token_issuance_repository(state.diesel_db.clone());
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        state.settings.as_ref(),
    )
    .expect("device runtime registry should initialize");
    let handles = decision_handles(&state, Arc::new(device_service), runtime.snapshot_store());
    let sessions = Data::new(crate::http::sessions::test_support::profile_session_handles(&state));
    let config = Data::new(DeviceHttpConfig::from(state.settings.as_ref()));
    let request = TestRequest::post()
        .uri("/device/decision")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            session_id,
        ))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            "device-csrf",
        ))
        .to_http_request();

    let response = device_decision(
        handles,
        sessions,
        config,
        request,
        actix_web::web::Form(DeviceDecisionForm {
            user_code: stored_user_code.clone(),
            decision: "deny".to_owned(),
            csrf_token: Some("device-csrf".to_owned()),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let state_after = ServerDeviceGrantService::new(std::sync::Arc::new(
        nazo_valkey::DeviceStore::new(&state.valkey_connection()),
    ));
    assert!(
        state_after
            .pending_request_for_user_code(&stored_user_code, Utc::now)
            .await
            .expect("device decision state should be readable")
            .is_none()
    );
}

#[actix_web::test]
async fn device_token_rejects_client_policy_before_polling_state() {
    let state = Data::new(state_with_settings(device_settings()));
    let mut client = device_client();
    client.security_policy = nazo_auth::ClientSecurityPolicy {
        allow_cross_device_flows: false,
        ..nazo_auth::ClientSecurityPolicy::default()
    };
    let connection = state.valkey_connection();
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
        state.keyset.clone(),
    );
    let issuance_config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(&state);
    let issuance = TokenIssuanceContext {
        config: &issuance_config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    let form = device_token_form(Some("not-stored"));
    let request = TestRequest::post().uri("/token").to_http_request();

    let response = crate::http::token::issue::test_support::present_token_result(
        token_device_code_with_service(
            &token_service,
            &issuance,
            &device_grant_service(&state),
            &crate::http::token::issue::test_support::token_request_facts(
                &request,
                state.settings.as_ref(),
            ),
            &client,
            &form,
            None,
        )
        .await,
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "unauthorized_client");
}

#[actix_web::test]
async fn device_code_replay_rejects_a_consumed_code_even_with_a_persisted_response() {
    let Some(state) = live_device_replay_state().await else {
        return;
    };
    let mut client = device_client();
    client.client_id = format!("device-persisted-replay-{}", client.id);
    let device_code = format!("device-replay-{}", Uuid::now_v7());
    let grant_key = format!(
        "device_code:{}::",
        nazo_oauth_server::crypto::blake3_hex(&device_code)
    );

    crate::http::token::issue::tests::persist_token_issuance_response_for_test(
        &state, &client, &grant_key,
    )
    .await;

    let response = call_device_token_for_test(&state, &client, &device_code).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_grant");
}

#[actix_web::test]
async fn device_http_boundaries_preserve_validation_csrf_and_verification_representation() {
    let Some(state) = live_device_replay_state().await else {
        return;
    };
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        state.settings.as_ref(),
    )
    .unwrap();
    let handles = decision_handles(
        &state,
        device_grant_service(&state).into_inner(),
        runtime.snapshot_store(),
    );
    let config = Data::new(DeviceHttpConfig::from(state.settings.as_ref()));
    let sessions = Data::new(crate::http::sessions::test_support::profile_session_handles(&state));
    for (content_type, body, expected) in [
        (
            "application/json",
            Bytes::from_static(b"{}"),
            "invalid_request",
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(&[255]),
            "invalid_request",
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"client_id=a&client_id=b"),
            "invalid_request",
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"resource=relative"),
            "invalid_target",
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"scope=openid"),
            "invalid_request",
        ),
        (
            "application/x-www-form-urlencoded",
            Bytes::from_static(b"client_id=unknown-device-boundary-client"),
            "invalid_client",
        ),
    ] {
        let request = TestRequest::post()
            .insert_header((header::CONTENT_TYPE, content_type))
            .to_http_request();
        let response = device_authorization(handles.clone(), config.clone(), request, body).await;
        assert_eq!(oauth_error_code(response).await, expected);
    }
    let response = device_verification_page(
        handles.clone(),
        config.clone(),
        Query(HashMap::from([("user_code".into(), "ABCD 1234".into())])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("?user_code=ABCD%201234")
    );
    let response = device_verification(
        handles.clone(),
        sessions.clone(),
        TestRequest::get()
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.csrf_cookie_name.clone(),
                "csrf-probe",
            ))
            .to_http_request(),
        Query(HashMap::from([("user_code".into(), "not-found".into())])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["csrf_token"], "csrf-probe");
    assert!(body["request"].is_null());
    for session_cookie in [false, true] {
        let mut request = TestRequest::post();
        if session_cookie {
            request = request.cookie(actix_web::cookie::Cookie::new(
                state.settings.session.session_cookie_name.clone(),
                "unused-session",
            ));
        }
        let response = device_decision(
            handles.clone(),
            sessions.clone(),
            config.clone(),
            request.to_http_request(),
            Form(DeviceDecisionForm {
                user_code: "unused".into(),
                decision: "approve".into(),
                csrf_token: None,
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            if session_cookie {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(
            oauth_error_code(response).await,
            if session_cookie {
                "invalid_request"
            } else {
                "login_required"
            }
        );
    }
}
