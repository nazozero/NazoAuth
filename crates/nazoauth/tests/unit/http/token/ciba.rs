async fn load_ciba_request_payload(
    service: &ServerCibaService,
    id: &str,
) -> Result<Option<CibaRequestState>, CibaStatePortError> {
    service
        .load(id)
        .await
        .map(|stored| stored.map(|stored| stored.into_state()))
}
fn configure_ciba_test_app(
    cfg: &mut actix_web::web::ServiceConfig,
    state: &TestInfrastructure,
    runtime: &crate::runtime_modules::ServerRuntimeModuleRegistry,
) {
    let application = nazo_oauth_server::token::ciba::CibaApplication::new(
        Arc::new(super::super::issue::test_support::test_authorization_service(state)),
        Arc::new(CibaTokenHandles::new(
            Arc::new(ServerCibaService::new(Arc::new(CibaStore::new(
                &state.valkey_connection(),
            )))),
            Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            Arc::new(ciba_config(state.settings.as_ref())),
        )),
        crate::test_support::test_remote_client_documents_data().into_inner(),
        runtime.snapshot_store(),
        crate::http::authorization::test_support::test_security_audit_arc(),
    );
    cfg.app_data(actix_web::web::Data::new(application))
        .app_data(actix_web::web::Data::new(
            crate::http::sessions::test_support::admin_session_handles(state),
        ))
        .app_data(actix_web::web::Data::new(
            nazo_http_actix::ClientIpConfig::new(
                &state.settings.endpoint.trusted_proxy_cidrs,
                state.settings.endpoint.client_ip_header_mode,
            ),
        ));
}
use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use crate::test_support::TestInfrastructure;

use nazo_identity::DEFAULT_ORGANIZATION_ID;
use nazo_identity::DEFAULT_REALM_ID;

use super::request::parse_backchannel_authentication_form;

use super::state::ciba_config;
use crate::config::ConfigSource;
use crate::settings::Settings;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
};
use chrono::Utc;
use nazo_auth::{
    CibaAuthenticationContext, CibaRequestState, CibaStatePortError, CibaStatus,
    ValidatedClientAssertion,
};
use nazo_identity::DEFAULT_TENANT_ID;
use nazo_oauth_server::{
    contracts::token_forms::TokenForm,
    domain::rows::ClientRow,
    services::{ServerCibaService, ServerTokenService},
    token::{
        ciba::{
            CIBA_GRANT_TYPE,
            poll::token_ciba,
            state::{CibaTokenContext, CibaTokenHandles, ciba_grant_key},
        },
        issue::TokenIssuanceContext,
    },
};
use nazo_postgres::{create_pool, get_conn};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use crate::test_support::valkey::valkey_set_ex;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use std::sync::{Arc, OnceLock};
use std::time::Duration as StdDuration;

fn ciba_test_state_with(configure: impl FnOnce(&mut Settings)) -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    configure(&mut settings);
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_ciba_test_invalid:nazo_ciba_test_invalid@127.0.0.1:1/nazo".to_owned(),
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

fn ciba_test_state() -> TestInfrastructure {
    ciba_test_state_with(|_| {})
}

async fn live_ciba_replay_state() -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let valkey = live_test_valkey().await?;
    let mut settings = Settings::from_config(&ConfigSource::default())
        .expect("default CIBA test settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    Some(TestInfrastructure {
        diesel_db: create_pool(database_url, 2).expect("CIBA test database should build"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

async fn live_test_valkey() -> Option<nazo_valkey::test_support::Client> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    Some(
        nazo_valkey::test_support::connect(&valkey_url, StdDuration::from_secs(1))
            .await
            .expect("VALKEY_URL should point to a reachable test Valkey instance"),
    )
}

fn ciba_token_form(auth_req_id: String) -> TokenForm {
    TokenForm {
        grant_type: CIBA_GRANT_TYPE.to_owned(),
        code: None,
        device_code: None,
        auth_req_id: Some(auth_req_id),
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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

async fn store_ciba_state(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: &str,
    status: CibaStatus,
) {
    store_ciba_state_with_user(state, client, auth_req_id, Uuid::now_v7(), status).await;
}

async fn store_ciba_state_with_user(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: &str,
    user_id: Uuid,
    status: CibaStatus,
) {
    let now = Utc::now().timestamp();
    let authentication_context = match status {
        CibaStatus::Approved => Some(CibaAuthenticationContext {
            auth_time: now,
            amr: vec!["pwd".to_owned()],
            oidc_sid: Some(format!("ciba-test-session-{user_id}")),
        }),
        CibaStatus::Pending | CibaStatus::Denied => None,
    };
    CibaStore::new(&state.valkey_connection())
        .create(
            auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id,
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context,
                binding_message: None,
                issued_at: now,
                status,
                interval_seconds: 5,
                expires_at: now + 600,
                retention_expires_at: now + 720,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("CIBA state should be stored");
}

async fn persist_ciba_test_client(state: &TestInfrastructure, client: &ClientRow) {
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .upsert(client, None)
        .await
        .expect("CIBA test client should be persisted");
}

async fn insert_ciba_user(state: &TestInfrastructure, user_id: Uuid) {
    insert_ciba_user_with_email(state, user_id, &format!("ciba-user-{user_id}@example.test")).await;
}

async fn insert_ciba_user_with_email(state: &TestInfrastructure, user_id: Uuid, email: &str) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("CIBA test database connection should be available");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("CIBA test user cleanup should succeed");
    sql_query(
        "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash,\
            is_active, mfa_enabled, email_verified, role, admin_level\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, TRUE, 'user', 0)",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("ciba-user-{user_id}"))
    .bind::<Text, _>(email.to_owned())
    .bind::<Text, _>("ciba-test-password-hash")
    .bind::<Bool, _>(true)
    .execute(&mut connection)
    .await
    .expect("CIBA test user should insert");
}

async fn store_ciba_session(state: &TestInfrastructure, sid: &str, user_id: Uuid) {
    let payload = nazo_oauth_server::sessions::SessionPayload {
        user_id,
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
        serde_json::to_string(&payload).expect("CIBA session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("CIBA session should store");
}

async fn call_ciba_token_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: String,
) -> HttpResponse {
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    call_ciba_token_with_request_for_test(state, client, auth_req_id, req).await
}

fn ciba_test_mtls_certificate() -> &'static crate::test_support::Rfc9440CertificateFixture {
    static CERTIFICATE: OnceLock<crate::test_support::Rfc9440CertificateFixture> = OnceLock::new();
    CERTIFICATE.get_or_init(|| crate::test_support::rfc9440_certificate_fixture("ciba-test"))
}

fn configure_ciba_test_mtls_proxy(state: &mut TestInfrastructure) {
    let mut settings = (*state.settings).clone();
    settings.endpoint.trusted_proxy_cidrs = vec![
        nazo_http_actix::IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse"),
    ];
    state.settings = Arc::new(settings);
}

async fn call_ciba_token_with_mtls_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: String,
) -> HttpResponse {
    let certificate = ciba_test_mtls_certificate();
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .app_data(actix_web::web::Data::new(
            crate::http::mtls::MtlsCertificateSource::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            ),
        ))
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header(("client-cert", certificate.header.as_str()))
        .to_http_request();
    call_ciba_token_with_request_for_test(state, client, auth_req_id, req).await
}

async fn call_ciba_token_with_request_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    auth_req_id: String,
    req: HttpRequest,
) -> HttpResponse {
    call_ciba_token_with_form_for_test(
        state,
        client,
        ciba_token_form(auth_req_id),
        req,
        None,
        "private_key_jwt",
    )
    .await
}

async fn call_ciba_token_with_form_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    form: TokenForm,
    req: HttpRequest,
    client_assertion: Option<&ValidatedClientAssertion>,
    auth_method: &str,
) -> HttpResponse {
    call_ciba_token_with_modules_for_test(
        state,
        client,
        form,
        req,
        client_assertion,
        auth_method,
        state.active_module_snapshot(),
    )
    .await
}

async fn call_ciba_token_with_modules_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    form: TokenForm,
    req: HttpRequest,
    client_assertion: Option<&ValidatedClientAssertion>,
    auth_method: &str,
    modules: nazo_runtime_modules::ActiveModuleSnapshot,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let ciba_service = ServerCibaService::new(std::sync::Arc::new(CibaStore::new(&connection)));
    let users = nazo_postgres::UserRepository::new(state.diesel_db.clone());
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
        state.keyset.clone(),
    );
    let issuance_config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let ciba_config = ciba_config(state.settings.as_ref());
    let authorization = super::super::issue::test_support::test_authorization_service(state);
    let issuance = TokenIssuanceContext {
        config: &issuance_config,
        modules: &modules,
        authorization: &authorization,
        security_audit: crate::http::authorization::test_support::test_security_audit(),
        remote_client_documents: crate::test_support::test_remote_client_documents(),
    };
    let handles = CibaTokenHandles::new(
        Arc::new(ciba_service),
        Arc::new(users),
        Arc::new(ciba_config),
    );
    let client_ip = nazo_http_actix::ClientIpConfig::new(
        &state.settings.endpoint.trusted_proxy_cidrs,
        state.settings.endpoint.client_ip_header_mode,
    );
    let facts = crate::http::token::dispatch::token_request_facts(&req, &client_ip);
    let result = token_ciba(
        CibaTokenContext {
            token_service: &token_service,
            issuance: &issuance,
            handles: &handles,
            request: &facts,
        },
        client,
        &form,
        client_assertion,
        auth_method,
    )
    .await;
    match result {
        Ok(success) => nazo_http_actix::token_endpoint_success_response(success),
        Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
    }
}

#[actix_web::test]
async fn token_ciba_rejects_client_policy_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.security_policy = nazo_auth::ClientSecurityPolicy {
        allow_cross_device_flows: false,
        ..nazo_auth::ClientSecurityPolicy::default()
    };

    let response = call_ciba_token_for_test(&state, &client, "not-stored".to_owned()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("unauthorized_client")
    );
}

#[actix_web::test]
async fn token_ciba_rejects_a_disabled_module_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("disabled-module-kid", &key);
    let modules = nazo_runtime_modules::ActiveModuleSnapshot {
        revision: nazo_runtime_modules::ModuleRevision::new(0),
        accepting: std::collections::BTreeSet::new(),
        draining: std::collections::BTreeSet::new(),
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response = call_ciba_token_with_modules_for_test(
        &state,
        &client,
        ciba_token_form("not-stored".to_owned()),
        request,
        None,
        "private_key_jwt",
        modules,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "unsupported_grant_type");
}

#[actix_web::test]
async fn token_ciba_rejects_a_missing_auth_req_id_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("missing-auth-req-id-kid", &key);
    let form = TokenForm {
        grant_type: CIBA_GRANT_TYPE.to_owned(),
        ..ciba_token_form("ignored".to_owned())
    };
    let form = TokenForm {
        auth_req_id: None,
        ..form
    };
    let request = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response =
        call_ciba_token_with_form_for_test(&state, &client, form, request, None, "private_key_jwt")
            .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn token_ciba_rejects_an_invalid_fapi_client_before_state_access() {
    let state = ciba_test_state();
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let client = ciba_private_key_jwt_client("invalid-fapi-client-kid", &key);

    let response = call_ciba_token_for_test(&state, &client, "not-stored".to_owned()).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "invalid_request");
}

#[actix_web::test]
async fn ciba_backchannel_fails_closed_before_client_state_access() {
    let state = ciba_test_state();
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let missing_credentials = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("scope=openid&login_hint=subject%40example.test")
        .to_request();
    let response = actix_web::test::call_service(&app, missing_credentials).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_client"
    );

    let mixed_methods = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(
            "client_id=unknown&client_secret=secret&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=jwt",
        )
        .to_request();
    let response = actix_web::test::call_service(&app, mixed_methods).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );

    let lookup_failure = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("client_id=unknown&client_secret=secret")
        .to_request();
    let response = actix_web::test::call_service(&app, lookup_failure).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "server_error"
    );
}

#[actix_web::test]
async fn ciba_backchannel_validates_request_object_and_creates_bound_state() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let kid = "backchannel-kid";
    let mut client = ciba_private_key_jwt_client(kid, &key);
    client.client_id = format!("ciba-backchannel-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA backchannel client should be stored");

    let user_id = Uuid::now_v7();
    let login_hint = format!("ciba-backchannel-user-{user_id}@example.test");
    insert_ciba_user_with_email(&state, user_id, &login_hint).await;
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(std::sync::Arc::new(
        CibaStore::new(&state.valkey_connection()),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request_object = signed_ciba_request_object_for_client(
        &client.client_id,
        kid,
        &key,
        json!({
            "scope": "openid profile",
            "login_hint": login_hint,
        }),
    );
    let client_assertion = signed_ciba_client_assertion(&client.client_id, kid, &key);
    let body = ciba_backchannel_body(
        &client.client_id,
        Some(&request_object),
        Some(&client_assertion),
        None,
        None,
    );
    let request = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let response: Value = serde_json::from_slice(&body).expect("CIBA response should be JSON");
    let auth_req_id = response["auth_req_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .expect("CIBA response should contain auth_req_id");
    assert_eq!(
        response["interval"],
        state.settings.ciba.ciba_poll_interval_seconds
    );

    let stored = load_ciba_request_payload(&ciba_service, auth_req_id)
        .await
        .expect("CIBA state lookup should succeed")
        .expect("successful backchannel request should persist state");
    assert_eq!(stored.client_id, client.client_id);
    assert_eq!(stored.user_id, user_id);
    assert_eq!(stored.status, CibaStatus::Pending);
    assert_eq!(stored.scopes, vec!["openid", "profile"]);
}

#[actix_web::test]
async fn ciba_backchannel_rejects_invalid_request_object_claims_before_user_lookup() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let kid = "backchannel-invalid-kid";
    let login_hint = format!(
        "ciba-backchannel-invalid-user-{}@example.test",
        Uuid::now_v7()
    );
    let mut client = ciba_private_key_jwt_client(kid, &key);
    client.client_id = format!("ciba-backchannel-invalid-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA invalid-request client should be stored");

    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let client_assertion = signed_ciba_client_assertion(&client.client_id, kid, &key);
    let cases = [
        (
            json!({"scope": "profile", "login_hint": login_hint.clone()}),
            "invalid_scope",
        ),
        (
            json!({"scope": "openid", "login_hint": login_hint.clone(), "id_token_hint": "unexpected"}),
            "invalid_request",
        ),
        (
            json!({"scope": "openid", "login_hint": login_hint.clone(), "acr_values": "9"}),
            "unknown_user_id",
        ),
    ];
    for (extra_claims, expected_error) in cases {
        let request_object =
            signed_ciba_request_object_for_client(&client.client_id, kid, &key, extra_claims);
        let body = ciba_backchannel_body(
            &client.client_id,
            Some(&request_object),
            Some(&client_assertion),
            None,
            None,
        );
        let request = actix_web::test::TestRequest::post()
            .uri("/bc-authorize")
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            oauth_error_code(response.into_parts().1).await,
            expected_error
        );
    }

    insert_ciba_user_with_email(&state, Uuid::now_v7(), &login_hint).await;
    let request_object = signed_ciba_request_object_for_client(
        &client.client_id,
        kid,
        &key,
        json!({
            "scope": "openid",
            "login_hint": login_hint,
            "acr_values": "9",
        }),
    );
    let body = ciba_backchannel_body(
        &client.client_id,
        Some(&request_object),
        Some(&client_assertion),
        None,
        None,
    );
    let request = actix_web::test::TestRequest::post()
        .uri("/bc-authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

fn ciba_private_key_jwt_client_with_alg(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    let public_jwk = fixture.public_jwk(kid);
    let mut client = client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "CIBA Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "profile", "email", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!([CIBA_GRANT_TYPE, "refresh_token"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
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
        jwks: Some(json!({"keys": [public_jwk]})),
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

fn ciba_private_key_jwt_client(kid: &str, fixture: &ClientSigningFixture) -> ClientRow {
    ciba_private_key_jwt_client_with_alg(kid, fixture)
}

fn signed_ciba_request_object_for_client_with_alg(
    client_id: &str,
    kid: &str,
    alg: jsonwebtoken::Algorithm,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-request-{}", Uuid::now_v7()),
        "scope": "openid profile email",
        "login_hint": "subject@example.test",
        "binding_message": "1234"
    });
    let target = claims.as_object_mut().expect("claims should be object");
    for (key, value) in extra_claims
        .as_object()
        .expect("extra claims should be object")
    {
        if value.is_null() {
            target.remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
    let mut header = jsonwebtoken::Header::new(alg);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn signed_ciba_request_object_for_client(
    client_id: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
    extra_claims: Value,
) -> String {
    signed_ciba_request_object_for_client_with_alg(
        client_id,
        kid,
        jsonwebtoken::Algorithm::PS256,
        fixture,
        extra_claims,
    )
}

fn signed_ciba_client_assertion(
    client_id: &str,
    kid: &str,
    fixture: &ClientSigningFixture,
) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("ciba-client-assertion-{}", Uuid::now_v7()),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn ciba_backchannel_body(
    client_id: &str,
    request_object: Option<&str>,
    client_assertion: Option<&str>,
    scope: Option<&str>,
    login_hint: Option<&str>,
) -> String {
    let mut fields = Vec::new();
    fields.push(format!("client_id={}", urlencoding::encode(client_id)));
    fields.push(format!(
        "client_assertion_type={}",
        urlencoding::encode(nazo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER)
    ));
    if let Some(request_object) = request_object {
        fields.push(format!("request={}", urlencoding::encode(request_object)));
    }
    if let Some(client_assertion) = client_assertion {
        fields.push(format!(
            "client_assertion={}",
            urlencoding::encode(client_assertion)
        ));
    }
    if let Some(scope) = scope {
        fields.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(login_hint) = login_hint {
        fields.push(format!("login_hint={}", urlencoding::encode(login_hint)));
    }
    fields.join("&")
}

#[actix_web::test]
async fn ciba_request_parser_enforces_form_encoding_and_parameter_uniqueness() {
    let body = concat!(
        "request=jwt&scope=openid%20profile&login_hint=user%40example.test&",
        "id_token_hint=id-token&login_hint_token=hint-token&binding_message=1234&",
        "acr_values=1&requested_expiry=30&client_id=client-1&client_secret=secret&",
        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&",
        "client_assertion=assertion&client_notification_token=notification&unknown=ignored"
    );
    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let form = parse_backchannel_authentication_form(&request, &mut payload)
        .await
        .expect("valid CIBA form should parse");
    assert_eq!(form.request.as_deref(), Some("jwt"));
    assert_eq!(form.scope.as_deref(), Some("openid profile"));
    assert_eq!(form.login_hint.as_deref(), Some("user@example.test"));
    assert_eq!(form.id_token_hint.as_deref(), Some("id-token"));
    assert_eq!(form.login_hint_token.as_deref(), Some("hint-token"));
    assert_eq!(form.binding_message.as_deref(), Some("1234"));
    assert_eq!(form.acr_values.as_deref(), Some("1"));
    assert_eq!(form.requested_expiry_seconds, Some(30));
    assert_eq!(
        form.client_notification_token.as_deref(),
        Some("notification")
    );

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("scope=openid&scope=profile")
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let duplicate = match parse_backchannel_authentication_form(&request, &mut payload).await {
        Ok(_) => panic!("duplicate CIBA parameters must fail"),
        Err(response) => response,
    };
    assert_eq!(oauth_error_code(duplicate).await, "invalid_request");

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(body)
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let wrong_content_type =
        match parse_backchannel_authentication_form(&request, &mut payload).await {
            Ok(_) => panic!("CIBA must reject non-form content types"),
            Err(response) => response,
        };
    assert_eq!(wrong_content_type.status(), StatusCode::BAD_REQUEST);

    let (request, mut payload) = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("x".repeat(16 * 1024 + 1))
        .to_http_parts();
    let mut payload =
        <actix_web::web::Payload as actix_web::FromRequest>::from_request(&request, &mut payload)
            .await
            .expect("CIBA payload extractor should succeed");
    let oversized = match parse_backchannel_authentication_form(&request, &mut payload).await {
        Ok(_) => panic!("oversized CIBA forms must fail closed"),
        Err(response) => response,
    };
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn ciba_decision_storage_failure_maps_to_non_cacheable_server_error() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let sid = format!("ciba-corrupt-session-{}", Uuid::now_v7());
    store_ciba_session(&state, &sid, user_id).await;
    let id = format!("ciba-corrupt-{}", Uuid::now_v7());
    valkey_set_ex(
        &state.valkey,
        nazo_valkey::test_support::ciba_request_storage_key(&id),
        "{not-json".to_owned(),
        60,
    )
    .await
    .expect("corrupt fixture stores");
    let settings = state.settings.clone();
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("runtime fixture");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;
    let request = actix_web::test::TestRequest::post()
        .uri(&format!("/auth/ciba/{id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid,
        ))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            "csrf",
        ))
        .set_json(json!({"decision":"approve","csrf_token":"csrf"}))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "server_error"
    );
}

#[actix_web::test]
async fn ciba_poll_storage_error_presenter_preserves_503_and_no_store() {
    let response = nazo_http_actix::oauth_endpoint_error_response(
        nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::token(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "CIBA state unavailable.",
            false,
        ),
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("server_error")
    );
}

#[actix_web::test]
async fn ciba_poll_error_presenter_preserves_invalid_grant_and_contention_headers() {
    for (description, expected_status, expected_error) in [
        (
            "CIBA auth_req_id is expired or consumed.",
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "CIBA auth_req_id was not issued to this client.",
            StatusCode::BAD_REQUEST,
            "invalid_grant",
        ),
        (
            "CIBA state is busy.",
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ] {
        let response = nazo_http_actix::oauth_endpoint_error_response(
            nazo_oauth_server::contracts::oauth_error::OAuthEndpointError::token(
                http::StatusCode::from_u16(expected_status.as_u16()).expect("valid status"),
                expected_error,
                description,
                false,
            ),
        );
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            Some(oauth_error_code(response).await.as_str()),
            Some(expected_error)
        );
    }
}

#[actix_web::test]
async fn ciba_verification_page_preserves_redirect_and_non_cacheable_headers() {
    let state = ciba_test_state_with(|settings| {
        settings.endpoint.frontend_base_url = "https://frontend.example/".to_owned();
    });
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri("/ciba/auth-request-id")
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("https://frontend.example/ciba/auth-request-id")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

#[actix_web::test]
async fn ciba_verification_loads_the_bound_user_and_rejects_a_session_mismatch() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("verification-kid", &key);
    client.client_id = format!("ciba-verification-client-{}", Uuid::now_v7());
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("verification CIBA client should be stored");

    let user_id = Uuid::now_v7();
    let other_user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    insert_ciba_user(&state, other_user_id).await;
    let auth_req_id = format!("verification-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Pending).await;
    let session_id = format!("ciba-session-{}", Uuid::now_v7());
    let other_session_id = format!("ciba-session-other-{}", Uuid::now_v7());
    store_ciba_session(&state, &session_id, user_id).await;
    store_ciba_session(&state, &other_session_id, other_user_id).await;

    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::get()
        .uri(&format!("/auth/ciba/{auth_req_id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            session_id,
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let view: Value = serde_json::from_slice(&body).expect("verification view should be JSON");
    assert_eq!(view["auth_req_id"], auth_req_id);
    assert!(view["request"].is_object());

    let request = actix_web::test::TestRequest::get()
        .uri(&format!("/auth/ciba/{auth_req_id}"))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            other_session_id,
        ))
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "access_denied"
    );
}

#[actix_web::test]
async fn ciba_browser_decision_rejects_invalid_csrf_before_session_lookup() {
    let state = ciba_test_state();
    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let request = actix_web::test::TestRequest::post()
        .uri("/auth/ciba/not-stored")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-csrf-check",
        ))
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            "csrf-cookie",
        ))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(r#"{"decision":"approve","csrf_token":"csrf-body-mismatch"}"#)
        .to_request();
    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

#[actix_web::test]
async fn ciba_browser_decision_commits_user_context_and_rejects_replay() {
    let Some(state) = live_ciba_replay_state().await else {
        return;
    };
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("browser-decision-kid", &key);
    client.client_id = format!("ciba-browser-decision-client-{}", Uuid::now_v7());
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("CIBA browser-decision client should be stored");
    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let auth_req_id = format!("browser-decision-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Pending).await;
    let session_id = format!("ciba-browser-session-{}", Uuid::now_v7());
    store_ciba_session(&state, &session_id, user_id).await;

    let settings = Arc::clone(&state.settings);
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        &settings,
    )
    .expect("CIBA runtime registry should initialize");
    let ciba_service = actix_web::web::Data::new(ServerCibaService::new(std::sync::Arc::new(
        CibaStore::new(&state.valkey_connection()),
    )));
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .configure(|cfg| configure_ciba_test_app(cfg, &state, &runtime))
            .configure(|cfg| crate::bootstrap::routes::configure(cfg, &settings, false)),
    )
    .await;

    let decision_request = || {
        actix_web::test::TestRequest::post()
            .uri(&format!("/auth/ciba/{auth_req_id}"))
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.session_cookie_name.clone(),
                session_id.clone(),
            ))
            .cookie(actix_web::cookie::Cookie::new(
                state.settings.session.csrf_cookie_name.clone(),
                "csrf-session-token",
            ))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"decision":"approve","csrf_token":"csrf-session-token"}"#)
            .to_request()
    };
    let response = actix_web::test::call_service(&app, decision_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::test::read_body(response).await;
    let value: Value = serde_json::from_slice(&body).expect("decision response should be JSON");
    assert_eq!(value["success"], true);

    let state_after = load_ciba_request_payload(&ciba_service, &auth_req_id)
        .await
        .expect("CIBA state lookup should succeed")
        .expect("decision should retain CIBA state for polling");
    assert_eq!(state_after.status, CibaStatus::Approved);
    let context = state_after
        .authentication_context
        .expect("browser decision should persist authentication context");
    assert!(
        context
            .oidc_sid
            .as_deref()
            .is_some_and(|sid| sid.starts_with("oidc-"))
    );

    let response = actix_web::test::call_service(&app, decision_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(response.into_parts().1).await,
        "invalid_request"
    );
}

#[actix_web::test]
async fn ciba_token_request_requires_mtls_binding_before_pending_state() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state();
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("pending-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Pending).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn ciba_token_request_validates_mtls_binding_before_issuing_approved_token() {
    let Some(valkey) = live_test_valkey().await else {
        return;
    };
    let mut state = ciba_test_state();
    state.valkey = valkey;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-kid", &key);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("approved-mtls-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &auth_req_id, CibaStatus::Approved).await;

    let response = call_ciba_token_for_test(&state, &client, auth_req_id).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

#[actix_web::test]
async fn ciba_token_poll_maps_pending_slow_down_and_denied_states() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("poll-status-kid", &key);
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;

    let pending_id = format!("pending-status-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &pending_id, CibaStatus::Pending).await;
    let pending = call_ciba_token_with_mtls_for_test(&state, &client, pending_id.clone()).await;
    assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(pending).await, "authorization_pending");

    let slow_down = call_ciba_token_with_mtls_for_test(&state, &client, pending_id).await;
    assert_eq!(slow_down.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(slow_down).await, "slow_down");

    let denied_id = format!("denied-status-{}", Uuid::now_v7());
    store_ciba_state(&state, &client, &denied_id, CibaStatus::Denied).await;
    let denied = call_ciba_token_with_mtls_for_test(&state, &client, denied_id).await;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(denied).await, "access_denied");
}

#[actix_web::test]
async fn ciba_token_poll_fails_closed_for_approved_state_without_authentication_context() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("missing-context-kid", &key);
    client.security_policy.allow_cross_device_flows = true;
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;
    let auth_req_id = format!("approved-without-context-{}", Uuid::now_v7());
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            &auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: Uuid::now_v7(),
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: None,
                binding_message: None,
                issued_at: now,
                status: CibaStatus::Approved,
                interval_seconds: 5,
                expires_at: now + 600,
                retention_expires_at: now + 720,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("malformed approved CIBA fixture should reach the core validation boundary");

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id.clone()).await;

    assert_eq!(
        (response.status(), oauth_error_code(response).await),
        (StatusCode::SERVICE_UNAVAILABLE, "server_error".to_owned())
    );
    let store = CibaStore::new(&state.valkey_connection());
    assert!(
        nazo_valkey::CibaStore::load(&store, &auth_req_id)
            .await
            .expect("malformed state should remain inspectable")
            .is_some(),
        "a malformed approved state must not be redeemed"
    );
}

#[actix_web::test]
async fn ciba_token_poll_maps_an_expired_state_before_user_lookup() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("expired-status-kid", &key);
    client.require_mtls_bound_tokens = true;
    persist_ciba_test_client(&state, &client).await;
    let auth_req_id = format!("expired-status-{}", Uuid::now_v7());
    let now = Utc::now().timestamp();
    CibaStore::new(&state.valkey_connection())
        .create(
            &auth_req_id,
            &CibaRequestState {
                client_id: client.client_id.clone(),
                user_id: Uuid::now_v7(),
                scopes: vec!["openid".to_owned()],
                audiences: vec!["resource://default".to_owned()],
                acr: None,
                authentication_context: None,
                binding_message: None,
                issued_at: now - 120,
                status: CibaStatus::Pending,
                interval_seconds: 5,
                expires_at: now - 1,
                retention_expires_at: now + 600,
                last_poll_at: None,
                ping_notification: None,
            },
        )
        .await
        .expect("expired CIBA state should be stored");

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(response).await, "expired_token");
}

#[actix_web::test]
async fn ciba_token_approved_state_issues_access_and_id_tokens_for_an_active_user() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    state.keyset =
        crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("approved-issue-kid", &key);
    client.client_id = format!("ciba-approved-client-{}", Uuid::now_v7());
    client.require_mtls_bound_tokens = true;
    nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .insert(&client, None, None)
        .await
        .expect("approved CIBA client should be stored");

    let user_id = Uuid::now_v7();
    insert_ciba_user(&state, user_id).await;
    let auth_req_id = format!("approved-issue-{}", Uuid::now_v7());
    store_ciba_state_with_user(&state, &client, &auth_req_id, user_id, CibaStatus::Approved).await;

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id.clone()).await;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("CIBA error response should collect");
        panic!(
            "approved CIBA token request returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("CIBA token response should collect");
    let value: Value = serde_json::from_slice(&body).expect("CIBA token response should be JSON");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(value.get("refresh_token").is_none());

    let replay = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(replay).await, "invalid_grant");
}

#[actix_web::test]
async fn ciba_replay_rejects_a_consumed_auth_req_id_even_with_a_persisted_response() {
    let Some(mut state) = live_ciba_replay_state().await else {
        return;
    };
    configure_ciba_test_mtls_proxy(&mut state);
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    let mut client = ciba_private_key_jwt_client("ciba-replay-kid", &key);
    client.client_id = format!("ciba-persisted-replay-{}", client.id);
    client.require_mtls_bound_tokens = true;
    let auth_req_id = format!("ciba-replay-{}", Uuid::now_v7());
    let grant_key = ciba_grant_key(
        &auth_req_id,
        None,
        Some(ciba_test_mtls_certificate().thumbprint.as_str()),
    );

    crate::http::token::issue::tests::persist_token_issuance_response_for_test(
        &state, &client, &grant_key,
    )
    .await;

    let response = call_ciba_token_with_mtls_for_test(&state, &client, auth_req_id).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        Some(oauth_error_code(response).await.as_str()),
        Some("invalid_grant")
    );
}

use nazo_valkey::CibaStore;
