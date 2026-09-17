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

use nazo_valkey::CibaStore;

#[path = "ciba/client_auth.rs"]
mod client_auth;
#[path = "ciba/issuance.rs"]
mod issuance;
#[path = "ciba/polling.rs"]
mod polling;
#[path = "ciba/subject_state.rs"]
mod subject_state;

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
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    call_ciba_token_with_prepared_service(
        state,
        &token_service,
        client,
        form,
        req,
        client_assertion,
        auth_method,
        modules,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn call_ciba_token_with_prepared_service(
    state: &TestInfrastructure,
    token_service: &ServerTokenService,
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
            token_service,
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
