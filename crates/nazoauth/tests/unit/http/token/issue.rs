use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use crate::test_support::TestInfrastructure;

use nazo_identity::DEFAULT_ORGANIZATION_ID;

use nazo_identity::DEFAULT_REALM_ID;

use nazo_identity::DEFAULT_TENANT_ID;
use nazo_oauth_server::domain::oauth::NativeSsoTokenBinding;

use nazo_auth::OidcClaimRequest;

use super::*;
use actix_web::{
    HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderValue},
    },
};
use nazo_oauth_server::{
    contracts::{oauth_error::OAuthEndpointError, token_endpoint::TokenEndpointSuccess},
    domain::{
        oauth::{RefreshTokenPolicy, TokenIssue},
        rows::ClientRow,
    },
    services::ServerTokenService,
    token::issue::TokenIssuanceContext,
};
use serde_json::{Value, json};
use uuid::Uuid;

use chrono::Utc;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Uuid as SqlUuid};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use fred::interfaces::ClientLike;
use nazo_postgres::{create_pool, get_conn};

use crate::test_support::client_signing_fixture;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, TokenIssuanceMode, TokenIssuedAuditFields,
    TokenRepositoryPort,
};

const LIVE_VALKEY_TIMEOUT: StdDuration = StdDuration::from_secs(5);

#[path = "issue/failure_boundaries.rs"]
mod failure_boundaries;
#[path = "issue/refresh.rs"]
mod refresh;
#[path = "issue/sender_constraints.rs"]
mod sender_constraints;
#[path = "issue/subject_and_claims.rs"]
mod subject_and_claims;

pub(crate) async fn issue_token_response(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    issue_token_response_with_modules(state, client, issue, state.active_module_snapshot()).await
}

async fn issue_token_response_with_repository(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
    repository: std::sync::Arc<dyn TokenRepositoryPort>,
) -> HttpResponse {
    let service = ServerTokenService::from_port(
        repository,
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let config = token_issuance_config(state.settings.as_ref());
    let authorization = test_support::test_authorization_service(state);
    present_token_result(
        nazo_oauth_server::token::issue::issue_token_response(
            &TokenIssuanceContext {
                config: &config,
                modules: &state.active_module_snapshot(),
                authorization: &authorization,
                security_audit: crate::http::authorization::test_support::test_security_audit(),
                remote_client_documents: crate::test_support::test_remote_client_documents(),
            },
            &service,
            client,
            TokenIssuanceMode::Fresh,
            issue,
        )
        .await,
    )
}

async fn issue_token_response_with_modules(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
    modules: nazo_runtime_modules::ActiveModuleSnapshot,
) -> HttpResponse {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let config = token_issuance_config(state.settings.as_ref());
    let authorization = test_support::test_authorization_service(state);
    present_token_result(
        nazo_oauth_server::token::issue::issue_token_response(
            &TokenIssuanceContext {
                config: &config,
                modules: &modules,
                authorization: &authorization,
                security_audit: crate::http::authorization::test_support::test_security_audit(),
                remote_client_documents: crate::test_support::test_remote_client_documents(),
            },
            &service,
            client,
            TokenIssuanceMode::Fresh,
            issue,
        )
        .await,
    )
}

async fn issue_token_response_with_grant_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
    issue: TokenIssue,
) -> HttpResponse {
    issue_token_response_with_mode_for_test(
        state,
        client,
        TokenIssuanceMode::SingleUse {
            grant_key: grant_key.to_owned(),
            grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
        },
        issue,
    )
    .await
}

async fn issue_token_response_with_mode_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    mode: TokenIssuanceMode,
    issue: TokenIssue,
) -> HttpResponse {
    issue_token_response_with_mode_and_modules_for_test(
        state,
        client,
        mode,
        issue,
        state.active_module_snapshot(),
    )
    .await
}

async fn issue_token_response_with_mode_and_modules_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    mode: TokenIssuanceMode,
    issue: TokenIssue,
    modules: nazo_runtime_modules::ActiveModuleSnapshot,
) -> HttpResponse {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let config = token_issuance_config(state.settings.as_ref());
    let authorization = test_support::test_authorization_service(state);
    present_token_result(
        nazo_oauth_server::token::issue::issue_token_response(
            &TokenIssuanceContext {
                config: &config,
                modules: &modules,
                authorization: &authorization,
                security_audit: crate::http::authorization::test_support::test_security_audit(),
                remote_client_documents: crate::test_support::test_remote_client_documents(),
            },
            &service,
            client,
            mode,
            issue,
        )
        .await,
    )
}

async fn response_body(response: HttpResponse) -> Vec<u8> {
    actix_web::body::to_bytes(response.into_body())
        .await
        .expect("token response body should collect")
        .to_vec()
}

#[derive(diesel::QueryableByName)]
#[allow(dead_code)]
struct TokenRowCount {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[allow(dead_code)]
async fn refresh_token_row_count(state: &TestInfrastructure, client: &ClientRow) -> i64 {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM oauth_tokens WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .get_result::<TokenRowCount>(&mut connection)
    .await
    .expect("refresh token row count should load")
    .count
}

async fn token_issuance_row_count(state: &TestInfrastructure, client: &ClientRow) -> i64 {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .get_result::<TokenRowCount>(&mut connection)
    .await
    .expect("issue token issuance count should load")
    .count
}

fn present_token_result(result: Result<TokenEndpointSuccess, OAuthEndpointError>) -> HttpResponse {
    match result {
        Ok(success) => nazo_http_actix::token_endpoint_success_response(success),
        Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
    }
}

/// Seed a durably consumed single-use grant for endpoint replay tests.  The
/// HTTP handlers under test must reject a consumed one-time grant; this helper
/// commits the winning issuance row so a later redemption loses the fence.
pub(crate) async fn persist_consumed_single_use_grant_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
) {
    insert_issue_client(state, client).await;
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    );
    let issuance_id = Uuid::now_v7();
    let result = service
        .commit_token_issuance(CommitTokenIssuance {
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            mode: TokenIssuanceMode::SingleUse {
                grant_key: grant_key.to_owned(),
                grant_expires_at: Utc::now() + chrono::Duration::minutes(5),
            },
            access_token_jti: format!("consumed-grant-{issuance_id}"),
            access_token_expires_at: (Utc::now() + chrono::Duration::minutes(5)).timestamp(),
            refresh_token: None,
            audit_fields: TokenIssuedAuditFields {
                client_id: client.client_id.clone(),
                subject_hash: "fixture-subject".to_owned(),
                scope: "fixture".to_owned(),
                audience: vec!["fixture".to_owned()],
            },
        })
        .await
        .expect("test token issuance should commit");
    assert!(matches!(result, CommitTokenIssuanceResult::Committed));
}

fn disconnected_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::default_centralized();
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(50);
        connection.internal_command_timeout = StdDuration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("valkey client construction should not connect")
}

fn live_valkey_client() -> Option<fred::prelude::Client> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = LIVE_VALKEY_TIMEOUT;
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = LIVE_VALKEY_TIMEOUT;
        connection.internal_command_timeout = LIVE_VALKEY_TIMEOUT;
        connection.max_command_attempts = 1;
    });
    Some(builder.build().expect("Valkey client should build"))
}

fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(grant_types),
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
    }
}

fn issue_state_with_invalid_signing_key() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_issue_test_invalid:nazo_issue_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::failing_key_manager(),
    }
}

fn issue_state_with_valid_signing_key() -> TestInfrastructure {
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_issue_test_invalid:nazo_issue_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn insert_issue_user(state: &TestInfrastructure, user_id: Uuid) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("issue test user cleanup should succeed");
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
    .bind::<Text, _>(format!("issue-user-{user_id}"))
    .bind::<Text, _>(format!("issue-user-{user_id}@example.test"))
    .bind::<Text, _>("issue-test-password-hash")
    .execute(&mut connection)
    .await
    .expect("issue test user should insert");
}

async fn insert_issue_client(state: &TestInfrastructure, client: &ClientRow) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .expect("issue test client cleanup should succeed");
    sql_query(
        "INSERT INTO oauth_clients (\
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
            redirect_uris, scopes, grant_types, token_endpoint_auth_method, is_active, security_policy\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE,\
            jsonb_build_object(\
                'version', 1, 'assurance', 'baseline',\
                'require_signed_authorization_request', false,\
                'require_signed_authorization_response', false,\
                'require_signed_introspection_response', false,\
                'session_management', false, 'allow_cross_device_flows', false,\
                'allow_confidential_oidc_without_pkce', false\
            ))",
    )
    .bind::<SqlUuid, _>(client.id)
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.realm_id)
    .bind::<SqlUuid, _>(client.organization_id)
    .bind::<Text, _>(&client.client_id)
    .bind::<Text, _>(&client.client_name)
    .bind::<Text, _>(&client.client_type)
    .bind::<Jsonb, _>(serde_json::to_value(&client.redirect_uris).expect("redirect URIs JSON"))
    .bind::<Jsonb, _>(serde_json::to_value(&client.scopes).expect("scopes JSON"))
    .bind::<Jsonb, _>(serde_json::to_value(&client.grant_types).expect("grant types JSON"))
    .bind::<Text, _>(&client.token_endpoint_auth_method)
    .execute(&mut connection)
    .await
    .expect("issue test client should insert");
}

fn issue_state_with_live_database() -> Option<TestInfrastructure> {
    issue_state_with_live_database_pool_size(1)
}

fn issue_state_with_live_database_pool_size(max_size: usize) -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let valkey = live_valkey_client()?;
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let diesel_db = create_pool(database_url, max_size).expect("database pool should build");
    crate::test_support::initialize_audit_dependencies(&diesel_db);
    Some(TestInfrastructure {
        diesel_db,
        valkey,
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        // The default OIDC ID-token algorithm is RS256. Keep the live
        // issuance fixture aligned with that protocol default so this test
        // exercises successful signing instead of manufacturing an
        // algorithm/key mismatch (the generic unit fixture intentionally
        // uses EdDSA for failure-path tests).
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::RS256,
        ),
    })
}

fn issue_state_with_live_database_and_disconnected_valkey() -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let diesel_db = create_pool(database_url, 1).expect("database pool should build");
    crate::test_support::initialize_audit_dependencies(&diesel_db);
    Some(TestInfrastructure {
        diesel_db,
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::RS256,
        ),
    })
}

async fn delete_token_issuance_for_grant(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available for cleanup");
    sql_query(
        "DELETE FROM oauth_token_issuances \
         WHERE tenant_id = $1 AND client_id = $2 AND single_use_key_blake3 = $3",
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .bind::<diesel::sql_types::Binary, _>(blake3::hash(grant_key.as_bytes()).as_bytes().to_vec())
    .execute(&mut connection)
    .await
    .expect("issue test token issuance cleanup should succeed");
}

fn token_issue_with_sid(id_token_claims: Vec<String>) -> TokenIssue {
    TokenIssue {
        user_id: None,
        prepared_subject: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("op-session-sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims,
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

fn token_issue_without_openid() -> TokenIssue {
    TokenIssue {
        user_id: None,
        prepared_subject: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["accounts".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}
