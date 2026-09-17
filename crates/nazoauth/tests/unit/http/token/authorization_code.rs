#[path = "../../../../../authorization-server/tests/support/authorization_code.rs"]
mod code_fixture;
use code_fixture::{VALID_CODE_VERIFIER, code_payload, form_for_code};

use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use crate::test_support::TestInfrastructure;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use chrono::Utc;
use nazo_auth::DpopError;
use nazo_auth::ValidatedClientAssertion;
use nazo_oauth_server::contracts::token_forms::TokenForm;
use nazo_oauth_server::crypto::blake3_hex;
use nazo_oauth_server::crypto::pkce_s256;
use nazo_oauth_server::domain::oauth::AuthorizationCodeState;
use nazo_oauth_server::domain::oauth::CodePayload;
use nazo_oauth_server::domain::oauth::ConsumedAuthorizationCode;
use nazo_oauth_server::domain::oauth::RefreshTokenPolicy;
use nazo_oauth_server::domain::rows::ClientRow;
use nazo_oauth_server::services::ServerTokenService;
use nazo_oauth_server::token::authorization_code::AuthorizationCodeConsumption;
use nazo_oauth_server::token::authorization_code::AuthorizationCodeIssueInput;
use nazo_oauth_server::token::authorization_code::authorization_code_client_mismatch_response;
use nazo_oauth_server::token::authorization_code::authorization_code_dpop_error_response;
use nazo_oauth_server::token::authorization_code::authorization_code_grant_key;
use nazo_oauth_server::token::authorization_code::authorization_code_mtls_holder_error_response;
use nazo_oauth_server::token::authorization_code::begin_authorization_code_consumption_with_service;
use nazo_oauth_server::token::authorization_code::load_pending_authorization_code_payload_with_service;
use nazo_oauth_server::token::authorization_code::redirect_uri_matches_authorization_request;
use nazo_oauth_server::token::authorization_code::refresh_token_dpop_binding;
use nazo_oauth_server::token::authorization_code::token_authorization_code_with_service;
use nazo_oauth_server::token::authorization_code::token_issue_from_authorization_code;
use nazo_oauth_server::token::authorization_code::validate_pending_authorization_code_request;
use nazo_oauth_server::token::issue::TokenIssuanceContext;

use nazo_valkey::test_support::authorization_code_storage_key as authorization_code_key;

use nazo_identity::DEFAULT_ORGANIZATION_ID;

use nazo_identity::DEFAULT_REALM_ID;

use nazo_identity::DEFAULT_TENANT_ID;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_get;

use crate::test_support::valkey::valkey_set_ex;

use actix_web::http::header;

use actix_web::http::header::HeaderValue;

use actix_web::web::Data;

use base64::Engine;

use chrono::{DateTime, Duration};

use nazo_auth::OidcClaimRequest;

use serde_json::{Value, json};

use uuid::Uuid;

use crate::schema::{access_token_revocations, oauth_tokens};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::test_support::DatabaseUserFixture;
use nazo_auth::pairwise_subject as oidc_subject;
use nazo_postgres::{create_pool, get_conn};

#[path = "authorization_code/admission.rs"]
mod admission;
#[path = "authorization_code/issuance.rs"]
mod issuance;
#[path = "authorization_code/replay.rs"]
mod replay;
#[path = "authorization_code/sender_constraints.rs"]
mod sender_constraints;

#[path = "authorization_code/error_mapping.rs"]
mod error_mapping;
#[path = "authorization_code/redirect_uri.rs"]
mod redirect_uri;

fn test_token_service(state: &TestInfrastructure) -> ServerTokenService {
    ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        std::sync::Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    )
}

async fn begin_authorization_code_consumption(
    state: &TestInfrastructure,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, HttpResponse> {
    begin_authorization_code_consumption_with_service(&test_token_service(state), code_hash)
        .await
        .map_err(nazo_http_actix::oauth_endpoint_error_response)
}

pub(crate) async fn token_authorization_code(
    state: &TestInfrastructure,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let service = test_token_service(state);
    let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = crate::http::token::issue::test_support::test_authorization_service(state);
    crate::http::token::issue::test_support::present_token_result(
        token_authorization_code_with_service(
            &service,
            &TokenIssuanceContext {
                config: &config,
                modules: &modules,
                authorization: &authorization,
                security_audit: crate::http::authorization::test_support::test_security_audit(),
                remote_client_documents: crate::test_support::test_remote_client_documents(),
            },
            &crate::http::token::issue::test_support::token_request_facts(
                req,
                state.settings.as_ref(),
            ),
            client,
            form,
            client_assertion,
            None,
        )
        .await,
    )
}

fn pkce_policy_client() -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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

struct LiveAuthorizationCodeFixture {
    state: Data<TestInfrastructure>,
}

impl LiveAuthorizationCodeFixture {
    async fn new() -> Option<Self> {
        let settings = Self::settings();
        Self::new_with_settings_and_keyset(settings, crate::test_support::failing_key_manager())
            .await
    }

    fn settings() -> Settings {
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("MTLS_ENDPOINT_BASE_URL", "https://issuer.example"),
            ("FRONTEND_BASE_URL", "https://app.example"),
            ("TRANSPORT_MODE", "trusted-proxy"),
            ("TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
            ("MTLS_CERTIFICATE_SOURCE", "rfc9440"),
            ("COOKIE_SECURE", "true"),
            ("TOKEN_RATE_LIMIT_MAX_REQUESTS", "100000"),
        ]);
        Settings::from_config(&config).expect("test settings should load")
    }

    async fn new_with_settings_and_keyset(
        settings: Settings,
        keyset: nazo_key_management::KeyManager,
    ) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");
        let diesel_db = create_pool(database_url, 4).expect("database pool should build");
        crate::test_support::initialize_audit_dependencies(&diesel_db);

        Some(Self {
            state: Data::new(TestInfrastructure {
                diesel_db,
                valkey,
                settings: Arc::new(settings),
                keyset,
            }),
        })
    }

    async fn insert_client(&self, client: &ClientRow) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client.client_id.as_str())
            .execute(&mut conn)
            .await
            .expect("test client cleanup should succeed");

        sql_query(
            r#"
            INSERT INTO oauth_clients (
                id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip,
                tls_client_auth_san_email, allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                is_active, jwks, security_policy,
                post_logout_redirect_uris, backchannel_logout_uri,
                backchannel_logout_session_required, subject_type, sector_identifier_uri,
                sector_identifier_host
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13, $14,
                $15, NULL, NULL,
                '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, false,
                false, false,
                $16, NULL,
                '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
                '[]'::jsonb, NULL,
                true, $17, $18, $19
            )
            "#,
        )
        .bind::<SqlUuid, _>(client.id)
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<SqlUuid, _>(client.realm_id)
        .bind::<SqlUuid, _>(client.organization_id)
        .bind::<Text, _>(client.client_id.as_str())
        .bind::<Text, _>(client.client_name.as_str())
        .bind::<Text, _>(client.client_type.as_str())
        .bind::<Nullable<Text>, _>(Option::<&str>::None)
        .bind::<Jsonb, _>(json!(&client.redirect_uris))
        .bind::<Jsonb, _>(json!(&client.scopes))
        .bind::<Jsonb, _>(json!(&client.allowed_audiences))
        .bind::<Jsonb, _>(json!(&client.grant_types))
        .bind::<Text, _>(client.token_endpoint_auth_method.as_str())
        .bind::<Bool, _>(client.require_dpop_bound_tokens)
        .bind::<Bool, _>(client.require_mtls_bound_tokens)
        .bind::<Bool, _>(client.is_active)
        .bind::<Text, _>(client.subject_type.as_str())
        .bind::<Nullable<Text>, _>(client.sector_identifier_uri.as_deref())
        .bind::<Nullable<Text>, _>(client.sector_identifier_host.as_deref())
        .execute(&mut conn)
        .await
        .expect("test client insert should succeed");
    }

    async fn insert_user(&self) -> DatabaseUserFixture {
        let suffix = Uuid::now_v7();
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                id, tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES (
                $1, $2, $3, $4, $5, $6,
                'unused-auth-code-test-hash', true, false, true, 'user', 0
            )
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(suffix)
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(format!("auth-code-{suffix}"))
        .bind::<Text, _>(format!("auth-code-{suffix}@example.com"))
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_code_state(&self, code: &str, state: &AuthorizationCodeState) {
        valkey_set_ex(
            &self.state.valkey,
            authorization_code_key(code),
            serde_json::to_string(state).expect("authorization code state should serialize"),
            self.state.settings.protocol.auth_code_ttl_seconds,
        )
        .await
        .expect("authorization code state should store");
    }

    async fn store_raw_code_state(&self, code: &str, raw: &str) {
        valkey_set_ex(
            &self.state.valkey,
            authorization_code_key(code),
            raw.to_owned(),
            self.state.settings.protocol.auth_code_ttl_seconds,
        )
        .await
        .expect("raw authorization code state should store");
    }

    async fn code_state(&self, code: &str) -> AuthorizationCodeState {
        let raw = valkey_get(&self.state.valkey, authorization_code_key(code))
            .await
            .expect("authorization code lookup should succeed")
            .expect("authorization code state should exist");
        serde_json::from_str(&raw).expect("authorization code state should deserialize")
    }

    async fn insert_refresh_token(&self, client: &ClientRow, family_id: Uuid) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO oauth_tokens (
                id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
                client_id, user_id, scopes, audience, oidc_auth_context,
                authorization_details, issued_at, expires_at,
                revoked_at, reuse_detected_at, subject, dpop_jkt, mtls_x5t_s256
            )
            VALUES (
                $1, $2, $3, $4, NULL,
                $5, $6, '["openid","offline_access"]'::jsonb,
                '["resource://default"]'::jsonb,
                jsonb_build_object(
                    'version', 1, 'issuer', 'https://issuer.example.test',
                    'audience', $7, 'auth_time', floor(extract(epoch from now()))::bigint,
                    'amr', '["pwd"]'::jsonb, 'oidc_sid', NULL, 'id_token_sid', NULL,
                    'acr', NULL, 'nonce', NULL, 'userinfo_claims', '[]'::jsonb,
                    'userinfo_claim_requests', '[]'::jsonb, 'id_token_claims', '[]'::jsonb,
                    'id_token_claim_requests', '[]'::jsonb
                ),
                '[]'::jsonb, now(),
                now() + interval '1 day', NULL, NULL, 'subject-1', NULL, NULL
            )
            "#,
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<Text, _>(blake3_hex(&format!("refresh-token-{family_id}")))
        .bind::<SqlUuid, _>(family_id)
        .bind::<SqlUuid, _>(client.id)
        .bind::<Nullable<SqlUuid>, _>(None::<Uuid>)
        .bind::<Text, _>(client.client_id.as_str())
        .execute(&mut conn)
        .await
        .expect("refresh token row should insert");
    }

    async fn access_token_revocation_count(
        &self,
        client: &ClientRow,
        access_token_jti: &str,
    ) -> i64 {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        access_token_revocations::table
            .filter(access_token_revocations::tenant_id.eq(client.tenant_id))
            .filter(access_token_revocations::client_id.eq(client.id))
            .filter(
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(access_token_jti)),
            )
            .count()
            .get_result::<i64>(&mut conn)
            .await
            .expect("access token revocation count should load")
    }

    async fn refresh_token_revoked_at(
        &self,
        client: &ClientRow,
        family_id: Uuid,
    ) -> Option<DateTime<Utc>> {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
            .filter(oauth_tokens::client_id.eq(client.id))
            .filter(oauth_tokens::token_family_id.eq(family_id))
            .select(oauth_tokens::revoked_at)
            .first::<Option<DateTime<Utc>>>(&mut conn)
            .await
            .expect("refresh token row should load")
    }
}

fn live_client(client_id: &str) -> ClientRow {
    let mut client = pkce_policy_client();
    client.id = Uuid::now_v7();
    client.client_id = client_id.to_owned();
    client.client_name = "Live Token Client".to_owned();
    client.grant_types = vec!["authorization_code".to_owned(), "refresh_token".to_owned()];
    client.allowed_audiences = vec!["resource://default".to_owned()];
    client.redirect_uris = vec!["https://client.example/callback".to_owned()];
    client
}

fn payload_for_client(client: &ClientRow) -> CodePayload {
    let mut payload = code_payload(true);
    payload.client_id = client.client_id.clone();
    payload.code_challenge = Some(pkce_s256(VALID_CODE_VERIFIER));
    payload.code_challenge_method = Some("S256".to_owned());
    payload.redirect_uri = "https://client.example/callback".to_owned();
    payload.redirect_uri_was_supplied = true;
    payload.scopes = vec!["openid".to_owned()];
    payload
}

async fn token_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}
