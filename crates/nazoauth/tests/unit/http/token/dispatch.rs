use crate::test_support::token_response_body as response_body;
use response_body::oauth_error_code;

use nazo_oauth_server::domain::rows::ClientRow;
use nazo_oauth_server::services::ServerTokenService;
use nazo_oauth_server::token::ciba::CibaTokenHandles;
use nazo_oauth_server::token::dispatch::{
    Openid4vcTokenHandles, TokenCoreHandles, TokenEndpointHandles,
};

use nazo_identity::DEFAULT_ORGANIZATION_ID;

use nazo_identity::DEFAULT_REALM_ID;

use nazo_identity::DEFAULT_TENANT_ID;

use crate::test_support::TestInfrastructure;

use crate::settings::{Settings, TransportMode};

use chrono::{Duration, Utc};

use serde_json::{Value, json};

use uuid::Uuid;

use crate::http::token::dispatch::token_with_service;
use crate::test_support::hash_client_secret_fixture as hash_client_secret;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Uuid as SqlUuid};
use diesel_async::{AsyncConnection, RunQueryDsl};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

use crate::config::ConfigSource;
use nazo_postgres::{create_pool, get_conn};

use nazo_http_actix::{IpCidr, UserinfoEndpoint};
use nazo_oauth_server::policy::AuthorizationServerProfile;
use nazo_oauth_server::services::ServerAuthorizationService;

#[path = "dispatch/client_auth.rs"]
mod client_auth;
#[path = "dispatch/failure_boundaries.rs"]
mod failure_boundaries;
#[path = "dispatch/grant_routing.rs"]
mod grant_routing;
#[path = "dispatch/token_management.rs"]
mod token_management;

#[path = "dispatch_credential_issuer.rs"]
mod credential_issuer;
#[path = "dispatch/pre_authorized.rs"]
mod pre_authorized_parser_tests;

pub(crate) async fn token(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    token_with_remote_documents(
        state,
        req,
        body,
        Arc::new(
            crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                .expect("empty remote document policy is valid"),
        ),
    )
    .await
}

async fn token_with_remote_documents(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
    resolver: Arc<crate::adapters::remote_client_documents::RemoteClientDocumentResolver>,
) -> HttpResponse {
    token_with_credential_issuer(state, req, body, resolver, Openid4vcTokenHandles::default()).await
}

async fn token_with_credential_issuer(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
    resolver: Arc<crate::adapters::remote_client_documents::RemoteClientDocumentResolver>,
    openid4vc: Openid4vcTokenHandles,
) -> HttpResponse {
    token_with_port_repositories(
        state.clone(),
        Arc::new(crate::test_support::token_issuance_repository(
            state.diesel_db.clone(),
        )),
        Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            DEFAULT_TENANT_ID,
        )),
        resolver,
        openid4vc,
        req,
        body,
    )
    .await
}

async fn token_with_port_repositories(
    state: Data<TestInfrastructure>,
    token_repository: Arc<dyn nazo_auth::TokenRepositoryPort>,
    authorization_repository: Arc<dyn nazo_auth::AuthorizationRepositoryPort>,
    resolver: Arc<crate::adapters::remote_client_documents::RemoteClientDocumentResolver>,
    openid4vc: Openid4vcTokenHandles,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let service = Data::new(ServerTokenService::from_port(
        token_repository,
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    ));
    let connection = state.valkey_connection();
    let authorization_service = Data::new(ServerAuthorizationService::from_port(
        authorization_repository,
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&connection)),
        state.keyset.clone(),
    ));
    let ciba_service = Data::new(nazo_oauth_server::services::ServerCibaService::new(
        Arc::new(nazo_valkey::CibaStore::new(&connection)),
    ));
    let ciba_users: Data<dyn nazo_persistence::CibaAccountStore> = Data::from(Arc::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
    )
        as Arc<dyn nazo_persistence::CibaAccountStore>);
    let ciba_config = Arc::new(crate::http::token::ciba::ciba_config(
        state.settings.as_ref(),
    ));
    let issuance_config = Data::new(crate::http::token::issue::token_issuance_config(
        state.settings.as_ref(),
    ));
    let device_service = Data::new(nazo_oauth_server::services::ServerDeviceGrantService::new(
        Arc::new(nazo_valkey::DeviceStore::new(&connection)),
    ));
    let runtime_modules = (crate::runtime_modules::test_support::runtime_module_registry_for_test(
        state.diesel_db.clone(),
        state.settings.as_ref(),
    )
    .expect("test runtime module registry should be valid"))
    .snapshot_store();
    token_with_service(
        Data::new(TokenEndpointHandles::new(
            TokenCoreHandles {
                token_service: service.into_inner(),
                authorization_service: authorization_service.into_inner(),
                device_service: device_service.into_inner(),
                security_audit: crate::http::authorization::test_support::test_security_audit_arc(),
            },
            CibaTokenHandles::new(
                ciba_service.into_inner(),
                ciba_users.into_inner(),
                ciba_config,
            ),
            issuance_config.into_inner(),
            runtime_modules,
            resolver,
            openid4vc,
        )),
        Data::new(nazo_http_actix::ClientIpConfig::new(
            &state.settings.endpoint.trusted_proxy_cidrs,
            state.settings.endpoint.client_ip_header_mode,
        )),
        req,
        body,
    )
    .await
}

pub(crate) fn validate_token_request_profile(
    client: &ClientRow,
    auth_method: &str,
) -> Result<(), HttpResponse> {
    nazo_oauth_server::token::dispatch::validate_token_request_profile(client, auth_method)
        .map_err(nazo_http_actix::oauth_endpoint_error_response)
}

fn authorization_service(state: &TestInfrastructure) -> Data<ServerAuthorizationService> {
    let connection = state.valkey_connection();
    Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&connection)),
        state.keyset.clone(),
    ))
}

fn token_service(state: &TestInfrastructure) -> Data<ServerTokenService> {
    Data::new(ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &state.valkey_connection(),
        )),
        state.keyset.clone(),
    ))
}

async fn userinfo(state: Data<TestInfrastructure>, req: HttpRequest, body: Bytes) -> HttpResponse {
    let connection = state.valkey_connection();
    let token_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
        state.keyset.clone(),
    );
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(
            nazo_oauth_server::domain::userinfo::ServerUserinfoOperations::new(
                Arc::new(token_service),
                crate::domain::userinfo::userinfo_handles_from_test_infrastructure(state.get_ref()),
            ),
        ),
        Arc::new(crate::http::mtls::ServerMtlsThumbprintExtractor::new(
            state.settings.endpoint.trusted_proxy_cidrs.clone(),
        )),
    ));
    nazo_http_actix::userinfo(endpoint, req, body).await
}

fn fixture_secret(label: &str) -> String {
    format!("token-dispatch-fixture-secret-{label}")
}

fn fixture_secret_hash(state: &Data<TestInfrastructure>, secret: &str) -> String {
    hash_client_secret(secret, &state.settings.protocol.client_secret_pepper)
}

async fn live_token_state(profile: AuthorizationServerProfile) -> Option<Data<TestInfrastructure>> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nazo_token_dispatch_invalid:nazo_token_dispatch_invalid@127.0.0.1:1/nazo"
            .to_owned()
    });
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("TRANSPORT_MODE", "direct-tls"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("MTLS_ENDPOINT_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
        ("TOKEN_RATE_LIMIT_MAX_REQUESTS", "100000"),
    ]);
    let mut settings = Settings::from_config(&config).expect("test settings should load");
    settings.protocol.authorization_server_profile = profile;
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

    Some(Data::new(TestInfrastructure {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }))
}

async fn live_valkey_invalid_db_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<TestInfrastructure>> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        ("TRANSPORT_MODE", "direct-tls"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("MTLS_ENDPOINT_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
        ("TOKEN_RATE_LIMIT_MAX_REQUESTS", "100000"),
    ]);
    let mut settings = Settings::from_config(&config).expect("test settings should load");
    settings.protocol.authorization_server_profile = profile;
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

    Some(Data::new(TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_token_dispatch_invalid:nazo_token_dispatch_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }))
}

async fn live_rfc9440_invalid_db_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<TestInfrastructure>> {
    let state = live_valkey_invalid_db_token_state(profile).await?;
    let mut updated = (*state.settings).clone();
    updated.endpoint.transport_mode = TransportMode::TrustedProxy;
    updated.endpoint.mtls_certificate_source =
        crate::http::mtls::MtlsCertificateSourceMode::Rfc9440;
    updated.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    Some(Data::new(TestInfrastructure {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(updated),
        keyset: state.keyset.clone(),
    }))
}

async fn live_rfc9440_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<TestInfrastructure>> {
    let state = live_token_state(profile).await?;
    let mut updated = (*state.settings).clone();
    updated.endpoint.transport_mode = TransportMode::TrustedProxy;
    updated.endpoint.mtls_certificate_source =
        crate::http::mtls::MtlsCertificateSourceMode::Rfc9440;
    updated.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    Some(Data::new(TestInfrastructure {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(updated),
        keyset: state.keyset.clone(),
    }))
}

async fn token_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

#[allow(clippy::too_many_arguments)]
async fn insert_token_client(
    state: &Data<TestInfrastructure>,
    client_id: &str,
    client_type: &str,
    token_endpoint_auth_method: &str,
    client_secret_hash: Option<String>,
    grant_types: Vec<&str>,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    is_active: bool,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        DELETE FROM access_token_revocations
        USING oauth_clients
        WHERE access_token_revocations.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("test access token revocation cleanup should succeed");
    sql_query(
        r#"
        DELETE FROM oauth_tokens
        USING oauth_clients
        WHERE oauth_tokens.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("test refresh token cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("test client cleanup should succeed");

    sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
            tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            is_active, security_policy,
            post_logout_redirect_uris, backchannel_logout_session_required
        )
        VALUES (
            $1, $2, $3, $4, 'Token Dispatch Test Client', $5,
            $6, '["https://client.example/callback"]'::jsonb, '["openid","accounts"]'::jsonb,
            '["resource://default"]'::jsonb, $7, $8, $9,
            $10, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb,
            false,
            false, false,
            $11,
            '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
            '[]'::jsonb, true
        )
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_REALM_ID)
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(client_id)
    .bind::<Text, _>(client_type)
    .bind::<Nullable<Text>, _>(client_secret_hash)
    .bind::<Jsonb, _>(json!(grant_types))
    .bind::<Text, _>(token_endpoint_auth_method)
    .bind::<Bool, _>(require_dpop_bound_tokens)
    .bind::<Bool, _>(require_mtls_bound_tokens)
    .bind::<Bool, _>(is_active)
    .execute(&mut conn)
    .await
    .expect("test client insert should succeed");
}

async fn set_token_client_security_policy(
    state: &Data<TestInfrastructure>,
    client_id: &str,
    policy: nazo_auth::ClientSecurityPolicy,
) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("database connection should open");
    sql_query(
        "UPDATE oauth_clients SET security_policy = $1 WHERE tenant_id = $2 AND client_id = $3",
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(policy).expect("client security policy should serialize"),
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut connection)
    .await
    .expect("test client security policy update should succeed");
}

async fn assert_token_error(
    response: HttpResponse,
    status: StatusCode,
    error: &str,
    www_authenticate: bool,
) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers().contains_key(header::WWW_AUTHENTICATE),
        www_authenticate
    );
    let (actual_status, body) = token_json_body(response).await;
    assert_eq!(
        body.get("error")
            .and_then(serde_json::Value::as_str)
            .expect("OAuth JSON should contain an error code"),
        error
    );
    assert_eq!(actual_status, status);
    assert_eq!(body["error"], error);
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

fn token_request(content_type: &str) -> HttpRequest {
    actix_web::test::TestRequest::post()
        .uri("/token")
        .insert_header((header::CONTENT_TYPE, content_type))
        .to_http_request()
}
