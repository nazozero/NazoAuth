//! Measured per-method SQL/transaction counts for the Postgres remediation
//! matrix (section M). Every measurement:
//!
//! 1. builds a size-1 pool, installs `QueryCounter` instrumentation on the
//!    sole connection, and returns it so the production repository method
//!    reuses that instrumented connection;
//! 2. snapshots the test-only `QueryCounter` immediately before the call;
//! 3. asserts the observed deltas are *exactly* the expected numbers.
//!
//! Tests serialize their database fixtures. Production pool acquisition timing
//! and counters are absent; checkout counts are not inferred or fabricated.

// Other helpers in `support` serve sibling test binaries; this binary only
// needs `query_counter`.
#[allow(dead_code)]
mod support;

#[path = "support/password.rs"]
mod password;

#[path = "support/refresh_fixture.rs"]
mod refresh_fixture;
use refresh_fixture::RefreshFixture;

use chrono::{DateTime, Duration, Utc};
use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::{
    AccessTokenRevocation, ClientSecurityPolicy, CommitTokenIssuance, CommitTokenIssuanceResult,
    OAuthClient, RefreshToken, RefreshTokenAuthenticationContext, TokenIssuanceMode,
    TokenIssuedAuditFields, TokenRepositoryPort, TokenRevocation, UserinfoSubjectRef,
    ValidatedClientRegistration,
};
use nazo_digital_credentials::CredentialFormat;
use nazo_identity::{AccessRequestStatus, TenantContext, TenantId, UserId};
use nazo_openid4vci::{
    CredentialAccess, CredentialStoreError, CredentialStorePort, DeferredCredential,
};
use nazo_postgres::{
    AccessRequestRepository, AuthorizationRepository, DbPool, OAuthClientRepository,
    Openid4vciRepository, TokenIssuanceRepository, TokenRepository, UserRepository, create_pool,
    get_conn, run_pending_migrations,
};
use serde_json::json;
use support::query_counter::{QueryCounter, QuerySnapshot};
use uuid::Uuid;

/// Serializes DB-active fixture mutations in this file.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI query-count tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

/// Builds a size-1 pool and installs `counter` on the only connection it will
/// ever vend, so any later `get_conn` returns the instrumented connection.
async fn instrumented_pool(database_url: &str) -> (DbPool, QueryCounter) {
    let pool = create_pool(database_url, 1).expect("the single-connection pool should build");
    let counter = QueryCounter::new();
    {
        let mut connection = get_conn(&pool)
            .await
            .expect("the warm-up checkout should succeed");
        connection.set_instrumentation(counter.clone());
    }
    (pool, counter)
}

/// Runs `call` while observing test-only SQL and transaction events.
async fn measure<F, T>(counter: &QueryCounter, call: F) -> (T, QuerySnapshot)
where
    F: std::future::Future<Output = T>,
{
    let baseline = counter.snapshot();
    let result = call.await;
    let delta = counter.since(baseline);
    (result, delta)
}

fn assert_clean(delta: QuerySnapshot) {
    assert_eq!(delta.failed_queries, 0, "no statement may fail");
    assert_eq!(delta.rollbacks, 0, "no transaction may roll back");
}

fn assert_no_transaction(delta: QuerySnapshot) {
    assert_eq!(
        delta.begins, 0,
        "query-only reads must not open transactions"
    );
    assert_eq!(delta.commits, 0, "query-only reads must not commit");
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

struct Seed {
    user_id: Uuid,
    client: OAuthClient,
    registration_access_token_blake3: String,
}

async fn connect(database_url: &str) -> AsyncPgConnection {
    AsyncPgConnection::establish(database_url)
        .await
        .expect("fixture connection should establish")
}

async fn seed_user(connection: &mut AsyncPgConnection, tenant: TenantContext, user_id: Uuid) {
    sql_query(
        "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash\
         ) VALUES ($1, $2, $3, $4, $5, $6, 'query-count-only-hash')",
    )
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(tenant.realm_id.as_uuid())
    .bind::<sql_types::Uuid, _>(tenant.organization_id.as_uuid())
    .bind::<sql_types::Text, _>(format!("query-count-{user_id}"))
    .bind::<sql_types::Text, _>(format!("query-count-{user_id}@example.test"))
    .execute(connection)
    .await
    .expect("the user fixture should insert");
}

/// A complete current `OAuthClient`/`ValidatedClientRegistration` domain
/// object. The full field set mirrors `oauth_client_dcr.rs::client` so the
/// row survives every NOT NULL/CHECK/JSON-shape constraint.
fn oauth_client_fixture(
    client_id: Uuid,
    tenant: TenantContext,
    client_public_id: &str,
) -> OAuthClient {
    OAuthClient {
        id: client_id,
        tenant_id: tenant.tenant_id.as_uuid(),
        realm_id: tenant.realm_id.as_uuid(),
        organization_id: tenant.organization_id.as_uuid(),
        registration: ValidatedClientRegistration {
            client_id: client_public_id.to_owned(),
            client_name: "Query Count Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/callback".to_owned()],
            post_logout_redirect_uris: vec![],
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            allowed_audiences: vec![],
            grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: vec![],
            tls_client_auth_san_uri: vec![],
            tls_client_auth_san_ip: vec![],
            tls_client_auth_san_email: vec![],
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: ClientSecurityPolicy::default(),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}

/// Inserts the fresh user + OAuth client pair most tests need. The client row
/// is written through the production `insert` so every column stays consistent
/// with the current persisted shape.
async fn seed_principal(database_url: &str, tenant: TenantContext) -> Seed {
    let mut connection = connect(database_url).await;
    let user_id = Uuid::now_v7();
    seed_user(&mut connection, tenant, user_id).await;
    drop(connection);

    let client_id = Uuid::now_v7();
    let client = oauth_client_fixture(
        client_id,
        tenant,
        &format!("query-count-client-{}", Uuid::now_v7().simple()),
    );
    let client_secret_hash = format!("client-secret-v1:qc-salt-{client_id}:qc-digest");
    let registration_access_token_blake3 = blake3_hex(&format!("qc-reg-{}", Uuid::now_v7()));
    // Seed on a separate pool: its acquisitions happen before the measurement
    // baseline and never enter the counted window.
    let seed_pool = create_pool(database_url, 2).expect("the seed pool should build");
    OAuthClientRepository::new(seed_pool)
        .insert(
            &client,
            Some(client_secret_hash.as_str()),
            Some(registration_access_token_blake3.as_str()),
        )
        .await
        .expect("the client fixture should insert");
    Seed {
        user_id,
        client,
        registration_access_token_blake3,
    }
}

/// A deterministic context matching the sibling-test helper: `auth_time` is a
/// fixed past instant so both the insert-time CHECK (`auth_time <= issued_at`)
/// and domain validation pass.
fn refresh_context(client_public_id: &str) -> RefreshTokenAuthenticationContext {
    RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: client_public_id.to_owned(),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        id_token_sid: None,
        acr: None,
        nonce: None,
        userinfo_claim_requests: (vec![]).into(),
        id_token_claim_requests: (vec![]).into(),
    }
}

/// Raw insert of one refresh generation in the minimal three-table model: the
/// deduplicated contract row, then the family current member (a
/// `rotated_from_id` successor first moves the existing current member into
/// its spent proof). `revoked_at` stages the member's terminal timestamp.
#[allow(clippy::too_many_arguments)]
async fn seed_refresh_token_row(
    connection: &mut AsyncPgConnection,
    tenant: TenantContext,
    seed: &Seed,
    token_id: Uuid,
    family_id: Uuid,
    raw_token: &str,
    rotated_from_id: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
    dpop_jkt: Option<&str>,
) {
    let issued_at = Utc::now();
    let contract = nazo_auth::RefreshContract {
        subject: seed.user_id.to_string(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        authentication_context: refresh_context(&seed.client.client_id),
    };
    let persisted = contract.persisted();
    let contract_blake3 = persisted.blake3_digest().to_vec();
    let contract_json = serde_json::to_value(&persisted).expect("contract serializes");
    sql_query(
        r#"
        WITH contract AS (
            INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract)
            VALUES ($2, $3, $4)
            ON CONFLICT (tenant_id, contract_blake3) DO NOTHING
            RETURNING contract_blake3
        ), resolved AS (
            SELECT contract_blake3 FROM contract
            UNION ALL
            SELECT contract_blake3 FROM oauth_refresh_contracts
            WHERE tenant_id = $2 AND contract_blake3 = $3
            LIMIT 1
        ), spent AS (
            INSERT INTO oauth_refresh_spent_tokens (
                tenant_id, refresh_token_blake3, token_family_id, member_id,
                successor_member_id, spent_at, expires_at
            )
            SELECT f.tenant_id, f.current_token_blake3, f.token_family_id,
                   f.current_member_id, $1,
                   COALESCE(f.revoked_at, CURRENT_TIMESTAMP), f.current_expires_at
            FROM oauth_refresh_families AS f
            WHERE $6 IS NOT NULL
              AND f.tenant_id = $2 AND f.token_family_id = $5
              AND f.current_member_id = $6
        )
        INSERT INTO oauth_refresh_families (
            tenant_id, token_family_id, client_id, user_id, contract_blake3,
            current_member_id, current_token_blake3, current_audience,
            current_issued_at, current_expires_at, dpop_jkt, created_at,
            revoked_at
        )
        SELECT
            $2, $5, $7, $8, r.contract_blake3,
            $1, $9, '["resource://default"]'::jsonb,
            $10, $11, $13, $10, $12
        FROM resolved AS r
        ON CONFLICT (tenant_id, token_family_id) DO UPDATE SET
            current_member_id = EXCLUDED.current_member_id,
            current_token_blake3 = EXCLUDED.current_token_blake3,
            current_audience = EXCLUDED.current_audience,
            current_issued_at = EXCLUDED.current_issued_at,
            current_expires_at = EXCLUDED.current_expires_at,
            revoked_at = EXCLUDED.revoked_at
        "#,
    )
    .bind::<sql_types::Uuid, _>(token_id)
    .bind::<sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<sql_types::Binary, _>(contract_blake3)
    .bind::<sql_types::Jsonb, _>(contract_json)
    .bind::<sql_types::Uuid, _>(family_id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(rotated_from_id)
    .bind::<sql_types::Uuid, _>(seed.client.id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(Some(seed.user_id))
    .bind::<sql_types::Binary, _>(blake3::hash(raw_token.as_bytes()).as_bytes().to_vec())
    .bind::<sql_types::Timestamptz, _>(issued_at)
    .bind::<sql_types::Timestamptz, _>(issued_at + Duration::hours(1))
    .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(revoked_at)
    .bind::<sql_types::Nullable<sql_types::Text>, _>(dpop_jkt.map(str::to_owned))
    .execute(connection)
    .await
    .expect("the refresh-token fixture should insert");
}

fn new_refresh_token(
    seed: &Seed,
    tenant_id: Uuid,
    family_id: Uuid,
    raw_token: String,
    rotated_from_id: Option<Uuid>,
    dpop_jkt: Option<String>,
) -> RefreshFixture {
    let issued_at = Utc::now();
    RefreshFixture::new(
        nazo_auth::NewRefreshToken {
            raw_token,
            member_id: Uuid::now_v7(),
            tenant_id,
            family_id,
            rotated_from_id,
            lost_response_retry: None,
            client_id: seed.client.id,
            user_id: Some(seed.user_id),
            audiences: vec!["resource://default".to_owned()],
            issued_at,
            expires_at: issued_at + Duration::hours(1),
            dpop_jkt,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
            id_token_sid: None,
        },
        nazo_auth::RefreshContract {
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            audiences: vec!["resource://default".to_owned()],
            authorization_details: json!([]),
            subject: seed.user_id.to_string(),
            authentication_context: refresh_context(&seed.client.client_id),
        }
        .persisted(),
    )
}

async fn refresh_issuance(token: RefreshFixture) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        authorization_id: None,
        native_sso_source: None,
        principal_state: nazo_auth::TokenPrincipalState {
            client_epoch: 0,
            user_epoch: (token.user_id).map(|_| 0),
            subject_bound: false,
        },
        subject: (token.user_id)
            .map(|id| id.to_string())
            .unwrap_or_else(|| "client".to_owned()),
        issuance_id,
        tenant_id: token.tenant_id,
        client_id: token.client_id,
        user_id: token.user_id,
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (token.issued_at + Duration::minutes(5)).timestamp(),
        audit_fields: TokenIssuedAuditFields {
            client_id: token.contract.authentication_context.audience.clone(),
            subject_hash: blake3::hash(token.contract.subject.as_bytes())
                .to_hex()
                .to_string(),
            scope: token.contract.scopes.join(" "),
            audience: token.audiences.clone(),
        },
        refresh_token: Some(token.into_commit().await),
    }
}

async fn seed_approved_request(
    connection: &mut AsyncPgConnection,
    tenant: TenantContext,
    seed: &Seed,
) -> Uuid {
    let request_id = Uuid::now_v7();
    sql_query(
        "INSERT INTO client_access_requests (\
            id, tenant_id, user_id, site_name, site_url, request_description, status,\
            approved_client_id, resolved_at\
         ) VALUES (\
            $1, $2, $3, 'QC site', 'https://qc.example', 'integration test', $4, $5,\
            CURRENT_TIMESTAMP\
         )",
    )
    .bind::<sql_types::Uuid, _>(request_id)
    .bind::<sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(seed.user_id)
    .bind::<sql_types::Int2, _>(AccessRequestStatus::Approved.code())
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(Some(seed.client.id))
    .execute(connection)
    .await
    .expect("the access-request fixture should insert");
    request_id
}

async fn seed_token_issuance(
    connection: &mut AsyncPgConnection,
    tenant: TenantContext,
    seed: &Seed,
    jti: &str,
) {
    sql_query(
        "INSERT INTO oauth_token_issuances (\
            issuance_id, tenant_id, client_id, user_id, access_token_jti,\
            access_token_expires_at, retain_until\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(seed.client.id)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(Some(seed.user_id))
    .bind::<sql_types::Text, _>(jti)
    .bind::<sql_types::Timestamptz, _>(Utc::now() + Duration::hours(1))
    .bind::<sql_types::Timestamptz, _>(Utc::now() + Duration::hours(2))
    .execute(connection)
    .await
    .expect("the token-issuance fixture should insert");
}

async fn seed_access_revocation(
    connection: &mut AsyncPgConnection,
    tenant: TenantContext,
    seed: &Seed,
    jti: &str,
) {
    sql_query(
        "INSERT INTO access_token_revocations (\
            id, access_token_jti_blake3, client_id, tenant_id, revoked_at, expires_at\
         ) VALUES (\
            $1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour'\
         )",
    )
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<sql_types::Text, _>(blake3_hex(jti))
    .bind::<sql_types::Uuid, _>(seed.client.id)
    .bind::<sql_types::Uuid, _>(tenant.tenant_id.as_uuid())
    .execute(connection)
    .await
    .expect("the access-revocation fixture should insert");
}

/// Deletes everything the seed helpers may have inserted, child rows first so
/// foreign keys never block removal. All statements are scoped to this test's
/// fresh ids, so concurrent tests are unaffected.
async fn cleanup_seed(database_url: &str, tenant: TenantContext, seed: &Seed) {
    let Ok(mut connection) = AsyncPgConnection::establish(database_url).await else {
        return;
    };
    let tenant_id = tenant.tenant_id.as_uuid();
    let user_id = seed.user_id;
    let client_id = seed.client.id;
    let statements = [
        "DELETE FROM openid4vci_deferred_transactions WHERE token_id IN (\
            SELECT token_id FROM openid4vci_access_grants WHERE tenant_id = $1 AND subject_id = $2)",
        "DELETE FROM openid4vci_access_grants WHERE tenant_id = $1 AND subject_id = $2",
        "DELETE FROM client_access_requests WHERE tenant_id = $1 AND user_id = $2",
        "DELETE FROM oauth_token_issuances WHERE tenant_id = $1 AND (user_id = $2 OR client_id = $3)",
        "DELETE FROM access_token_revocations WHERE tenant_id = $1 AND client_id = $3",
        "DELETE FROM oauth_refresh_spent_tokens WHERE tenant_id = $1 AND token_family_id IN (\
            SELECT token_family_id FROM oauth_refresh_families WHERE tenant_id = $1 AND client_id = $3)",
        "DELETE FROM oauth_refresh_families WHERE tenant_id = $1 AND client_id = $3",
        "DELETE FROM oauth_refresh_contracts WHERE tenant_id = $1 AND NOT EXISTS (\
            SELECT 1 FROM oauth_refresh_families f WHERE f.tenant_id = $1 \
            AND f.contract_blake3 = oauth_refresh_contracts.contract_blake3)",
        "DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $3",
        "DELETE FROM users WHERE tenant_id = $1 AND id = $2",
    ];
    for statement in statements {
        let _ = sql_query(statement)
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Uuid, _>(user_id)
            .bind::<sql_types::Uuid, _>(client_id)
            .execute(&mut connection)
            .await;
    }
}

// ---------------------------------------------------------------------------
// RV-09: token revocation
// ---------------------------------------------------------------------------

/// A verified access token is access-only authority: its bytes are never
/// reinterpreted as a refresh token. The JTI retention upsert is one statement.
#[tokio::test]
async fn rv09_mixed_revocation_retains_refresh_probes_before_jti_upsert() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    let unknown_refresh = format!("qc-unknown-refresh-{}", Uuid::now_v7());
    let input = TokenRevocation {
        tenant_id: tenant.tenant_id.as_uuid(),
        client_id: seed.client.id,
        raw_token: &unknown_refresh,
        access_token: Some(AccessTokenRevocation {
            jti: format!("qc-jti-{}", Uuid::now_v7()),
            expires_at: Utc::now() + Duration::minutes(5),
        }),
    };
    let (result, delta) = measure(&counter, repository.revoke_token(input)).await;

    assert_eq!(result.expect("revocation succeeds"), 0);
    assert_eq!(
        delta.data_queries, 1,
        "verified access authority never probes refresh families"
    );
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

/// RV-09 (refresh-family path): revoking a presented refresh token is family
/// lookup + `pg_advisory_xact_lock` + one UPDATE — 3 data statements in one
/// transaction on one pooled connection. A verified access-token input cannot
/// borrow refresh-family authority even when its bytes collide with that family.
#[tokio::test]
async fn rv09_revoke_refresh_family_is_lookup_lock_and_single_update() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let family_id = Uuid::now_v7();
    let raw_token = format!("qc-refresh-{}", Uuid::now_v7());
    {
        let mut connection = connect(&database_url).await;
        seed_refresh_token_row(
            &mut connection,
            tenant,
            &seed,
            Uuid::now_v7(),
            family_id,
            &raw_token,
            None,
            None,
            None,
        )
        .await;
    }
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    let access_input = TokenRevocation {
        tenant_id: tenant.tenant_id.as_uuid(),
        client_id: seed.client.id,
        raw_token: &raw_token,
        access_token: Some(AccessTokenRevocation {
            jti: format!("qc-associated-jti-{}", Uuid::now_v7()),
            expires_at: Utc::now() + Duration::minutes(5),
        }),
    };
    let (result, access_delta) = measure(&counter, repository.revoke_token(access_input)).await;
    assert_eq!(result.expect("verified access revocation succeeds"), 0);
    assert_eq!(access_delta.data_queries, 1);
    assert_eq!(access_delta.begins, 1);
    assert_eq!(access_delta.commits, 1);
    assert_clean(access_delta);
    assert!(
        repository
            .refresh_family_active(tenant.tenant_id.as_uuid(), family_id, seed.user_id)
            .await
            .expect("refresh family state remains readable"),
        "verified access authority must leave the colliding refresh family active"
    );
    let input = TokenRevocation {
        tenant_id: tenant.tenant_id.as_uuid(),
        client_id: seed.client.id,
        raw_token: &raw_token,
        access_token: None,
    };
    let (result, delta) = measure(&counter, repository.revoke_token(input)).await;

    assert_eq!(
        result.expect("family revocation succeeds"),
        1,
        "one family member was marked revoked"
    );
    // 3 data statements: SELECT token_family_id, SELECT pg_advisory_xact_lock,
    // UPDATE oauth_refresh_families SET revoked_at. The access-token upsert never runs
    // because the raw token resolved to a refresh family first.
    assert_eq!(delta.data_queries, 3);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

/// RV-09 (replay-compensation short-circuit): without a refresh family,
/// `AuthorizationRepository::revoke_issued_tokens` needs no transaction — an
/// expiry-less call is a pure in-memory no-op, and an access-only call is the
/// single retention upsert on one checkout.
#[tokio::test]
async fn rv09_revoke_issued_tokens_short_circuits_without_a_family() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = AuthorizationRepository::new(pool);

    // Neither a revocation fact nor a family: rejected purely in memory — no
    // connection checkout, no statement.
    let (result, delta) = measure(
        &counter,
        repository.revoke_issued_tokens(
            tenant.tenant_id.as_uuid(),
            seed.client.id,
            "qc-neither-jti",
            None,
            None,
        ),
    )
    .await;
    result.expect("a no-op revocation must succeed");
    assert_eq!(delta.data_queries, 0);
    assert_no_transaction(delta);
    assert_clean(delta);

    // Access-only: one `INSERT .. ON CONFLICT DO UPDATE` retention upsert, no
    // transaction wrapper.
    let (result, delta) = measure(
        &counter,
        repository.revoke_issued_tokens(
            tenant.tenant_id.as_uuid(),
            seed.client.id,
            &format!("qc-access-only-jti-{}", Uuid::now_v7()),
            Some(Utc::now() + Duration::minutes(5)),
            None,
        ),
    )
    .await;
    result.expect("access-only revocation must succeed");
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// CA-01: authentication snapshot
// ---------------------------------------------------------------------------

/// CA-01: `authentication_snapshot` reads the client row and derives the
/// secret salt in one SELECT — the salt split happens in SQL, not in a second
/// round trip.
#[tokio::test]
async fn ca01_authentication_snapshot_is_single_combined_read() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = OAuthClientRepository::new(pool);

    let (result, delta) = measure(
        &counter,
        repository
            .authentication_snapshot(tenant.tenant_id.as_uuid(), seed.client.client_id.as_str()),
    )
    .await;

    let (client, salt, epoch) = result
        .expect("snapshot query should succeed")
        .expect("the seeded client must produce a snapshot");
    assert_eq!(client.client_id, seed.client.client_id);
    assert_eq!(
        salt.as_deref(),
        Some(format!("qc-salt-{}", seed.client.id).as_str()),
        "the salt must be derived inside the same SELECT"
    );
    assert_eq!(epoch, 0, "the client version is part of the same snapshot");
    // 1 data statement: SELECT oauth_clients row plus
    // split_part(client_secret_hash, ':', 2) as a computed column. No
    // transaction is opened for a read-only snapshot.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// RF-01: ordinary refresh rotation
// ---------------------------------------------------------------------------

/// Malformed immutable input is rejected before the repository checks out a
/// database connection.
#[tokio::test]
async fn rf00_malformed_refresh_contract_is_rejected_before_pool_checkout() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    let mut malformed = new_refresh_token(
        &seed,
        tenant_id,
        Uuid::now_v7(),
        format!("qc-malformed-{}", Uuid::now_v7()),
        None,
        None,
    );
    malformed.contract.audiences.clear();
    let input = refresh_issuance(malformed).await;
    let (result, delta) = measure(&counter, repository.commit_token_issuance(input)).await;
    assert!(
        result.is_err(),
        "malformed immutable contracts must be rejected"
    );
    assert_eq!(
        delta,
        QuerySnapshot::default(),
        "validation must precede DB work"
    );
    cleanup_seed(&database_url, tenant, &seed).await;
}

/// RF-01: `commit_token_issuance` for an ordinary rotation issues every write
/// inside one transaction on one connection. The family is read under its
/// advisory lock to validate the current member and sender binding; rotation
/// retains a bounded spent proof and updates the current member in place.
#[tokio::test]
async fn rf01_ordinary_rotation_commit_has_exact_statement_count() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let family_id = Uuid::now_v7();

    // The parent is committed through the production path on a separate seed
    // pool so its statements never enter the measurement.
    let parent_raw = format!("qc-parent-{}", Uuid::now_v7());
    let parent = {
        let seed_pool = create_pool(database_url.as_str(), 2).expect("seed pool");
        let seeder = TokenIssuanceRepository::new(seed_pool.clone());
        let input = refresh_issuance(new_refresh_token(
            &seed,
            tenant_id,
            family_id,
            parent_raw.clone(),
            None,
            Some("qc-parent-dpop".to_owned()),
        ))
        .await;
        let outcome = seeder
            .commit_token_issuance(input)
            .await
            .expect("parent issuance should commit");
        assert_eq!(outcome, CommitTokenIssuanceResult::Committed);
        TokenRepository::new(seed_pool)
            .by_raw_refresh_token(tenant_id, &parent_raw)
            .await
            .expect("parent lookup should succeed")
            .expect("the committed parent must exist")
    };
    let second_family_id = Uuid::now_v7();
    let second_parent_raw = format!("qc-parent-{}", Uuid::now_v7());
    let second_parent = {
        let seed_pool = create_pool(database_url.as_str(), 2).expect("second seed pool");
        let seeder = TokenIssuanceRepository::new(seed_pool.clone());
        let input = refresh_issuance(new_refresh_token(
            &seed,
            tenant_id,
            second_family_id,
            second_parent_raw.clone(),
            None,
            Some("qc-parent-dpop".to_owned()),
        ))
        .await;
        let outcome = seeder
            .commit_token_issuance(input)
            .await
            .expect("second parent issuance should commit");
        assert_eq!(outcome, CommitTokenIssuanceResult::Committed);
        TokenRepository::new(seed_pool)
            .by_raw_refresh_token(tenant_id, &second_parent_raw)
            .await
            .expect("second parent lookup should succeed")
            .expect("the second committed parent must exist")
    };
    assert_ne!(family_id, second_family_id);
    assert_eq!(parent.contract_key, second_parent.contract_key);

    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);
    let child = refresh_issuance(new_refresh_token(
        &seed,
        tenant_id,
        family_id,
        format!("qc-child-{}", Uuid::now_v7()),
        Some(parent.id),
        // Sender binding is family authority: the successor carries the same
        // DPoP binding as the parent it replaces.
        Some("qc-parent-dpop".to_owned()),
    ))
    .await;
    // Preserve uses four statements: the ordered principal SHARE
    // fence, shared family advisory, family SHARE read, and Required audit.
    let mut preserved = child.clone();
    preserved.issuance_id = Uuid::now_v7();
    preserved.access_token_jti = preserved.issuance_id.to_string();
    preserved.refresh_token = Some(nazo_auth::RefreshTokenCommit::UseExisting {
        authority: parent.authority(),
        rotation: None,
    });
    let (result, delta) = measure(
        &counter,
        repository.commit_token_issuance(preserved.clone()),
    )
    .await;
    assert_eq!(
        result.expect("preserve should commit"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(delta.data_queries, 4);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(delta.family_contract_cache_queries, 1);
    assert_clean(delta);

    // The next Preserve reads another family on the same one-slot connection
    // with the same typed query shape. Its prepared statement is already cached.
    let mut preserved_second = preserved;
    preserved_second.issuance_id = Uuid::now_v7();
    preserved_second.access_token_jti = preserved_second.issuance_id.to_string();
    preserved_second.refresh_token = Some(nazo_auth::RefreshTokenCommit::UseExisting {
        authority: second_parent.authority(),
        rotation: None,
    });
    let (result, delta) =
        measure(&counter, repository.commit_token_issuance(preserved_second)).await;
    assert_eq!(
        result.expect("second-family preserve should commit"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(delta.data_queries, 4);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(
        delta.family_contract_cache_queries, 0,
        "the same-mode family query must not emit CacheQuery again"
    );
    assert_clean(delta);

    let (result, delta) = measure(&counter, repository.commit_token_issuance(child)).await;

    assert_eq!(
        result.expect("rotation should commit"),
        CommitTokenIssuanceResult::Committed
    );
    // 8 data statements inside the single commit transaction:
    //   SELECT nazo_lock_token_principals (timeout, then client/user FOR SHARE)
    //   SELECT pg_advisory_xact_lock(grant scope)
    //   SELECT pg_advisory_xact_lock(family)
    //   SELECT oauth_refresh_families                      (current member check)
    //   INSERT INTO oauth_refresh_spent_tokens             (predecessor proof)
    //   DELETE FROM oauth_refresh_spent_tokens .. OFFSET   (overflow proofs)
    //   UPDATE oauth_refresh_families SET current_*        (in-place rotation)
    //   SELECT nazo_persist_security_audit_event(..)       (token_issued)
    // Rotation writes one narrow family UPDATE plus one compact spent proof —
    // the immutable contract is never rewritten.
    assert_eq!(delta.data_queries, 8);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// RF-06: lost-response successor lookup
// ---------------------------------------------------------------------------

/// RF-06: the spent edge, active direct-successor family and contract are read
/// in one joined statement. Without sender binding recovery needs no checkout.
#[tokio::test]
async fn rf06_lost_response_successor_is_single_read() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let family_id = Uuid::now_v7();
    let parent_id = Uuid::now_v7();
    let child_id = Uuid::now_v7();
    let dpop_jkt = "qc-dpop-jkt".to_owned();
    let revoked_at = Utc::now() - Duration::seconds(2);
    let parent_raw = format!("qc-parent-{}", Uuid::now_v7());
    let child_raw = format!("qc-child-{}", Uuid::now_v7());

    {
        let mut connection = connect(&database_url).await;
        seed_refresh_token_row(
            &mut connection,
            tenant,
            &seed,
            parent_id,
            family_id,
            &parent_raw,
            None,
            Some(revoked_at),
            Some(&dpop_jkt),
        )
        .await;
        seed_refresh_token_row(
            &mut connection,
            tenant,
            &seed,
            child_id,
            family_id,
            &child_raw,
            Some(parent_id),
            None,
            Some(&dpop_jkt),
        )
        .await;
    }

    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenRepository::new(pool.clone());
    // R05: the production port reads presentation and candidate together.
    let snapshots = TokenIssuanceRepository::new(pool.clone());
    let retry_started_at = Utc::now();
    for (raw, expected_member, expected_successor) in [
        (&child_raw, child_id, None),
        (&parent_raw, parent_id, Some(child_id)),
    ] {
        let (result, delta) = measure(
            &counter,
            snapshots.refresh_token_snapshot(tenant_id, raw, seed.client.id, retry_started_at),
        )
        .await;
        let snapshot = result.unwrap().expect("presentation exists");
        assert_eq!(snapshot.presented.id, expected_member);
        assert_eq!(
            snapshot.presented.token_blake3,
            *blake3::hash(raw.as_bytes()).as_bytes()
        );
        assert_eq!(
            snapshot.successor.unwrap().map(|token| token.id),
            expected_successor
        );
        assert_eq!(delta.data_queries, 1);
        assert_no_transaction(delta);
        assert_clean(delta);
    }
    for (client_id, at) in [
        (Uuid::now_v7(), retry_started_at),
        (seed.client.id, revoked_at - Duration::seconds(1)),
        (seed.client.id, revoked_at + Duration::seconds(61)),
    ] {
        let (result, delta) = measure(
            &counter,
            snapshots.refresh_token_snapshot(tenant_id, &parent_raw, client_id, at),
        )
        .await;
        let snapshot = result.unwrap().expect("original presentation still exists");
        assert_eq!(snapshot.presented.id, parent_id);
        assert!(snapshot.successor.unwrap().is_none());
        assert_eq!(delta.data_queries, 1);
        assert_no_transaction(delta);
        assert_clean(delta);
    }
    // R05 snapshot recovery includes both endpoints of the 0..=60s window.
    // Read the persisted timestamp so PostgreSQL microsecond precision cannot
    // turn an exact endpoint into a sub-microsecond before/after presentation.
    let parent_digest = *blake3::hash(parent_raw.as_bytes()).as_bytes();
    let child_digest = *blake3::hash(child_raw.as_bytes()).as_bytes();
    let persisted_spent_at = {
        #[derive(diesel::QueryableByName)]
        struct SpentTimestamp {
            #[diesel(sql_type = sql_types::Timestamptz)]
            spent_at: DateTime<Utc>,
        }

        let mut connection = connect(&database_url).await;
        sql_query(
            "SELECT spent_at FROM oauth_refresh_spent_tokens \
             WHERE tenant_id = $1 AND refresh_token_blake3 = $2",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Binary, _>(parent_digest.as_slice())
        .get_result::<SpentTimestamp>(&mut connection)
        .await
        .expect("the seeded predecessor must have a persisted spent edge")
        .spent_at
    };
    for (case, elapsed, expect_successor) in [
        ("0s", Duration::zero(), true),
        ("60s", Duration::seconds(60), true),
        (
            "60s + 1ms",
            Duration::seconds(60) + Duration::milliseconds(1),
            false,
        ),
        ("-1ms", Duration::milliseconds(-1), false),
    ] {
        let (result, delta) = measure(
            &counter,
            snapshots.refresh_token_snapshot(
                tenant_id,
                &parent_raw,
                seed.client.id,
                persisted_spent_at + elapsed,
            ),
        )
        .await;
        let snapshot = result
            .expect("the boundary snapshot read should succeed")
            .expect("the original spent presentation must remain observable");
        assert_eq!(snapshot.presented.id, parent_id, "{case}");
        assert_eq!(snapshot.presented.token_blake3, parent_digest, "{case}");
        assert_eq!(snapshot.presented.token_family_id, family_id, "{case}");
        assert_eq!(snapshot.presented.client_id, seed.client.id, "{case}");
        assert_eq!(
            snapshot.presented.revoked_at,
            Some(persisted_spent_at),
            "{case}"
        );
        let successor = snapshot
            .successor
            .expect("the intact candidate projection should not fail");
        if expect_successor {
            let successor = successor.expect("both retry-window endpoints recover the child");
            assert_eq!(successor.id, child_id, "{case}");
            assert_eq!(successor.token_blake3, child_digest, "{case}");
            assert_eq!(successor.token_family_id, family_id, "{case}");
            assert_eq!(successor.client_id, seed.client.id, "{case}");
        } else {
            assert!(
                successor.is_none(),
                "{case}: outside the inclusive retry window"
            );
        }
        assert_eq!(delta.data_queries, 1, "{case}");
        assert_no_transaction(delta);
        assert_clean(delta);
    }

    for (lookup_tenant, raw) in [
        (Uuid::now_v7(), parent_raw.as_str()),
        (tenant_id, "unknown-r05-token"),
    ] {
        let (result, delta) = measure(
            &counter,
            snapshots.refresh_token_snapshot(lookup_tenant, raw, seed.client.id, retry_started_at),
        )
        .await;
        assert!(result.unwrap().is_none());
        assert_eq!(delta.data_queries, 1);
        assert_no_transaction(delta);
        assert_clean(delta);
    }

    let parent = RefreshToken {
        id: parent_id,
        token_blake3: *blake3::hash(parent_raw.as_bytes()).as_bytes(),
        tenant_id,
        token_family_id: family_id,
        client_id: seed.client.id,
        user_id: Some(seed.user_id),
        contract_key: [0; 32],
        contract_audiences: vec!["resource://default".to_owned()],
        scopes: json!(["openid", "offline_access"]),
        audience: json!(["resource://default"]),
        authorization_details: json!([]),
        issued_at: revoked_at - Duration::minutes(5),
        expires_at: revoked_at + Duration::hours(1),
        revoked_at: Some(revoked_at),
        subject: seed.user_id.to_string(),
        dpop_jkt: Some(dpop_jkt),
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: refresh_context(&seed.client.client_id),
    };

    let (result, delta) = measure(
        &counter,
        repository.inspect_lost_response_successor(&parent, seed.client.id, Utc::now()),
    )
    .await;

    let successor = result.expect("successor lookup succeeds");
    assert_eq!(
        successor.map(|token| token.id),
        Some(child_id),
        "the seeded non-compromised child must be found"
    );
    // One joined statement keeps the spent edge, current family and immutable
    // contract in one snapshot, including the compromise and expiry predicates.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    let mut unbound_parent = parent;
    unbound_parent.dpop_jkt = None;
    let (result, delta) = measure(
        &counter,
        repository.inspect_lost_response_successor(&unbound_parent, seed.client.id, Utc::now()),
    )
    .await;
    assert!(
        result
            .expect("unbound presentations cannot recover successors")
            .is_none()
    );
    assert_eq!(delta.data_queries, 0);
    assert_no_transaction(delta);
    assert_clean(delta);

    // Current digest identity wins even if another presentation also has a
    // spent proof with those bytes. Restore the actual digest before cleanup.
    let mut connection = connect(&database_url).await;
    sql_query("UPDATE oauth_refresh_families SET current_token_blake3 = $1 WHERE tenant_id = $2 AND token_family_id = $3")
        .bind::<sql_types::Binary, _>(blake3::hash(parent_raw.as_bytes()).as_bytes().as_slice())
        .bind::<sql_types::Uuid, _>(tenant_id).bind::<sql_types::Uuid, _>(family_id)
        .execute(&mut connection).await.unwrap();
    let (result, delta) = measure(
        &counter,
        snapshots.refresh_token_snapshot(tenant_id, &parent_raw, seed.client.id, retry_started_at),
    )
    .await;
    let snapshot = result.unwrap().expect("current presentation has priority");
    assert_eq!(snapshot.presented.id, child_id);
    assert!(snapshot.successor.unwrap().is_none());
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    sql_query("UPDATE oauth_refresh_families SET current_token_blake3 = $1, dpop_jkt = NULL WHERE tenant_id = $2 AND token_family_id = $3")
        .bind::<sql_types::Binary, _>(blake3::hash(child_raw.as_bytes()).as_bytes().as_slice())
        .bind::<sql_types::Uuid, _>(tenant_id).bind::<sql_types::Uuid, _>(family_id)
        .execute(&mut connection).await.unwrap();
    let (result, delta) = measure(
        &counter,
        snapshots.refresh_token_snapshot(tenant_id, &parent_raw, seed.client.id, retry_started_at),
    )
    .await;
    let snapshot = result
        .unwrap()
        .expect("unbound spent presentation remains observable");
    assert_eq!(snapshot.presented.id, parent_id);
    assert!(
        snapshot.successor.unwrap().is_none(),
        "unbound holder cannot recover a successor"
    );
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    drop(connection);

    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// OIDC subject preparation: claims, epoch and binding in one read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_subject_preparation_reads_claims_epoch_and_binding_once() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let other_user = Uuid::now_v7();
    let public_subject = seed.user_id.to_string();
    let private_subject = format!("qc-pairwise-{}", Uuid::now_v7());
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    for subject in [&public_subject, &private_subject] {
        let (result, delta) = measure(
            &counter,
            repository.active_subject_claims(tenant_id, seed.user_id, subject),
        )
        .await;
        let snapshot = result.unwrap().unwrap();
        assert_eq!(snapshot.tenant_id, tenant_id);
        assert_eq!(snapshot.claims.subject.as_uuid(), seed.user_id);
        assert_eq!(snapshot.token_subject, *subject);
        assert_eq!(snapshot.user_epoch, 0);
        assert!(!snapshot.subject_bound);
        assert_eq!(delta.data_queries, 1);
        assert_no_transaction(delta);
        assert_clean(delta);
    }

    let mut connection = connect(&database_url).await;
    seed_user(&mut connection, tenant, other_user).await;
    sql_query(
        "INSERT INTO oauth_subject_bindings (tenant_id, subject, user_id) VALUES ($1, $2, $3)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(&private_subject)
    .bind::<sql_types::Uuid, _>(seed.user_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query("UPDATE users SET access_token_epoch = 7 WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(seed.user_id)
        .execute(&mut connection)
        .await
        .unwrap();

    let (result, delta) = measure(
        &counter,
        repository.active_subject_claims(tenant_id, seed.user_id, &private_subject),
    )
    .await;
    let snapshot = result.unwrap().unwrap();
    assert!(snapshot.subject_bound);
    assert_eq!(snapshot.user_epoch, 7);
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // The binding is looked up by tenant and subject, never pre-filtered by
    // the requested user: a different owner must be a consistency failure.
    let (result, delta) = measure(
        &counter,
        repository.active_subject_claims(tenant_id, other_user, &private_subject),
    )
    .await;
    assert!(matches!(
        result,
        Err(nazo_auth::TokenPortError::CorruptData)
    ));
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    let (result, delta) = measure(
        &counter,
        repository.active_subject_claims(Uuid::now_v7(), seed.user_id, &private_subject),
    )
    .await;
    assert!(result.unwrap().is_none());
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_user)
        .execute(&mut connection)
        .await
        .unwrap();
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// UI-01: userinfo snapshot
// ---------------------------------------------------------------------------

/// UI-01: `userinfo_snapshot` joins the subject row to the client row in a
/// single SELECT for both subject reference kinds — direct user id, and
/// non-public subject resolved through its reusable identity binding.
#[tokio::test]
async fn ui01_userinfo_snapshot_is_single_read_for_both_subject_refs() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let jti = format!("qc-userinfo-jti-{}", Uuid::now_v7());
    {
        let mut connection = connect(&database_url).await;
        seed_token_issuance(&mut connection, tenant, &seed, &jti).await;
        sql_query("INSERT INTO oauth_subject_bindings (tenant_id, subject, user_id) VALUES ($1, 'legacy-pairwise', $2) ON CONFLICT (tenant_id, subject) DO UPDATE SET user_id = EXCLUDED.user_id")
            .bind::<diesel::sql_types::Uuid, _>(tenant_id)
            .bind::<diesel::sql_types::Uuid, _>(seed.user_id)
            .execute(&mut connection).await.expect("stable subject binding should seed");
    }
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    // Direct UserId reference.
    let (result, delta) = measure(
        &counter,
        repository.userinfo_snapshot(
            tenant_id,
            UserinfoSubjectRef::UserId(seed.user_id),
            seed.client.client_id.as_str(),
        ),
    )
    .await;
    let snapshot = result
        .expect("user-id snapshot should load")
        .expect("the seeded user must produce a snapshot");
    assert_eq!(snapshot.subject.subject.as_uuid(), seed.user_id);
    assert!(snapshot.client.is_some());
    // 1 data statement: SELECT users LEFT JOIN oauth_clients ON
    // (tenant_id, client_id) — subject and client metadata are read together.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // A stable subject binding resolves in the same SELECT via an inner join.
    let (result, delta) = measure(
        &counter,
        repository.userinfo_snapshot(
            tenant_id,
            UserinfoSubjectRef::AccessToken {
                subject: "legacy-pairwise",
                jti: jti.as_str(),
            },
            seed.client.client_id.as_str(),
        ),
    )
    .await;
    let snapshot = result
        .expect("jti snapshot should load")
        .expect("the seeded issuance must produce a snapshot");
    assert_eq!(snapshot.subject.subject.as_uuid(), seed.user_id);
    assert!(snapshot.client.is_some());
    // 1 data statement: SELECT users INNER JOIN oauth_subject_bindings
    // LEFT JOIN oauth_clients — still one round trip.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// DC-01: replace_registration
// ---------------------------------------------------------------------------

/// DC-01: `replace_registration` is a single `UPDATE .. WHERE
/// registration_access_token_blake3 = expected RETURNING *` inside the shared
/// atomic audited owner — the previous UPDATE + SELECT pair is gone.
#[tokio::test]
async fn dc01_replace_registration_is_single_update_returning() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = OAuthClientRepository::new(pool);

    let (result, delta) = measure(
        &counter,
        repository.replace_registration(
            &seed.client,
            Some("client-secret-v1:rotated-salt:rotated-digest"),
            &seed.registration_access_token_blake3,
            Some("rotated-registration-token-hash"),
        ),
    )
    .await;

    let replaced = result.expect("replace_registration should succeed");
    assert_eq!(replaced.id, seed.client.id);
    // The single data query is drained and domain-validated before COMMIT.
    assert_eq!(delta.data_queries, 1);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// DF-01: deferred claim ready
// ---------------------------------------------------------------------------

/// DF-01: one complete locked projection, then one authorized lease UPDATE.
/// V02's retained authorization/current-grant decision runs once between them;
/// there is no separate unlocked intent SELECT or tentative lease on denial.
#[tokio::test]
async fn df01_deferred_claim_ready_uses_locked_projection_then_lease_update() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let issuer = Openid4vciRepository::new(
        pool.clone(),
        [0x51_u8; 32],
        std::sync::Arc::new(password::BlockingSecretVerifier),
    );

    // Fixture rows go through the production upsert/store on the instrumented
    // pool; the measurement baseline is taken after they complete.
    let access = CredentialAccess {
        authorization_id: None,
        mtls_x5t_s256: None,
        proof_origin: nazo_openid4vci::CredentialProofOrigin::RegisteredClient,
        token_id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        subject_id: seed.user_id,
        client_id: seed.client.client_id.clone(),
        configuration_ids: vec!["qc-config".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .upsert_access(&format!("qc-access-hash-{}", Uuid::now_v7()), &access)
        .await
        .expect("access grant should persist");
    let ready_at = Utc::now() + Duration::seconds(1);
    let transaction_hash = format!("qc-deferred-{}", Uuid::now_v7());
    let deferred = DeferredCredential {
        selection: None,
        id: Uuid::now_v7(),
        transaction_hash: transaction_hash.clone(),
        access: access.clone(),
        configuration_id: "qc-config".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![json!({"key_type": "software", "kid": "qc-key"})],
        payload_ciphertext: b"deferred-payload".to_vec(),
        ready_at,
        expires_at: ready_at + Duration::minutes(5),
    };
    issuer
        .store_deferred(&deferred)
        .await
        .expect("deferred transaction should persist");
    // Persist a valid future schedule, then model preparation already elapsed.
    // Fixture statements complete before the measured production call.
    let mut fixture = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_deferred_transactions \
        SET ready_at=clock_timestamp()-INTERVAL '1 second', \
            created_at=LEAST(created_at,clock_timestamp()-INTERVAL '2 seconds') WHERE id=$1",
    )
    .bind::<sql_types::Uuid, _>(deferred.id)
    .execute(&mut fixture)
    .await
    .unwrap();
    drop(fixture);

    let (result, delta) = measure(
        &counter,
        issuer.claim_ready_deferred(&transaction_hash, access.token_id, "claim-1", ready_at),
    )
    .await;

    let nazo_openid4vci::DeferredClaimOutcome::Claimed(claim) =
        result.expect("claim should succeed")
    else {
        panic!("the accepting owner must classify the ready fixture as Claimed");
    };
    assert_eq!(claim.credential.id, deferred.id);
    assert_eq!(claim.claim_id, "claim-1");
    // Historical 3-vs-1 failure is preserved in remediation evidence. The
    // accepted V02 contract costs two statements: locked facts + authorized
    // lease. The independent intent SELECT was removed, rather than allowing
    // an unauthorized tentative write to retain the old one-query budget.
    assert_eq!(delta.data_queries, 2);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// EXS-04: existence-check query-only methods
// ---------------------------------------------------------------------------

/// EXS-04: `family_active`, `access_token_revoked`, and
/// `approved_delivery_matches` are each exactly one read-only SELECT — no
/// transaction, one pooled checkout.
#[tokio::test]
async fn exs04_existence_checks_are_single_statements() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&database_url, tenant).await;
    let family_id = Uuid::now_v7();
    let jti = format!("qc-existence-jti-{}", Uuid::now_v7());
    let request_id;
    {
        let mut connection = connect(&database_url).await;
        seed_refresh_token_row(
            &mut connection,
            tenant,
            &seed,
            Uuid::now_v7(),
            family_id,
            &format!("qc-family-{}", Uuid::now_v7()),
            None,
            None,
            None,
        )
        .await;
        seed_access_revocation(&mut connection, tenant, &seed, &jti).await;
        request_id = seed_approved_request(&mut connection, tenant, &seed).await;
    }
    let (pool, counter) = instrumented_pool(&database_url).await;
    let tokens = TokenRepository::new(pool.clone());
    let requests = AccessRequestRepository::new(pool);

    // family_active — SELECT EXISTS over oauth_refresh_families.
    let (result, delta) = measure(
        &counter,
        tokens.family_active(tenant_id, family_id, seed.user_id),
    )
    .await;
    assert!(result.expect("family_active succeeds"));
    // 1 data statement: SELECT EXISTS(active member of the family).
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // access_token_revoked — SELECT EXISTS over access_token_revocations.
    let (result, delta) = measure(&counter, tokens.access_token_revoked(tenant_id, &jti)).await;
    assert!(result.expect("access_token_revoked succeeds"));
    // 1 data statement: SELECT EXISTS(revocation row for JTI hash).
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // approved_delivery_matches — request joined to the approved client.
    let (result, delta) = measure(
        &counter,
        requests.approved_delivery_matches(
            TenantId::new(tenant_id).expect("tenant id"),
            UserId::new(seed.user_id).expect("user id"),
            request_id,
            seed.client.id,
            seed.client.client_id.as_str(),
            Some(&format!(
                "client-secret-v1:qc-salt-{}:qc-digest",
                seed.client.id
            )),
        ),
    )
    .await;
    assert!(result.expect("approved_delivery_matches succeeds"));
    // 1 data statement: SELECT EXISTS over client_access_requests joined to
    // oauth_clients with the approved-client predicates.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// UP-06: idempotent access upsert
// ---------------------------------------------------------------------------

/// UP-06: a fresh upsert writes in one statement. An identical retry preserves
/// the row version and verifies its exact facts with one additional locked read;
/// a zero-row write alone cannot distinguish it from immutable-binding rejection.
#[tokio::test]
async fn up06_upsert_access_verifies_no_write_retries() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let issuer = Openid4vciRepository::new(
        pool,
        [0x52_u8; 32],
        std::sync::Arc::new(password::BlockingSecretVerifier),
    );

    let token_hash = format!("qc-access-hash-{}", Uuid::now_v7());
    let access = CredentialAccess {
        authorization_id: None,
        mtls_x5t_s256: None,
        proof_origin: nazo_openid4vci::CredentialProofOrigin::RegisteredClient,
        token_id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        subject_id: seed.user_id,
        client_id: seed.client.client_id.clone(),
        configuration_ids: vec!["qc-config".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };

    for round in 1..=2 {
        let (result, delta) = measure(&counter, issuer.upsert_access(&token_hash, &access)).await;
        result.unwrap_or_else(|error| panic!("upsert round {round} must succeed: {error}"));
        // Round one acknowledges the write. Round two's conditional upsert
        // writes nothing and a fresh locked SELECT acknowledges the exact retry.
        assert_eq!(
            delta.data_queries, round,
            "round {round} retains the precise write/retry verification budget"
        );
        assert_no_transaction(delta);
        assert_clean(delta);
    }
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// VF-01: pre-authorized access persistence
// ---------------------------------------------------------------------------

/// VF-01: `persist_pre_authorized_access` folds the active-client `FOR SHARE`
/// lock and the conditional grant upsert into one CTE statement on one
/// connection — no wrapping transaction. A `registered_client_id` mismatch is
/// rejected before any connection is acquired, and the anonymous path is the
/// same single conditional upsert. Identical retries on either path require
/// a second, locked exact-fact check without writing a new row version.
#[tokio::test]
async fn vf01_pre_authorized_access_is_one_statement_per_path() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let issuer = Openid4vciRepository::new(
        pool.clone(),
        [0x53_u8; 32],
        std::sync::Arc::new(password::BlockingSecretVerifier),
    );

    let access = CredentialAccess {
        authorization_id: None,
        mtls_x5t_s256: None,
        proof_origin: nazo_openid4vci::CredentialProofOrigin::RegisteredClient,
        token_id: Uuid::now_v7(),
        tenant_id: tenant.tenant_id.as_uuid(),
        subject_id: seed.user_id,
        client_id: seed.client.client_id.clone(),
        configuration_ids: vec!["qc-config".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };

    // A registered client id that does not match the access row must be
    // rejected purely in memory: no connection checkout, no statement.
    let (result, delta) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &format!("qc-mismatch-{}", Uuid::now_v7()),
            &access,
            Some("qc-not-the-registered-client"),
        ),
    )
    .await;
    assert!(matches!(
        result,
        Err(CredentialStoreError::InvalidTransition)
    ));
    assert_eq!(delta.data_queries, 0);
    assert_no_transaction(delta);
    assert_clean(delta);

    let registered_hash = format!("qc-access-hash-{}", Uuid::now_v7());
    // Registered path: 1 data statement — WITH active_client (FOR SHARE) +
    // conditional upsert + outcome probe in a single CTE.
    let (result, delta) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &registered_hash,
            &access,
            Some(seed.client.client_id.as_str()),
        ),
    )
    .await;
    result.expect("active-client pre-authorized persist must succeed");
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // No-write retry: the conditional upsert plus a fresh locked exact-fact
    // verification. It retains one checkout and never rewrites an identical row.
    let (result, delta) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &registered_hash,
            &access,
            Some(seed.client.client_id.as_str()),
        ),
    )
    .await;
    result.expect("an exact registered retry must succeed");
    assert_eq!(delta.data_queries, 2);
    assert_no_transaction(delta);
    assert_clean(delta);

    // Anonymous path: 1 data statement — the plain conditional upsert, no
    // oauth_clients read.
    let (result, delta) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &format!("qc-access-hash-{}", Uuid::now_v7()),
            &CredentialAccess {
                token_id: Uuid::now_v7(),
                proof_origin: nazo_openid4vci::CredentialProofOrigin::AnonymousPreAuthorized,
                ..access.clone()
            },
            None,
        ),
    )
    .await;
    result.expect("anonymous pre-authorized persist must succeed");
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);

    // Opt-in bounded measurement uses this same production owner and existing
    // instrumentation. All ordinary VF-01 assertions above always execute.
    // This is a single-writer owner-call boundary, not HTTP or capacity evidence.
    if std::env::var_os("NAZO_VCI_OWNER_MEASUREMENT").is_some() {
        const SAMPLES: usize = 100;
        #[derive(diesel::QueryableByName, Debug, PartialEq, Eq)]
        struct RowVersion {
            #[diesel(sql_type = sql_types::Uuid)]
            token_id: Uuid,
            #[diesel(sql_type = sql_types::Text)]
            row_version: String,
        }
        async fn row_versions(pool: &DbPool, subject_id: Uuid) -> Vec<RowVersion> {
            let mut connection = get_conn(pool).await.expect("version checkout succeeds");
            sql_query("SELECT token_id, xmin::text AS row_version FROM openid4vci_access_grants WHERE subject_id = $1 ORDER BY token_id")
                .bind::<sql_types::Uuid, _>(subject_id)
                .load(&mut connection)
                .await
                .expect("version read succeeds")
        }
        #[derive(diesel::QueryableByName, serde::Serialize)]
        struct Durability {
            #[diesel(sql_type = sql_types::Text)]
            fsync: String,
            #[diesel(sql_type = sql_types::Text)]
            synchronous_commit: String,
            #[diesel(sql_type = sql_types::Text)]
            full_page_writes: String,
            #[diesel(sql_type = sql_types::Text)]
            server_version: String,
        }
        let durability = {
            let mut connection = get_conn(&pool).await.expect("settings checkout succeeds");
            sql_query("SELECT current_setting('fsync') AS fsync, current_setting('synchronous_commit') AS synchronous_commit, current_setting('full_page_writes') AS full_page_writes, current_setting('server_version') AS server_version")
                .get_result::<Durability>(&mut connection)
                .await
                .expect("durability settings are readable")
        };
        assert_eq!(durability.fsync, "on");
        assert_eq!(durability.synchronous_commit, "on");
        assert_eq!(durability.full_page_writes, "on");
        let baseline = row_versions(&pool, seed.user_id).await;
        // A known mTLS binding is immutable even for this lineage-free fixture.
        // DPoP projection updates on lineage-free rows are intentionally allowed.
        let requests = (0..SAMPLES)
            .map(|_| {
                let access = CredentialAccess {
                    token_id: Uuid::now_v7(),
                    mtls_x5t_s256: Some("B".repeat(43)),
                    ..access.clone()
                };
                (blake3_hex(&access.token_id.to_string()), access)
            })
            .collect::<Vec<_>>();
        let mut phases = Vec::new();
        for (phase_index, phase) in [
            "fresh_registered_write",
            "exact_no_write_retry",
            "immutable_sender_rejection",
        ]
        .into_iter()
        .enumerate()
        {
            let versions_before = row_versions(&pool, seed.user_id).await;
            let mut samples_ns = Vec::with_capacity(SAMPLES);
            let mut queries = QuerySnapshot::default();
            let mut accepted = 0;
            let mut rejected = 0;
            let phase_started = std::time::Instant::now();
            for (hash, access) in &requests {
                let attempted = if phase_index == 2 {
                    CredentialAccess {
                        mtls_x5t_s256: Some("A".repeat(43)),
                        ..access.clone()
                    }
                } else {
                    access.clone()
                };
                let started = std::time::Instant::now();
                let (result, delta) = measure(
                    &counter,
                    issuer.persist_pre_authorized_access(
                        hash,
                        &attempted,
                        Some(seed.client.client_id.as_str()),
                    ),
                )
                .await;
                samples_ns.push(
                    u64::try_from(started.elapsed().as_nanos()).expect("bounded duration fits u64"),
                );
                if phase_index == 2 {
                    assert_eq!(result, Err(CredentialStoreError::InvalidTransition));
                    rejected += 1;
                } else {
                    result.expect("the complete owner call is accepted");
                    accepted += 1;
                }
                assert_eq!(delta.data_queries, if phase_index == 0 { 1 } else { 2 });
                assert_no_transaction(delta);
                assert_clean(delta);
                queries = queries.checked_add(delta);
            }
            let phase_seconds = phase_started.elapsed().as_secs_f64();
            let versions_after = row_versions(&pool, seed.user_id).await;
            if phase_index == 0 {
                assert_eq!(versions_after.len(), baseline.len() + SAMPLES);
            } else {
                assert_eq!(
                    versions_after, versions_before,
                    "retry/rejection may not rewrite any grant row version"
                );
            }
            assert_eq!(samples_ns.len(), SAMPLES);
            assert_eq!(accepted + rejected, SAMPLES);
            let mut ordered = samples_ns.clone();
            ordered.sort_unstable();
            phases.push(json!({
                "scenario": phase, "planned_calls": SAMPLES, "completed_calls": SAMPLES,
                "accepted": accepted, "expected_invalid_transition": rejected,
                "unexpected_errors": 0, "unstarted_calls": 0,
                "complete_call_samples_ns": samples_ns, "phase_wall_seconds": phase_seconds,
                "completed_calls_per_second": SAMPLES as f64 / phase_seconds,
                "complete_call_p50_ms": ordered[49] as f64 / 1_000_000.0,
                "complete_call_p95_ms": ordered[94] as f64 / 1_000_000.0,
                "complete_call_p99_ms": ordered[98] as f64 / 1_000_000.0,
                "data_statements": queries.data_queries, "failed_statements": queries.failed_queries,
                "pool_checkouts": serde_json::Value::Null, "pool_checkout_observation_status": "unavailable: production acquisition collection removed", "explicit_begins": queries.begins,
                "explicit_commits": queries.commits, "rollbacks": queries.rollbacks,
                "new_grant_rows": if phase_index == 0 { SAMPLES } else { 0 },
                "unchanged_existing_row_versions": phase_index != 0,
                "row_version_writes": if phase_index == 0 { SAMPLES } else { 0 }
            }));
        }
        println!(
            "NAZO_VCI_OWNER_METRICS {}",
            json!({
                "recipe": "vf01-owner-serial-3x100-v1", "sample_count_per_phase": SAMPLES,
                "percentile_method": "empirical nearest rank: sorted100 indices49/94/98",
                "boundary": "complete instrumented production repository call; one pooled connection; single writer; includes QueryCounter snapshot overhead; excludes HTTP/signature/proof processing and fixture/version-read setup",
                "drop_boundary": "unstarted_calls is planned minus completed in this closed-loop recipe; no fixed-arrival-rate dropped_iterations claim",
                "write_boundary": "row_version_writes tracks inserted/new xmin versions; unchanged xmin does not assert zero WAL or physical writes",
                "durability": durability, "phases": phases
            })
        );
    }

    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// ID-01: active subject lookup
// ---------------------------------------------------------------------------

/// ID-01: `active_subject_id_by_tenant_id` is one read-only SELECT over users.
#[tokio::test]
async fn id01_active_subject_id_by_tenant_id_is_single_read() {
    let _serial = SERIAL.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&database_url, tenant).await;
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = UserRepository::new(pool);

    let (result, delta) = measure(
        &counter,
        repository.active_subject_id_by_tenant_id(
            TenantId::new(tenant.tenant_id.as_uuid()).expect("tenant id"),
            UserId::new(seed.user_id).expect("user id"),
        ),
    )
    .await;

    assert_eq!(
        result.expect("lookup succeeds"),
        Some(seed.user_id),
        "the seeded active user must resolve"
    );
    // 1 data statement: SELECT user principal row WHERE (id, tenant_id,
    // is_active) — the subject id projection is computed in the same read.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// Ordinary OIDC refresh combines presentation and successful subject preparation.
async fn replace_oidc_refresh_contract(
    connection: &mut AsyncPgConnection,
    tenant: TenantContext,
    seed: &Seed,
    family: Uuid,
    subject: &str,
    scopes: Vec<String>,
) {
    let contract = nazo_auth::RefreshContract {
        subject: subject.to_owned(),
        scopes,
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        authentication_context: refresh_context(&seed.client.client_id),
    }
    .persisted();
    let key = contract.blake3_digest().to_vec();
    sql_query("INSERT INTO oauth_refresh_contracts (tenant_id,contract_blake3,contract) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind::<sql_types::Uuid,_>(tenant.tenant_id.as_uuid()).bind::<sql_types::Binary,_>(&key)
        .bind::<sql_types::Jsonb,_>(serde_json::to_value(contract).unwrap())
        .execute(connection).await.unwrap();
    sql_query("UPDATE oauth_refresh_families SET contract_blake3=$1 WHERE tenant_id=$2 AND token_family_id=$3")
        .bind::<sql_types::Binary,_>(key).bind::<sql_types::Uuid,_>(tenant.tenant_id.as_uuid())
        .bind::<sql_types::Uuid,_>(family).execute(connection).await.unwrap();
}

#[tokio::test]
async fn oidc_refresh_snapshot_prepares_public_and_pairwise_in_one_runtime_role_query() {
    let _serial = SERIAL.lock().await;
    let Some(url) = database_url() else {
        return;
    };
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&url, tenant).await;
    let family = Uuid::now_v7();
    let raw = format!("oidc-snapshot-{}", Uuid::now_v7());
    let mut connection = connect(&url).await;
    seed_refresh_token_row(
        &mut connection,
        tenant,
        &seed,
        Uuid::now_v7(),
        family,
        &raw,
        None,
        None,
        None,
    )
    .await;
    let role = format!("oidc_snapshot_reader_{}", Uuid::now_v7().simple());
    connection
        .batch_execute(&format!("CREATE ROLE {role} NOLOGIN"))
        .await
        .unwrap();
    nazo_postgres::configure_runtime_role(&url, &role)
        .await
        .unwrap();
    let (pool, counter) = instrumented_pool(&url).await;
    {
        let mut c = get_conn(&pool).await.unwrap();
        c.batch_execute(&format!("SET ROLE {role}")).await.unwrap();
    }
    let repository = TokenIssuanceRepository::new(pool.clone());
    for subject in [
        seed.user_id.to_string(),
        format!("oidc-pairwise-{}", Uuid::now_v7()),
    ] {
        replace_oidc_refresh_contract(
            &mut connection,
            tenant,
            &seed,
            family,
            &subject,
            vec!["openid".to_owned(), "offline_access".to_owned()],
        )
        .await;
        let private = subject != seed.user_id.to_string();
        if private {
            sql_query(
                "INSERT INTO oauth_subject_bindings(tenant_id,subject,user_id)VALUES($1,$2,$3)",
            )
            .bind::<sql_types::Uuid, _>(tenant_id)
            .bind::<sql_types::Text, _>(&subject)
            .bind::<sql_types::Uuid, _>(seed.user_id)
            .execute(&mut connection)
            .await
            .unwrap();
        }
        let (result, delta) = measure(
            &counter,
            repository.refresh_token_snapshot_with_subject(
                tenant_id,
                &raw,
                seed.client.id,
                Utc::now(),
                true,
            ),
        )
        .await;
        let snapshot = result.unwrap().unwrap();
        let prepared = snapshot.prepared_subject.unwrap();
        assert_eq!(prepared.token_subject, subject);
        assert_eq!(prepared.tenant_id, tenant_id);
        assert_eq!(prepared.claims.subject.as_uuid(), seed.user_id);
        assert_eq!(prepared.user_epoch, 0);
        assert_eq!(prepared.subject_bound, private);
        assert_eq!(delta.data_queries, 1);
        assert_no_transaction(delta);
        assert_clean(delta);
        let (_, baseline) = measure(&counter, async {
            let original = repository
                .refresh_token_snapshot(tenant_id, &raw, seed.client.id, Utc::now())
                .await
                .unwrap()
                .unwrap();
            assert!(original.prepared_subject.is_none());
            repository
                .active_subject_claims(tenant_id, seed.user_id, &original.presented.subject)
                .await
                .unwrap()
                .unwrap()
        })
        .await;
        assert_eq!(baseline.data_queries, 2);
    }
    {
        let mut c = get_conn(&pool).await.unwrap();
        c.batch_execute("RESET ROLE").await.unwrap();
    }
    connection
        .batch_execute(&format!("DROP OWNED BY {role};DROP ROLE {role}"))
        .await
        .unwrap();
    cleanup_seed(&url, tenant, &seed).await;
}

#[tokio::test]
async fn oidc_refresh_snapshot_fallback_and_non_oidc_keep_original_reads() {
    let _serial = SERIAL.lock().await;
    let Some(url) = database_url() else {
        return;
    };
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&url, tenant).await;
    let family = Uuid::now_v7();
    let raw = format!("oidc-fallback-{}", Uuid::now_v7());
    let mut c = connect(&url).await;
    seed_refresh_token_row(
        &mut c,
        tenant,
        &seed,
        Uuid::now_v7(),
        family,
        &raw,
        None,
        None,
        None,
    )
    .await;
    let (pool, counter) = instrumented_pool(&url).await;
    let repo = TokenIssuanceRepository::new(pool.clone());
    for (lookup_tenant, lookup_client, hint) in [
        (id, seed.client.id, false),
        (id, Uuid::now_v7(), true),
        (Uuid::now_v7(), seed.client.id, true),
    ] {
        let (r, q) = measure(
            &counter,
            repo.refresh_token_snapshot_with_subject(
                lookup_tenant,
                &raw,
                lookup_client,
                Utc::now(),
                hint,
            ),
        )
        .await;
        assert!(r.unwrap().is_none_or(|s| s.prepared_subject.is_none()));
        assert_eq!(q.data_queries, 1);
    }
    sql_query("UPDATE users SET is_active=false WHERE tenant_id=$1 AND id=$2")
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(seed.user_id)
        .execute(&mut c)
        .await
        .unwrap();
    let (r, q) = measure(
        &counter,
        repo.refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true),
    )
    .await;
    assert!(r.unwrap().unwrap().prepared_subject.is_none());
    assert_eq!(q.data_queries, 1);
    // A single-connection temporary users table permits corrupt profile data
    // without altering the real users CHECK/FK constraints or its rows.
    {
        let mut profile = get_conn(&pool).await.unwrap();
        profile
            .batch_execute("CREATE TEMP TABLE users (LIKE public.users INCLUDING DEFAULTS)")
            .await
            .unwrap();
        sql_query("INSERT INTO users SELECT * FROM public.users WHERE id=$1")
            .bind::<sql_types::Uuid, _>(seed.user_id)
            .execute(&mut profile)
            .await
            .unwrap();
        profile
            .batch_execute("UPDATE users SET is_active=true,role='corrupt-role'")
            .await
            .unwrap();
    }
    let (r, q) = measure(
        &counter,
        repo.refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true),
    )
    .await;
    assert!(r.unwrap().unwrap().prepared_subject.is_none());
    assert_eq!(q.data_queries, 1);
    // A non-OIDC contract must not turn a corrupt, unused profile into an error.
    replace_oidc_refresh_contract(
        &mut c,
        tenant,
        &seed,
        family,
        &seed.user_id.to_string(),
        vec!["offline_access".to_owned()],
    )
    .await;
    let (r, q) = measure(
        &counter,
        repo.refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true),
    )
    .await;
    assert!(r.unwrap().unwrap().prepared_subject.is_none());
    assert_eq!(q.data_queries, 1);
    {
        let mut profile = get_conn(&pool).await.unwrap();
        profile
            .batch_execute("DROP TABLE pg_temp.users")
            .await
            .unwrap();
    }
    // Restore the principal, then retain any wrong binding owner as a collision.
    sql_query("UPDATE users SET is_active=true,realm_id=$1,role='user' WHERE id=$2")
        .bind::<sql_types::Uuid, _>(tenant.realm_id.as_uuid())
        .bind::<sql_types::Uuid, _>(seed.user_id)
        .execute(&mut c)
        .await
        .unwrap();
    let subject = format!("oidc-collision-{}", Uuid::now_v7());
    let other = Uuid::now_v7();
    seed_user(&mut c, tenant, other).await;
    replace_oidc_refresh_contract(
        &mut c,
        tenant,
        &seed,
        family,
        &subject,
        vec!["openid".to_owned()],
    )
    .await;
    sql_query("INSERT INTO oauth_subject_bindings(tenant_id,subject,user_id)VALUES($1,$2,$3)")
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Text, _>(&subject)
        .bind::<sql_types::Uuid, _>(other)
        .execute(&mut c)
        .await
        .unwrap();
    let (r, q) = measure(
        &counter,
        repo.refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true),
    )
    .await;
    assert!(r.unwrap().unwrap().prepared_subject.is_none());
    assert_eq!(q.data_queries, 1);
    assert!(matches!(
        repo.active_subject_claims(id, seed.user_id, &subject).await,
        Err(nazo_auth::TokenPortError::CorruptData)
    ));
    sql_query("DELETE FROM oauth_subject_bindings WHERE tenant_id=$1 AND subject=$2")
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Text, _>(&subject)
        .execute(&mut c)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id=$1")
        .bind::<sql_types::Uuid, _>(other)
        .execute(&mut c)
        .await
        .unwrap();
    cleanup_seed(&url, tenant, &seed).await;
}

#[tokio::test]
async fn oidc_refresh_early_profile_is_coherent_and_final_fences_reject_changes() {
    let _serial = SERIAL.lock().await;
    let Some(url) = database_url() else {
        return;
    };
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&url, tenant).await;
    let family = Uuid::now_v7();
    let raw = format!("oidc-early-{}", Uuid::now_v7());
    let mut c = connect(&url).await;
    seed_refresh_token_row(
        &mut c,
        tenant,
        &seed,
        Uuid::now_v7(),
        family,
        &raw,
        None,
        None,
        None,
    )
    .await;
    sql_query("UPDATE users SET display_name='before snapshot' WHERE id=$1")
        .bind::<sql_types::Uuid, _>(seed.user_id)
        .execute(&mut c)
        .await
        .unwrap();
    let repo = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
    let early = repo
        .refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true)
        .await
        .unwrap()
        .unwrap();
    let prepared = early.prepared_subject.unwrap();
    let epoch = prepared.user_epoch;
    sql_query("UPDATE users SET display_name='after snapshot' WHERE id=$1")
        .bind::<sql_types::Uuid, _>(seed.user_id)
        .execute(&mut c)
        .await
        .unwrap();
    let late = repo
        .active_subject_claims(id, seed.user_id, &early.presented.subject)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prepared.claims.name.as_deref(), Some("before snapshot"));
    assert_eq!(late.claims.name.as_deref(), Some("after snapshot"));
    assert_eq!(late.user_epoch, epoch);
    for case in ["user epoch", "client epoch", "family revoked"] {
        let authenticated_client_epoch = OAuthClientRepository::new(create_pool(&url, 1).unwrap())
            .authentication_snapshot(id, &seed.client.client_id)
            .await
            .unwrap()
            .unwrap()
            .2;
        let source = repo
            .refresh_token_snapshot_with_subject(id, &raw, seed.client.id, Utc::now(), true)
            .await
            .unwrap()
            .unwrap();
        let profile = source.prepared_subject.unwrap();
        let mut input = refresh_issuance(new_refresh_token(
            &seed,
            id,
            family,
            format!("unused-{}", Uuid::now_v7()),
            None,
            None,
        ))
        .await;
        input.subject = profile.token_subject;
        input.principal_state.user_epoch = Some(profile.user_epoch);
        input.principal_state.subject_bound = profile.subject_bound;
        input.refresh_token = Some(nazo_auth::RefreshTokenCommit::UseExisting {
            authority: source.presented.authority(),
            rotation: None,
        });
        let (sql, key, expected) = match case {
            "user epoch" => (
                "UPDATE users SET access_token_epoch=access_token_epoch+1 WHERE id=$1",
                seed.user_id,
                CommitTokenIssuanceResult::SubjectInactive,
            ),
            "client epoch" => (
                "UPDATE oauth_clients SET access_token_epoch=access_token_epoch+1 WHERE id=$1",
                seed.client.id,
                CommitTokenIssuanceResult::ClientInactive,
            ),
            _ => (
                "UPDATE oauth_refresh_families SET revoked_at=CURRENT_TIMESTAMP WHERE token_family_id=$1",
                family,
                CommitTokenIssuanceResult::RefreshGrantUnavailable,
            ),
        };
        if case == "user epoch" {
            for active in [false, true] {
                sql_query("UPDATE users SET is_active=$1 WHERE id=$2")
                    .bind::<sql_types::Bool, _>(active)
                    .bind::<sql_types::Uuid, _>(key)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
        } else {
            sql_query(sql)
                .bind::<sql_types::Uuid, _>(key)
                .execute(&mut c)
                .await
                .unwrap();
        }
        // Never endorse the subject snapshot with a newer authentication epoch.
        input.principal_state.client_epoch = authenticated_client_epoch;
        let issuance_id = input.issuance_id;
        assert_eq!(repo.commit_token_issuance(input).await.unwrap(), expected);
        #[derive(diesel::QueryableByName)]
        struct AuditCount {
            #[diesel(sql_type=sql_types::BigInt)]
            count: i64,
        }
        let count=sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type='token_issued' AND payload->>'issuance_id'=$1")
            .bind::<sql_types::Text,_>(issuance_id.to_string()).get_result::<AuditCount>(&mut c).await.unwrap();
        assert_eq!(count.count, 0);
    }
    cleanup_seed(&url, tenant, &seed).await;
}

#[tokio::test]
async fn refresh_lookup_prepared_cache_reuses_two_shapes_and_isolates_binds() {
    let _serial = SERIAL.lock().await;
    let Some(url) = database_url() else {
        return;
    };
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let tenant_id = tenant.tenant_id.as_uuid();
    let seed = seed_principal(&url, tenant).await;
    let mut connection = connect(&url).await;
    let mut fixtures = Vec::new();
    for _ in 0..2 {
        let family = Uuid::now_v7();
        let member = Uuid::now_v7();
        let raw = format!("lookup-cache-{}", Uuid::now_v7());
        seed_refresh_token_row(
            &mut connection,
            tenant,
            &seed,
            member,
            family,
            &raw,
            None,
            None,
            None,
        )
        .await;
        replace_oidc_refresh_contract(
            &mut connection,
            tenant,
            &seed,
            family,
            &seed.user_id.to_string(),
            vec!["openid".to_owned(), "offline_access".to_owned()],
        )
        .await;
        fixtures.push((member, raw));
    }
    #[derive(diesel::QueryableByName)]
    struct CacheState {
        #[diesel(sql_type = sql_types::Integer)]
        backend_pid: i32,
        #[diesel(sql_type = sql_types::BigInt)]
        plain_count: i64,
        #[diesel(sql_type = sql_types::BigInt)]
        prepared_count: i64,
        #[diesel(sql_type = sql_types::BigInt)]
        plain_executions: i64,
        #[diesel(sql_type = sql_types::BigInt)]
        prepared_executions: i64,
        #[diesel(sql_type = sql_types::Bool)]
        parameter_types_match: bool,
    }
    async fn cache_state(pool: &DbPool) -> CacheState {
        let mut connection = get_conn(pool).await.unwrap();
        sql_query(
            "SELECT pg_backend_pid() AS backend_pid, \
             count(*) FILTER (WHERE position('NULL::jsonb AS prepared_subject' in statement)>0) AS plain_count, \
             count(*) FILTER (WHERE position('to_jsonb(profile)' in statement)>0) AS prepared_count, \
             coalesce(sum(generic_plans+custom_plans) FILTER (WHERE position('NULL::jsonb AS prepared_subject' in statement)>0),0)::bigint AS plain_executions, \
             coalesce(sum(generic_plans+custom_plans) FILTER (WHERE position('to_jsonb(profile)' in statement)>0),0)::bigint AS prepared_executions, \
             coalesce(bool_and(CASE WHEN position('to_jsonb(profile)' in statement)>0 \
               THEN parameter_types=ARRAY['uuid'::regtype,'bytea'::regtype,'uuid'::regtype] \
               ELSE parameter_types=ARRAY['uuid'::regtype,'bytea'::regtype] END),true) AS parameter_types_match \
             FROM pg_prepared_statements WHERE statement LIKE 'WITH presentation AS (%'",
        )
        .get_result(&mut connection)
        .await
        .unwrap()
    }
    let pool = create_pool(&url, 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let before = cache_state(&pool).await;
    assert_eq!((before.plain_count, before.prepared_count), (0, 0));
    for _ in 0..3 {
        for (member, raw) in &fixtures {
            for prepared in [false, true] {
                let result = repository
                    .refresh_token_snapshot_with_subject(
                        tenant_id,
                        raw,
                        seed.client.id,
                        Utc::now(),
                        prepared,
                    )
                    .await;
                let snapshot = result.unwrap().unwrap();
                assert_eq!(snapshot.presented.id, *member);
                assert_eq!(snapshot.presented.tenant_id, tenant_id);
                assert_eq!(snapshot.prepared_subject.is_some(), prepared);
            }
        }
    }
    let unknown = format!("lookup-cache-missing-{}", Uuid::now_v7());
    for prepared in [false, true] {
        for (lookup_tenant, raw) in [
            (Uuid::now_v7(), fixtures[0].1.as_str()),
            (tenant_id, unknown.as_str()),
        ] {
            let result = repository
                .refresh_token_snapshot_with_subject(
                    lookup_tenant,
                    raw,
                    seed.client.id,
                    Utc::now(),
                    prepared,
                )
                .await;
            assert!(result.unwrap().is_none());
        }
    }
    let result = repository
        .refresh_token_snapshot_with_subject(
            tenant_id,
            &fixtures[0].1,
            Uuid::now_v7(),
            Utc::now(),
            true,
        )
        .await;
    let foreign_client = result.unwrap().unwrap();
    assert_eq!(foreign_client.presented.id, fixtures[0].0);
    assert!(foreign_client.prepared_subject.is_none());

    let after = cache_state(&pool).await;
    assert_eq!(before.backend_pid, after.backend_pid);
    assert_eq!((after.plain_count, after.prepared_count), (1, 1));
    assert_eq!((after.plain_executions, after.prepared_executions), (8, 9));
    assert!(after.parameter_types_match);
    eprintln!(
        "REFRESH_LOOKUP_CACHE same_backend=true statements=2 plain_executions=8 prepared_executions=9 parameter_types_match=true bind_isolation=true"
    );
    cleanup_seed(&url, tenant, &seed).await;
}

#[tokio::test]
async fn refresh_contract_prepared_shape_preserves_distinct_contracts() {
    let _serial = SERIAL.lock().await;
    let url = database_url().expect("isolated PostgreSQL required");
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&url, tenant).await;
    let pool = create_pool(&url, 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    for index in 0..2 {
        let mut token = new_refresh_token(
            &seed,
            tenant.tenant_id.as_uuid(),
            Uuid::now_v7(),
            format!("cache-contract-{}", Uuid::now_v7()),
            None,
            None,
        );
        if index == 1 {
            token.contract.scopes.push("profile".to_owned());
        }
        assert!(matches!(
            repository
                .commit_token_issuance(refresh_issuance(token).await)
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        ));
    }
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type=sql_types::BigInt)]
        count: i64,
    }
    let mut c = get_conn(&pool).await.unwrap();
    let cached=sql_query("SELECT count(*)::bigint AS count FROM pg_prepared_statements WHERE statement LIKE 'SELECT outcome, retired_source FROM public.nazo_create_refresh_family(%' AND generic_plans+custom_plans=2").get_result::<Count>(&mut c).await.unwrap().count;
    assert_eq!(
        cached, 1,
        "one cached shape must execute both contract binds"
    );
    let distinct=sql_query("SELECT count(DISTINCT contract_blake3)::bigint AS count FROM oauth_refresh_families WHERE client_id=$1").bind::<sql_types::Uuid,_>(seed.client.id).get_result::<Count>(&mut c).await.unwrap().count;
    assert_eq!(
        distinct, 2,
        "prepared execution must not reuse the first contract payload"
    );
    drop(c);
    cleanup_seed(&url, tenant, &seed).await;
}

#[tokio::test]
async fn new_family_capacity_transition_has_bounded_round_trips_and_complete_evidence() {
    let _serial = SERIAL.lock().await;
    let url = database_url().expect("isolated PostgreSQL required");
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&url, tenant).await;
    let (pool, counter) = instrumented_pool(&url).await;
    let repository = TokenIssuanceRepository::new(pool.clone());
    let mut families = Vec::new();
    let mut counts = Vec::new();
    for _ in 0..13 {
        let family_id = Uuid::now_v7();
        families.push(family_id);
        let input = refresh_issuance(new_refresh_token(
            &seed,
            tenant.tenant_id.as_uuid(),
            family_id,
            format!("bounded-create-{}", Uuid::now_v7()),
            None,
            None,
        ))
        .await;
        let (outcome, delta) = measure(&counter, repository.commit_token_issuance(input)).await;
        assert_eq!(outcome.unwrap(), CommitTokenIssuanceResult::Committed);
        assert_clean(delta);
        assert_eq!((delta.begins, delta.commits), (1, 1));
        counts.push(delta.data_queries);
    }
    #[derive(diesel::QueryableByName)]
    struct Facts {
        #[diesel(sql_type=sql_types::Array<sql_types::Uuid>)]
        retired: Vec<Uuid>,
        #[diesel(sql_type=sql_types::BigInt)]
        live: i64,
        #[diesel(sql_type=sql_types::BigInt)]
        retire_events: i64,
        #[diesel(sql_type=sql_types::BigInt)]
        issued_events: i64,
    }
    let mut c = get_conn(&pool).await.unwrap();
    let facts = sql_query("SELECT         ARRAY(SELECT token_family_id FROM oauth_refresh_families WHERE tenant_id=$1 AND client_id=$2 AND revoked_at IS NOT NULL ORDER BY current_issued_at, token_family_id) AS retired,         (SELECT count(*) FROM oauth_refresh_families WHERE tenant_id=$1 AND client_id=$2 AND revoked_at IS NULL) AS live,         (SELECT count(*) FROM security_audit_events WHERE event_type='refresh_family_capacity_retired' AND payload->>'client_id'=$2::text AND payload->>'tenant_id'=$1::text) AS retire_events,         (SELECT count(*) FROM security_audit_events WHERE event_type='token_issued' AND payload->>'client_id'=$3 AND payload->>'tenant_id'=$1::text) AS issued_events")
        .bind::<sql_types::Uuid,_>(tenant.tenant_id.as_uuid())
        .bind::<sql_types::Uuid,_>(seed.client.id)
        .bind::<sql_types::Text,_>(&seed.client.client_id)
        .get_result::<Facts>(&mut c).await.unwrap();
    assert_eq!(facts.retired, families[..3]);
    assert_eq!(
        (facts.live, facts.retire_events, facts.issued_events),
        (10, 3, 13)
    );
    drop(c);
    cleanup_seed(&url, tenant, &seed).await;
    eprintln!(
        "NEW_FAMILY_ROUND_TRIPS counts={counts:?} confirmed_commits=13 live=10 retired=3 issued_audit=13 retired_audit=3"
    );
    assert!(
        counts.iter().all(|n| *n <= 3),
        "new-family creation must not add client round trips for each locked capacity retirement: {counts:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_fence_timeout_covers_later_locks_and_resets_at_transaction_end() {
    use diesel_async::SimpleAsyncConnection as _;
    let _serial = SERIAL.lock().await;
    let url = database_url().expect("isolated PostgreSQL required");
    run_pending_migrations(&url).await.unwrap();
    let tenant = TenantContext::default_system();
    let seed = seed_principal(&url, tenant).await;
    let input = refresh_issuance(new_refresh_token(
        &seed,
        tenant.tenant_id.as_uuid(),
        Uuid::now_v7(),
        format!("timeout-{}", Uuid::now_v7()),
        None,
        None,
    ))
    .await;
    let pool = create_pool(&url, 1).unwrap();
    let mut c = get_conn(&pool).await.unwrap();
    #[derive(diesel::QueryableByName)]
    struct Setting {
        #[diesel(sql_type=sql_types::Text)]
        value: String,
    }
    let before = sql_query("SELECT current_setting('lock_timeout') AS value")
        .get_result::<Setting>(&mut c)
        .await
        .unwrap()
        .value;
    c.batch_execute("BEGIN").await.unwrap();
    sql_query("SELECT * FROM public.nazo_lock_token_principals($1,$2,$3,$4,$5)")
        .bind::<sql_types::Uuid, _>(input.tenant_id)
        .bind::<sql_types::Uuid, _>(input.client_id)
        .bind::<sql_types::BigInt, _>(input.principal_state.client_epoch)
        .bind::<sql_types::Nullable<sql_types::Uuid>, _>(input.user_id)
        .bind::<sql_types::Nullable<sql_types::BigInt>, _>(input.principal_state.user_epoch)
        .execute(&mut c)
        .await
        .unwrap();
    let after_call = sql_query("SELECT current_setting('lock_timeout') AS value")
        .get_result::<Setting>(&mut c)
        .await
        .unwrap()
        .value;
    assert_eq!(
        after_call, "2s",
        "later receipt and family locks retain the timeout"
    );
    c.batch_execute("ROLLBACK").await.unwrap();
    let after_transaction = sql_query("SELECT current_setting('lock_timeout') AS value")
        .get_result::<Setting>(&mut c)
        .await
        .unwrap()
        .value;
    assert_eq!(
        after_transaction, before,
        "the next pool borrower inherits no local setting"
    );
    drop(c);
    cleanup_seed(&url, tenant, &seed).await;
}
