//! Measured per-method SQL/transaction counts for the Postgres remediation
//! matrix (section M). Every measurement:
//!
//! 1. builds a size-1 pool, installs `QueryCounter` instrumentation on the
//!    sole connection, and returns it so the production repository method
//!    reuses that instrumented connection;
//! 2. snapshots `QueryCounter` plus the process-global
//!    `db_pool_metrics().acquire_count` immediately before the call;
//! 3. asserts the observed deltas are *exactly* the expected numbers.
//!
//! `acquire_count` is process-global, so every test holds `SERIAL` for the
//! entire measurement: while the lock is held no other test in this binary can
//! perform pool work, which makes each acquire delta exclusive.

// Other helpers in `support` serve sibling test binaries; this binary only
// needs `query_counter`.
#[allow(dead_code)]
mod support;

#[path = "support/password.rs"]
mod password;

use chrono::{DateTime, Duration, Utc};
use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    AccessTokenRevocation, ClientSecurityPolicy, CommitTokenIssuance, CommitTokenIssuanceResult,
    NewRefreshToken, OAuthClient, RefreshToken, RefreshTokenAuthenticationContext,
    TokenIssuanceMode, TokenIssuedAuditFields, TokenRepositoryPort, TokenRevocation,
    UserinfoSubjectRef, ValidatedClientRegistration,
};
use nazo_digital_credentials::CredentialFormat;
use nazo_identity::{AccessRequestStatus, TenantContext, TenantId, UserId};
use nazo_openid4vci::{
    CredentialAccess, CredentialStoreError, CredentialStorePort, DeferredCredential,
};
use nazo_postgres::{
    AccessRequestRepository, AuthorizationRepository, DbPool, OAuthClientRepository,
    Openid4vciRepository, TokenIssuanceRepository, TokenRepository, UserRepository, create_pool,
    db_pool_metrics, get_conn, run_pending_migrations,
};
use serde_json::json;
use support::query_counter::{QueryCounter, QuerySnapshot};
use uuid::Uuid;

/// Serializes every DB-active test in this file so the process-global
/// `db_pool_metrics().acquire_count` deltas are exclusive to the call under
/// measurement.
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

/// Runs `call` while measuring query events and pool acquisitions. The pool
/// acquire counter is process-global; the caller must hold `SERIAL`.
async fn measure<F, T>(counter: &QueryCounter, call: F) -> (T, QuerySnapshot, u64)
where
    F: std::future::Future<Output = T>,
{
    let acquires_before = db_pool_metrics().acquire_count;
    let baseline = counter.snapshot();
    let result = call.await;
    let delta = counter.since(baseline);
    let acquires = db_pool_metrics().acquire_count - acquires_before;
    (result, delta, acquires)
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
        userinfo_claims: vec![],
        userinfo_claim_requests: vec![],
        id_token_claims: vec![],
        id_token_claim_requests: vec![],
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
) -> NewRefreshToken {
    let issued_at = Utc::now();
    NewRefreshToken {
        raw_token,
        member_id: Uuid::now_v7(),
        tenant_id,
        family_id,
        rotated_from_id,
        lost_response_retry: None,
        client_id: seed.client.id,
        user_id: Some(seed.user_id),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        subject: seed.user_id.to_string(),
        dpop_jkt,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: refresh_context(&seed.client.client_id),
    }
}

fn refresh_issuance(token: NewRefreshToken) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        issuance_id,
        tenant_id: token.tenant_id,
        client_id: token.client_id,
        user_id: token.user_id,
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (token.issued_at + Duration::minutes(5)).timestamp(),
        audit_fields: TokenIssuedAuditFields {
            client_id: token.authentication_context.audience.clone(),
            subject_hash: blake3::hash(token.subject.as_bytes()).to_hex().to_string(),
            scope: token.scopes.join(" "),
            audience: token.audiences.clone(),
        },
        refresh_token: Some(token),
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

/// RV-09 (access-token path): revoking one access-token JTI is a family lookup
/// plus a single `INSERT .. ON CONFLICT` upsert — 2 data statements inside one
/// transaction on one pooled connection.
#[tokio::test]
async fn rv09_revoke_access_token_jti_is_lookup_plus_single_upsert() {
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
    let (result, delta, acquires) = measure(&counter, repository.revoke_token(input)).await;

    assert_eq!(result.expect("revocation succeeds"), 0);
    // 3 data statements: the digest probe on oauth_refresh_families misses,
    // the spent-proof probe on oauth_refresh_spent_tokens also misses (a spent
    // token still names its family for revocation), then the single
    // INSERT .. ON CONFLICT DO UPDATE upsert into access_token_revocations.
    // The JTI write is one statement, not an insert-then-select pair.
    assert_eq!(delta.data_queries, 3);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(acquires, 1, "one pooled checkout for the whole revocation");
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

/// RV-09 (refresh-family path): revoking a presented refresh token is family
/// lookup + `pg_advisory_xact_lock` + one UPDATE — 3 data statements in one
/// transaction on one pooled connection. The attached access-token JTI is
/// never upserted once the family matches.
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

    let input = TokenRevocation {
        tenant_id: tenant.tenant_id.as_uuid(),
        client_id: seed.client.id,
        raw_token: &raw_token,
        access_token: Some(AccessTokenRevocation {
            jti: format!("qc-associated-jti-{}", Uuid::now_v7()),
            expires_at: Utc::now() + Duration::minutes(5),
        }),
    };
    let (result, delta, acquires) = measure(&counter, repository.revoke_token(input)).await;

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
    assert_eq!(acquires, 1, "one pooled checkout for the whole revocation");
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
    let (result, delta, acquires) = measure(
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
    assert_eq!(acquires, 0);
    assert_clean(delta);

    // Access-only: one `INSERT .. ON CONFLICT DO UPDATE` retention upsert, no
    // transaction wrapper.
    let (result, delta, acquires) = measure(
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
    assert_eq!(acquires, 1);
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

    let (result, delta, acquires) = measure(
        &counter,
        repository
            .authentication_snapshot(tenant.tenant_id.as_uuid(), seed.client.client_id.as_str()),
    )
    .await;

    let (client, salt) = result
        .expect("snapshot query should succeed")
        .expect("the seeded client must produce a snapshot");
    assert_eq!(client.client_id, seed.client.client_id);
    assert_eq!(
        salt.as_deref(),
        Some(format!("qc-salt-{}", seed.client.id).as_str()),
        "the salt must be derived inside the same SELECT"
    );
    // 1 data statement: SELECT oauth_clients row plus
    // split_part(client_secret_hash, ':', 2) as a computed column. No
    // transaction is opened for a read-only snapshot.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// RF-01: ordinary refresh rotation
// ---------------------------------------------------------------------------

/// RF-01: `commit_token_issuance` for an ordinary rotation issues every write
/// inside one transaction on one connection. The rotated-from parent is
/// updated with `UPDATE .. WHERE revoked_at IS NULL RETURNING
/// oidc_auth_context` — the parent row is *not* loaded first; that removed
/// SELECT is the remediation under test.
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
        ));
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
    ));
    let (result, delta, acquires) =
        measure(&counter, repository.commit_token_issuance(child)).await;

    assert_eq!(
        result.expect("rotation should commit"),
        CommitTokenIssuanceResult::Committed
    );
    // 11 data statements inside the single commit transaction:
    //   SET LOCAL lock_timeout
    //   SELECT is_active FROM oauth_clients .. FOR SHARE
    //   SELECT is_active FROM users .. FOR SHARE          (user_id is Some)
    //   INSERT INTO oauth_token_issuances                  (issuance fence)
    //   SELECT pg_advisory_xact_lock(grant scope)
    //   SELECT pg_advisory_xact_lock(family)
    //   SELECT oauth_refresh_families                      (current member check)
    //   INSERT INTO oauth_refresh_spent_tokens             (predecessor proof)
    //   DELETE FROM oauth_refresh_spent_tokens .. LIMIT    (generation bound)
    //   UPDATE oauth_refresh_families SET current_*        (in-place rotation)
    //   SELECT nazo_persist_security_audit_event(..)       (token_issued)
    // Rotation writes one narrow family UPDATE plus one compact spent proof —
    // the immutable contract is never rewritten.
    assert_eq!(delta.data_queries, 11);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(acquires, 1, "the whole saga runs on one pooled checkout");
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// RF-06: lost-response successor lookup
// ---------------------------------------------------------------------------

/// RF-06: `inspect_lost_response_successor` locates the non-compromised
/// successor in one SELECT — the `NOT EXISTS` compromise guard is a subquery
/// inside that same statement.
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
    let repository = TokenRepository::new(pool);
    let parent = RefreshToken {
        id: parent_id,
        token_blake3: *blake3::hash(parent_raw.as_bytes()).as_bytes(),
        tenant_id,
        token_family_id: family_id,
        client_id: seed.client.id,
        user_id: Some(seed.user_id),
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

    let (result, delta, acquires) = measure(
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
    // 1 data statement: SELECT .. WHERE rotated_from_id = parent AND
    // NOT EXISTS (compromised family member) — the compromise check lives in
    // the same SQL statement as the successor predicates.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// UI-01: userinfo snapshot
// ---------------------------------------------------------------------------

/// UI-01: `userinfo_snapshot` joins the subject row to the client row in a
/// single SELECT for both subject reference kinds — direct user id, and
/// access-token JTI resolved through an inner join to oauth_token_issuances.
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
    }
    let (pool, counter) = instrumented_pool(&database_url).await;
    let repository = TokenIssuanceRepository::new(pool);

    // Direct UserId reference.
    let (result, delta, acquires) = measure(
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
    assert_eq!(acquires, 1);
    assert_clean(delta);

    // AccessTokenJti reference resolves through oauth_token_issuances in the
    // same SELECT via an inner join.
    let (result, delta, acquires) = measure(
        &counter,
        repository.userinfo_snapshot(
            tenant_id,
            UserinfoSubjectRef::AccessTokenJti(jti.as_str()),
            seed.client.client_id.as_str(),
        ),
    )
    .await;
    let snapshot = result
        .expect("jti snapshot should load")
        .expect("the seeded issuance must produce a snapshot");
    assert_eq!(snapshot.subject.subject.as_uuid(), seed.user_id);
    assert!(snapshot.client.is_some());
    // 1 data statement: SELECT users INNER JOIN oauth_token_issuances (jti
    // + expiry horizon) LEFT JOIN oauth_clients — still one round trip.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// DC-01: replace_registration
// ---------------------------------------------------------------------------

/// DC-01: `replace_registration` is a single `UPDATE .. WHERE
/// registration_access_token_blake3 = expected RETURNING *` with no wrapping
/// transaction — the previous UPDATE + SELECT pair is gone.
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

    let (result, delta, acquires) = measure(
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
    // 1 data statement: UPDATE oauth_clients SET (metadata columns) WHERE
    // id = ? AND registration_access_token_blake3 = ? RETURNING *. The old
    // implementation followed the UPDATE with a second SELECT; the single
    // statement needs no transaction wrapper.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// DF-01: deferred claim ready
// ---------------------------------------------------------------------------

/// DF-01: `claim_ready_deferred` claims a ready transaction with one
/// `UPDATE .. WHERE <claim predicates> RETURNING (deferred, access)` inside a
/// single transaction — the post-update SELECT was removed.
#[tokio::test]
async fn df01_deferred_claim_ready_is_single_update_returning() {
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
        [0x51_u8; 32],
        std::sync::Arc::new(password::BlockingSecretVerifier),
    );

    // Fixture rows go through the production upsert/store on the instrumented
    // pool; the measurement baseline is taken after they complete.
    let access = CredentialAccess {
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

    let (result, delta, acquires) = measure(
        &counter,
        issuer.claim_ready_deferred(&transaction_hash, access.token_id, "claim-1", ready_at),
    )
    .await;

    let claim = result
        .expect("claim should succeed")
        .expect("a ready deferred transaction must be claimable");
    assert_eq!(claim.credential.id, deferred.id);
    assert_eq!(claim.claim_id, "claim-1");
    // 1 data statement: UPDATE openid4vci_deferred_transactions SET claim_id,
    // claim_expires_at FROM openid4vci_access_grants .. WHERE ready/consumable
    // predicates RETURNING the deferred row joined to its access grant. The
    // old code ran UPDATE then SELECT.
    assert_eq!(delta.data_queries, 1);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(acquires, 1);
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
    let (result, delta, acquires) = measure(
        &counter,
        tokens.family_active(tenant_id, family_id, seed.user_id),
    )
    .await;
    assert!(result.expect("family_active succeeds"));
    // 1 data statement: SELECT EXISTS(active member of the family).
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);

    // access_token_revoked — SELECT EXISTS over access_token_revocations.
    let (result, delta, acquires) =
        measure(&counter, tokens.access_token_revoked(tenant_id, &jti)).await;
    assert!(result.expect("access_token_revoked succeeds"));
    // 1 data statement: SELECT EXISTS(revocation row for JTI hash).
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);

    // approved_delivery_matches — request joined to the approved client.
    let (result, delta, acquires) = measure(
        &counter,
        requests.approved_delivery_matches(
            TenantId::new(tenant_id).expect("tenant id"),
            UserId::new(seed.user_id).expect("user id"),
            request_id,
            seed.client.id,
            seed.client.client_id.as_str(),
        ),
    )
    .await;
    assert!(result.expect("approved_delivery_matches succeeds"));
    // 1 data statement: SELECT EXISTS over client_access_requests joined to
    // oauth_clients with the approved-client predicates.
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}

// ---------------------------------------------------------------------------
// UP-06: idempotent access upsert
// ---------------------------------------------------------------------------

/// UP-06: `upsert_access` is one `INSERT .. ON CONFLICT DO UPDATE .. WHERE ..
/// IS DISTINCT FROM` per call; replaying the identical payload stays a single
/// statement and succeeds.
#[tokio::test]
async fn up06_upsert_access_is_one_statement_and_idempotent() {
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
        let (result, delta, acquires) =
            measure(&counter, issuer.upsert_access(&token_hash, &access)).await;
        result.unwrap_or_else(|error| panic!("upsert round {round} must succeed: {error}"));
        // 1 data statement per call: INSERT .. ON CONFLICT (token_hash) DO
        // UPDATE .. WHERE <columns> IS DISTINCT FROM EXCLUDED. On round 2 the
        // IS DISTINCT FROM guard makes the conflict update a no-op — still a
        // single statement, and it must not error.
        assert_eq!(
            delta.data_queries, 1,
            "round {round} upsert is one statement"
        );
        assert_no_transaction(delta);
        assert_eq!(acquires, 1, "round {round} uses one pooled checkout");
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
/// same single conditional upsert.
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
        pool,
        [0x53_u8; 32],
        std::sync::Arc::new(password::BlockingSecretVerifier),
    );

    let access = CredentialAccess {
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
    let (result, delta, acquires) = measure(
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
    assert_eq!(acquires, 0);
    assert_clean(delta);

    // Registered path: 1 data statement — WITH active_client (FOR SHARE) +
    // conditional upsert + outcome probe in a single CTE.
    let (result, delta, acquires) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &format!("qc-access-hash-{}", Uuid::now_v7()),
            &access,
            Some(seed.client.client_id.as_str()),
        ),
    )
    .await;
    result.expect("active-client pre-authorized persist must succeed");
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);

    // Anonymous path: 1 data statement — the plain conditional upsert, no
    // oauth_clients read.
    let (result, delta, acquires) = measure(
        &counter,
        issuer.persist_pre_authorized_access(
            &format!("qc-access-hash-{}", Uuid::now_v7()),
            &CredentialAccess {
                token_id: Uuid::now_v7(),
                ..access.clone()
            },
            None,
        ),
    )
    .await;
    result.expect("anonymous pre-authorized persist must succeed");
    assert_eq!(delta.data_queries, 1);
    assert_no_transaction(delta);
    assert_eq!(acquires, 1);
    assert_clean(delta);

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

    let (result, delta, acquires) = measure(
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
    assert_eq!(acquires, 1);
    assert_clean(delta);
    cleanup_seed(&database_url, tenant, &seed).await;
}
