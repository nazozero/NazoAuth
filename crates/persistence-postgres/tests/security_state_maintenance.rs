//! Bounded security-state maintenance coverage.
//!
//! One `cleanup_batch` performs at most 256 row modifications per category.
//! Refresh reclaim works on `(tenant_id, token_family_id)` authorities under
//! the shared family advisory key: expired spent proofs delete on their own
//! `expires_at`, a fully expired family row deletes under a try-lock (a writer
//! holding the lock skips it for the batch), and orphan contracts leave after
//! a grace period once the last family reference is gone — never touching a
//! family that still has an unexpired current member or a same-named family
//! in another tenant. OpenID4VP reads are pure selects; the global
//! presentation sweep belongs exclusively to this worker.

use chrono::{DateTime, Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{self, BigInt, Text, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::RefreshTokenAuthenticationContext;
use nazo_digital_credentials::{CredentialFormat, CredentialQuery, DcqlQuery};
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationCreateIdempotency, PresentationCreateOutcome,
    PresentationStorePort, PresentationTransaction, RequestMethod, ResponseMode,
};
use nazo_persistence::SecurityStateMaintenancePort;
use nazo_postgres::{
    Openid4vpRepository, SecurityStateMaintenanceRepository, create_pool, get_conn,
};
use uuid::Uuid;

const SYSTEM_TENANT: Uuid = Uuid::from_u128(1);

/// `cleanup_batch` sweeps expired security state globally. Sibling tests each
/// seed their own fixtures but share that single sweep, so their batches must
/// not interleave with one another's.
static CLEANUP_BATCH_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI security-state tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn family_lock_key(family_id: Uuid) -> i64 {
    let bytes = family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    high ^ low
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct FlagRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    flag: bool,
}

#[derive(QueryableByName)]
struct DeploymentRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    deployment: Option<String>,
}

#[derive(QueryableByName)]
struct FixtureIds {
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct TenantFixtureRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
}

async fn fixture(database_url: &str) -> (FixtureIds, AsyncPgConnection) {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let suffix = Uuid::now_v7().simple().to_string();
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    let security_policy = r#"{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}"#;
    let row = sql_query(format!(
        r#"
        WITH inserted_user AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('maint-{suffix}', 'maint-{suffix}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method, security_policy
            ) VALUES (
                'maint-{suffix}', 'Maintenance Test', 'confidential',
                '["https://client.example/callback"]'::jsonb,
                '["openid", "offline_access"]'::jsonb,
                '["authorization_code", "refresh_token"]'::jsonb,
                'client_secret_basic',
                '{security_policy}'::jsonb
            ) RETURNING id, client_id
        )
        SELECT inserted_user.id AS user_id, inserted_client.id AS client_id,
               inserted_client.client_id AS client_public_id
        FROM inserted_user CROSS JOIN inserted_client
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("maintenance fixture should insert");
    (row, connection)
}

async fn insert_refresh_leaf(
    connection: &mut AsyncPgConnection,
    fixture: &FixtureIds,
    family_id: Uuid,
    rotated_from_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
) -> Uuid {
    insert_refresh_leaf_in_tenant(
        connection,
        fixture,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        family_id,
        rotated_from_id,
        expires_at,
    )
    .await
}

/// Inserts one refresh generation in the minimal three-table model. A
/// `rotated_from_id` successor first moves the family's current member into a
/// spent proof (carrying that member's own `expires_at`), then the new member
/// becomes the family's current state.
#[allow(clippy::too_many_arguments)]
async fn insert_refresh_leaf_in_tenant(
    connection: &mut AsyncPgConnection,
    fixture: &FixtureIds,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    rotated_from_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    let issued_at = (expires_at - Duration::hours(1)).min(Utc::now());
    let context = RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: fixture.client_public_id.clone(),
        auth_time: issued_at.timestamp() - 1,
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        id_token_sid: None,
        acr: None,
        nonce: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
    };
    let contract = nazo_auth::RefreshContract {
        subject: fixture.user_id.to_string(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: serde_json::json!([]),
        authentication_context: context,
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
                   LEAST(CURRENT_TIMESTAMP,
                         f.current_expires_at - INTERVAL '1 microsecond'),
                   f.current_expires_at
            FROM oauth_refresh_families AS f
            WHERE $6 IS NOT NULL
              AND f.tenant_id = $2 AND f.token_family_id = $5
              AND f.current_member_id = $6
        )
        INSERT INTO oauth_refresh_families (
            tenant_id, token_family_id, client_id, user_id, contract_blake3,
            current_member_id, current_token_blake3, current_audience,
            current_issued_at, current_expires_at, created_at
        )
        SELECT
            $2, $5, $7, $8, r.contract_blake3,
            $1, $9, '["resource://default"]'::jsonb, $10, $11, $10
        FROM resolved AS r
        ON CONFLICT (tenant_id, token_family_id) DO UPDATE SET
            current_member_id = EXCLUDED.current_member_id,
            current_token_blake3 = EXCLUDED.current_token_blake3,
            current_audience = EXCLUDED.current_audience,
            current_issued_at = EXCLUDED.current_issued_at,
            current_expires_at = EXCLUDED.current_expires_at
        "#,
    )
    .bind::<SqlUuid, _>(id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<sql_types::Binary, _>(contract_blake3)
    .bind::<sql_types::Jsonb, _>(contract_json)
    .bind::<SqlUuid, _>(family_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(rotated_from_id)
    .bind::<SqlUuid, _>(client_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(Some(user_id))
    .bind::<sql_types::Binary, _>(blake3::hash(Uuid::now_v7().as_bytes()).as_bytes().to_vec())
    .bind::<Timestamptz, _>(issued_at)
    .bind::<Timestamptz, _>(expires_at)
    .execute(connection)
    .await
    .expect("refresh leaf fixture should insert");
    id
}

/// Clears expired refresh state the same way the production sweeps do: spent
/// proofs at their own expiry, expired families (proofs cascade), then orphan
/// contracts.
async fn clear_expired_tokens(connection: &mut AsyncPgConnection) {
    sql_query("DELETE FROM oauth_refresh_spent_tokens WHERE expires_at <= CURRENT_TIMESTAMP")
        .execute(connection)
        .await
        .expect("expired spent proofs should clear");
    sql_query("DELETE FROM oauth_refresh_families WHERE current_expires_at <= CURRENT_TIMESTAMP")
        .execute(connection)
        .await
        .expect("expired families should clear");
    sql_query(
        "DELETE FROM oauth_refresh_contracts AS c WHERE NOT EXISTS (\
             SELECT 1 FROM oauth_refresh_families AS f \
             WHERE f.tenant_id = c.tenant_id AND f.contract_blake3 = c.contract_blake3)",
    )
    .execute(connection)
    .await
    .expect("orphan contracts should clear");
}

/// Family extent = its family row plus surviving spent proofs.
async fn family_row_count(connection: &mut AsyncPgConnection, family_id: Uuid) -> i64 {
    sql_query(
        "SELECT \
             (SELECT COUNT(*) FROM oauth_refresh_families WHERE token_family_id = $1) \
             + (SELECT COUNT(*) FROM oauth_refresh_spent_tokens WHERE token_family_id = $1) \
             AS count",
    )
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("family row count should query")
    .count
}

async fn tagged_issuance_count(connection: &mut AsyncPgConnection, tag: &str) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances \
         WHERE tenant_id = $1 AND access_token_jti LIKE 'maint-' || $2 || '-%'",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(tag.to_owned())
    .get_result::<CountRow>(connection)
    .await
    .expect("tagged issuance count should query")
    .count
}

async fn expired_presentation_count(
    connection: &mut AsyncPgConnection,
    create_request_jti: &str,
) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vp_transactions \
         WHERE tenant_id = $1 AND create_request_jti = $2 \
           AND expires_at <= CURRENT_TIMESTAMP",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(create_request_jti.to_owned())
    .get_result::<CountRow>(connection)
    .await
    .expect("expired presentation count should query")
    .count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_issuances_are_reclaimed_in_bounded_batches() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let tag = Uuid::now_v7().simple().to_string();
    // The shared test database accumulates expired issuances from other
    // suites; clear the queue so the bounded rounds below measure only this
    // fixture's rows.
    sql_query("DELETE FROM oauth_token_issuances WHERE retain_until <= clock_timestamp()")
        .execute(&mut connection)
        .await
        .expect("stale expired issuances should clear");
    // 700 expired rows plus one row whose retention has not elapsed.
    sql_query(
        "INSERT INTO oauth_token_issuances (\
             issuance_id, tenant_id, client_id, user_id, access_token_jti, \
             access_token_expires_at, retain_until) \
         SELECT gen_random_uuid(), $1, $2, NULL, \
                'maint-' || $3 || '-' || g, \
                CURRENT_TIMESTAMP - INTERVAL '2 hours', \
                CURRENT_TIMESTAMP - INTERVAL '1 hour' \
         FROM generate_series(1, 700) AS g",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<Text, _>(tag.clone())
    .execute(&mut connection)
    .await
    .expect("expired issuance fixture should insert");
    sql_query(
        "INSERT INTO oauth_token_issuances (\
             issuance_id, tenant_id, client_id, user_id, access_token_jti, \
             access_token_expires_at, retain_until) \
         VALUES (gen_random_uuid(), $1, $2, NULL, 'maint-' || $3 || '-future', \
                 CURRENT_TIMESTAMP + INTERVAL '1 hour', \
                 CURRENT_TIMESTAMP + INTERVAL '2 hours')",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<Text, _>(tag.clone())
    .execute(&mut connection)
    .await
    .expect("retained issuance fixture should insert");

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    for round in 0..8 {
        let result = maintenance
            .cleanup_batch()
            .await
            .expect("cleanup batch should succeed");
        assert!(
            result.issuances <= 256,
            "one batch must never exceed the per-category bound"
        );
        if tagged_issuance_count(&mut connection, &tag).await == 1 {
            break;
        }
        assert_ne!(round, 7, "700 rows must drain within the bounded rounds");
    }
    assert_eq!(
        tagged_issuance_count(&mut connection, &tag).await,
        1,
        "only the not-yet-retained issuance may remain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn natural_expiry_refresh_leaf_reclaimed_without_revocation() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let family_id = Uuid::now_v7();
    // Naturally expired, never marked revoked: revoked_at stays NULL.
    insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        None,
        Utc::now() - Duration::hours(2),
    )
    .await;
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert_eq!(
        family_row_count(&mut connection, family_id).await,
        0,
        "a fully expired family must reclaim its leaf without a revocation mark"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_successor_blocks_ancestor_reclaim() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let family_id = Uuid::now_v7();
    let parent = insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        None,
        Utc::now() - Duration::hours(2),
    )
    .await;
    // The successor is still valid, so the family is not fully expired; the
    // predecessor's already-expired spent proof is reclaimed independently.
    insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        Some(parent),
        Utc::now() + Duration::hours(1),
    )
    .await;
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert_eq!(
        family_row_count(&mut connection, family_id).await,
        1,
        "the live family row survives; the expired spent proof is deleted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_generation_family_reclaims_whole_chain_in_one_batch() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    // Clear expired token rows left by other suites so this family's batch
    // placement is deterministic.
    clear_expired_tokens(&mut connection).await;
    let family_id = Uuid::now_v7();
    let expired = Utc::now() - Duration::hours(2);
    let grandparent =
        insert_refresh_leaf(&mut connection, &fixture, family_id, None, expired).await;
    let parent = insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        Some(grandparent),
        expired,
    )
    .await;
    insert_refresh_leaf(&mut connection, &fixture, family_id, Some(parent), expired).await;

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let result = maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert!(
        result.refresh_tokens >= 1,
        "the expired family row must be reclaimed in one batch, got {}",
        result.refresh_tokens
    );
    assert_eq!(
        family_row_count(&mut connection, family_id).await,
        0,
        "deleting the family cascades its spent proofs — the whole chain \
         leaves in one batch"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_family_drains_across_bounded_batches_and_reports_saturation() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    clear_expired_tokens(&mut connection).await;
    let family_id = Uuid::now_v7();
    let expired = Utc::now() - Duration::hours(2);
    // 300 expired generations under a still-live head: the spent sweep must
    // drain the proofs across bounded batches while the family row stays.
    let mut previous = None;
    for _ in 0..300 {
        previous = Some(
            insert_refresh_leaf(&mut connection, &fixture, family_id, previous, expired).await,
        );
    }
    insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        previous,
        Utc::now() + Duration::hours(1),
    )
    .await;

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let first = maintenance
        .cleanup_batch()
        .await
        .expect("first cleanup batch should succeed");
    assert!(
        first.saturated,
        "hitting the 256-row budget must mark the batch saturated"
    );
    assert!(
        first.spent_refresh_proofs <= 256,
        "one batch may delete at most 256 spent proofs"
    );
    let remaining = family_row_count(&mut connection, family_id).await;
    assert_eq!(
        remaining,
        300 - first.spent_refresh_proofs as i64 + 1,
        "the live family row plus the undrained spent proofs remain"
    );
    let second = maintenance
        .cleanup_batch()
        .await
        .expect("second cleanup batch should succeed");
    assert_eq!(
        family_row_count(&mut connection, family_id).await,
        1,
        "the follow-up batch finishes the proofs; the live family stays"
    );
    assert_eq!(
        second.spent_refresh_proofs,
        300 - first.spent_refresh_proofs
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_family_lock_skips_locked_family_and_recheck_blocks_late_successor() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let locked_family = Uuid::now_v7();
    let free_family = Uuid::now_v7();
    let expired = Utc::now() - Duration::hours(2);
    let locked_leaf =
        insert_refresh_leaf(&mut connection, &fixture, locked_family, None, expired).await;
    insert_refresh_leaf(&mut connection, &fixture, free_family, None, expired).await;

    // A concurrent rotation transaction holds the writer advisory key.
    let mut writer = AsyncPgConnection::establish(&database_url)
        .await
        .expect("writer connection should connect");
    writer
        .batch_execute("BEGIN")
        .await
        .expect("writer transaction should open");
    sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(family_lock_key(locked_family))
        .execute(&mut writer)
        .await
        .expect("writer family lock should be acquired");

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed without waiting on the family lock");
    assert_eq!(
        family_row_count(&mut connection, locked_family).await,
        1,
        "a family whose advisory key is held must be skipped, not blocked on"
    );
    assert_eq!(
        family_row_count(&mut connection, free_family).await,
        0,
        "unlocked families in the same batch must still be reclaimed"
    );

    // The writer commits a fresh successor before releasing the key. The
    // maintenance recheck under the acquired advisory lock must see the
    // family is no longer expired even though the earlier scan listed it;
    // the predecessor's expired spent proof is reclaimed on its own.
    insert_refresh_leaf(
        &mut writer,
        &fixture,
        locked_family,
        Some(locked_leaf),
        Utc::now() + Duration::hours(1),
    )
    .await;
    writer
        .batch_execute("COMMIT")
        .await
        .expect("writer transaction should commit");
    maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert_eq!(
        family_row_count(&mut connection, locked_family).await,
        1,
        "a family that gained an unexpired generation after the candidate \
         scan must survive the post-lock recheck; only the spent proof goes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_reclaim_batches_locks_without_waiting_or_exceeding_the_candidate_budget() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let (fixture, mut connection) = fixture(&database_url).await;
    clear_expired_tokens(&mut connection).await;
    let locked_family = Uuid::now_v7();
    insert_refresh_leaf(
        &mut connection,
        &fixture,
        locked_family,
        None,
        Utc::now() - Duration::days(730),
    )
    .await;
    // Put the held key first in a 300-family backlog. The candidate budget
    // counts attempted families, including the one whose try-lock fails.
    sql_query(
        "INSERT INTO oauth_refresh_families \
         (tenant_id,token_family_id,client_id,user_id,contract_blake3, \
          current_member_id,current_token_blake3,current_audience, \
          current_issued_at,current_expires_at,created_at) \
         SELECT tenant_id,gen_random_uuid(),client_id,user_id,contract_blake3, \
                gen_random_uuid(),decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text),'hex'),current_audience, \
                current_issued_at,current_expires_at + interval '1 second',created_at \
         FROM oauth_refresh_families CROSS JOIN generate_series(1,299) \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(locked_family)
    .execute(&mut connection)
    .await
    .unwrap();
    connection.batch_execute("BEGIN").await.unwrap();
    sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(family_lock_key(locked_family))
        .execute(&mut connection)
        .await
        .unwrap();
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let first = maintenance.cleanup_batch().await.unwrap();
        let second = maintenance.cleanup_batch().await.unwrap();
        (first, second)
    })
    .await
    .expect("a held family advisory key must not stall either batch");
    assert_eq!(first.refresh_tokens, 255);
    assert!(first.saturated);
    assert_eq!(second.refresh_tokens, 44);
    assert_eq!(family_row_count(&mut connection, locked_family).await, 1);
    connection.batch_execute("COMMIT").await.unwrap();
    let final_batch = maintenance.cleanup_batch().await.unwrap();
    assert_eq!(final_batch.refresh_tokens, 1);
    assert_eq!(family_row_count(&mut connection, locked_family).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_batches_do_not_deadlock_or_double_count() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let expired = Utc::now() - Duration::hours(2);
    let mut families = Vec::new();
    for _ in 0..6 {
        let family_id = Uuid::now_v7();
        insert_refresh_leaf(&mut connection, &fixture, family_id, None, expired).await;
        families.push(family_id);
    }
    let first = SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let second = SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let (a, b) = tokio::join!(first.cleanup_batch(), second.cleanup_batch());
    a.expect("first maintenance batch should succeed");
    b.expect("second maintenance batch should succeed");
    for family_id in families {
        assert_eq!(
            family_row_count(&mut connection, family_id).await,
            0,
            "every eligible family must be reclaimed exactly once across instances"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_batch_leaves_no_open_transaction_on_pooled_connection() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    let expired = Utc::now() - Duration::hours(2);
    let gated_family = Uuid::now_v7();
    insert_refresh_leaf(&mut connection, &fixture, gated_family, None, expired).await;

    // Gate the leaf DELETE inside the maintenance transaction on a session
    // advisory lock held by a second connection.
    let suffix = Uuid::now_v7().simple().to_string();
    let gate_key = i64::from_be_bytes(Uuid::now_v7().as_bytes()[..8].try_into().unwrap());
    let function = format!("test_maintenance_gate_{suffix}");
    let trigger = format!("test_maintenance_gate_trigger_{suffix}");
    sql_query(format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
             IF OLD.token_family_id = '{gated_family}'::uuid THEN \
                 PERFORM pg_advisory_xact_lock({gate_key}); \
             END IF; \
             RETURN OLD; \
         END $$"
    ))
    .execute(&mut connection)
    .await
    .expect("gate function should install");
    sql_query(format!(
        "CREATE TRIGGER {trigger} BEFORE DELETE ON oauth_refresh_families \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&mut connection)
    .await
    .expect("gate trigger should install");

    let mut locker = AsyncPgConnection::establish(&database_url)
        .await
        .expect("locker connection should connect");
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut locker)
        .await
        .expect("session gate lock should be held");

    let tagged_url = format!(
        "{database_url}{}application_name=maint-cancel-{suffix}",
        if database_url.contains('?') { '&' } else { '?' }
    );
    let maintenance = SecurityStateMaintenanceRepository::new(create_pool(&tagged_url, 2).unwrap());
    let task = tokio::spawn(async move { maintenance.cleanup_batch().await });

    // Wait until the maintenance transaction is blocked on the gate.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let blocked = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity \
             WHERE application_name = $1 AND wait_event_type = 'Lock'",
        )
        .bind::<Text, _>(format!("maint-cancel-{suffix}"))
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("lock wait observation should query");
        if blocked.count > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "maintenance batch should reach the gated row lock"
        );
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;

    let unlocked = sql_query("SELECT pg_advisory_unlock($1) AS flag")
        .bind::<BigInt, _>(gate_key)
        .get_result::<FlagRow>(&mut locker)
        .await
        .expect("session gate lock should release");
    assert!(unlocked.flag, "the gate advisory lock must still be held");
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_refresh_families"))
        .execute(&mut connection)
        .await
        .expect("gate trigger should drop");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut connection)
        .await
        .expect("gate function should drop");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let lingering = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity \
             WHERE application_name = $1 AND state = 'idle in transaction'",
        )
        .bind::<Text, _>(format!("maint-cancel-{suffix}"))
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("lingering transaction observation should query");
        if lingering.count == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a cancelled batch must discard its connection instead of \
             returning an open transaction to the pool"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vp_find_never_deletes_and_create_only_clears_the_same_key() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let pool = create_pool(&database_url, 4).unwrap();
    let verifier = Openid4vpRepository::new(pool.clone(), SYSTEM_TENANT, [0x77; 32]);
    let now = Utc::now();

    let base_transaction = |id: Uuid, expires_at: DateTime<Utc>| PresentationTransaction {
        id,
        client_id_prefix: ClientIdPrefix::RedirectUri,
        request_method: RequestMethod::UrlQuery,
        response_mode: ResponseMode::DirectPost,
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request: AuthorizationRequest {
            client_id: "redirect_uri:https://verifier.example/response".to_owned(),
            response_type: "vp_token".to_owned(),
            response_mode: "direct_post".to_owned(),
            response_uri: "https://verifier.example/response".to_owned(),
            nonce: "nonce".to_owned(),
            state: format!("state-{id}"),
            dcql_query: DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".to_owned(),
                    format: CredentialFormat::SdJwtVc,
                    multiple: false,
                    meta: None,
                    claims: None,
                    claim_sets: None,
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                }],
                credential_sets: None,
            },
            client_metadata: None,
            verifier_info: None,
            transaction_data: None,
            wallet_nonce: None,
        },
        request_object: None,
        request_uri: None,
        openid4vc_trust_policy_binding_id: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
        response_encryption_private_key: Some(vec![7_u8; 32]),
        created_at: now - Duration::hours(2),
        expires_at,
    };

    let normalized = nazo_operator_protocol::Openid4vpNormalizedCreateRequest {
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        dcql_query: serde_json::json!({
            "credentials": [{
                "id": "pid",
                "format": "sd_jwt_vc",
                "require_cryptographic_holder_binding": true
            }]
        }),
        haip: false,
        client_id_prefix: "redirect_uri".to_owned(),
        request_method: "url_query".to_owned(),
        response_mode: "direct_post".to_owned(),
        transaction_data: None,
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
    };
    let (canonical, sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
            .expect("normalized create request should canonicalize");

    // Clear expired transactions left by other suites so the single bounded
    // batch below provably reclaims this fixture's row.
    {
        let mut connection = get_conn(&pool).await.unwrap();
        sql_query("DELETE FROM openid4vp_transactions WHERE expires_at <= clock_timestamp()")
            .execute(&mut connection)
            .await
            .expect("stale expired transactions should clear");
    }

    let expired_first = base_transaction(Uuid::now_v7(), now - Duration::hours(1));
    let expired_other = base_transaction(Uuid::now_v7(), now - Duration::hours(1));
    let jti_first = Uuid::now_v7().to_string();
    let jti_other = Uuid::now_v7().to_string();
    for (transaction, jti) in [(&expired_first, &jti_first), (&expired_other, &jti_other)] {
        assert_eq!(
            verifier
                .create(
                    transaction,
                    PresentationCreateIdempotency {
                        request_jti: jti,
                        request_sha256: &sha256,
                        canonical_request: &canonical,
                    },
                )
                .await
                .expect("expired presentation fixture should insert"),
            PresentationCreateOutcome::Created
        );
    }

    // find performs a pure select: the expired row is filtered out but must
    // not be deleted.
    assert!(
        verifier
            .find_by_create_request(PresentationCreateIdempotency {
                request_jti: &jti_first,
                request_sha256: &sha256,
                canonical_request: &canonical,
            })
            .await
            .expect("find on an expired key should succeed")
            .is_none(),
        "an expired presentation must not be returned"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    assert_eq!(
        expired_presentation_count(&mut connection, &jti_first).await,
        1,
        "find must not delete the expired row"
    );

    // create may clear only the conflicting same-key expired row.
    let fresh = base_transaction(Uuid::now_v7(), now + Duration::minutes(5));
    assert_eq!(
        verifier
            .create(
                &fresh,
                PresentationCreateIdempotency {
                    request_jti: &jti_first,
                    request_sha256: &sha256,
                    canonical_request: &canonical,
                },
            )
            .await
            .expect("same-key create after expiry should succeed"),
        PresentationCreateOutcome::Created
    );
    assert_eq!(
        expired_presentation_count(&mut connection, &jti_other).await,
        1,
        "create must not run the global cleanup for unrelated expired rows"
    );

    // The global sweep belongs to the maintenance worker alone.
    let maintenance = SecurityStateMaintenanceRepository::new(pool.clone());
    let result = maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert!(result.presentations >= 1);
    assert_eq!(
        expired_presentation_count(&mut connection, &jti_other).await,
        0,
        "the maintenance worker owns expired presentation reclamation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocations_and_scim_and_logout_categories_keep_their_retention() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    // Clear expired rows left by other suites so the single bounded batch
    // below provably reaches this fixture's rows.
    for statement in [
        "DELETE FROM access_token_revocations WHERE expires_at <= clock_timestamp()",
        "DELETE FROM scim_security_events WHERE expires_at <= clock_timestamp()",
        "DELETE FROM backchannel_logout_deliveries WHERE expires_at <= clock_timestamp()",
        "DELETE FROM scim_audit_events          WHERE created_at < clock_timestamp() - INTERVAL '180 days'",
    ] {
        sql_query(statement)
            .execute(&mut connection)
            .await
            .expect("stale expired rows should clear");
    }
    let past = Utc::now() - Duration::hours(1);
    let older = Utc::now() - Duration::hours(2);
    let future = Utc::now() + Duration::hours(1);
    let old = Utc::now() - Duration::days(181);

    // One expired and one retained row per maintained category; every row is
    // tracked by its primary key so assertions never depend on a shared
    // database being empty.
    let expired_revocation = Uuid::now_v7();
    let kept_revocation = Uuid::now_v7();
    sql_query(
        "INSERT INTO access_token_revocations \
             (id, access_token_jti_blake3, client_id, tenant_id, revoked_at, expires_at) \
         VALUES ($1, $4, $2, $3, $5, $6), ($7, $4 || '-keep', $2, $3, $5, $8)",
    )
    .bind::<SqlUuid, _>(expired_revocation)
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(format!("jti-blake3-{}", Uuid::now_v7().simple()))
    .bind::<Timestamptz, _>(past)
    .bind::<Timestamptz, _>(past)
    .bind::<SqlUuid, _>(kept_revocation)
    .bind::<Timestamptz, _>(future)
    .execute(&mut connection)
    .await
    .expect("revocation fixture should insert");

    let expired_security_event = Uuid::now_v7();
    let kept_security_event = Uuid::now_v7();
    sql_query(
        "INSERT INTO scim_security_events \
             (id, tenant_id, transaction_id, subject_uri, events, occurred_at, expires_at) \
         VALUES ($1, $2, gen_random_uuid(), $3, $4, $5, $6), \
                ($7, $2, gen_random_uuid(), $8, $4, $5, $9)",
    )
    .bind::<SqlUuid, _>(expired_security_event)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(format!("/Users/{}", Uuid::now_v7()))
    .bind::<sql_types::Jsonb, _>(serde_json::json!({"test": true}))
    .bind::<Timestamptz, _>(older)
    .bind::<Timestamptz, _>(past)
    .bind::<SqlUuid, _>(kept_security_event)
    .bind::<Text, _>(format!("/Users/{}", Uuid::now_v7()))
    .bind::<Timestamptz, _>(future)
    .execute(&mut connection)
    .await
    .expect("scim security-event fixture should insert");

    let expired_delivery = Uuid::now_v7();
    let kept_delivery = Uuid::now_v7();
    sql_query(
        "INSERT INTO backchannel_logout_deliveries \
             (id, tenant_id, client_id, client_public_id, logout_uri, logout_token, \
              attempts, next_attempt_at, expires_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'https://client.example/logout', 'logout-token', \
                 0, $5, $6, $5, $5), \
                ($7, $2, $3, $4, 'https://client.example/logout', 'logout-token', \
                 0, $5, $8, $5, $5)",
    )
    .bind::<SqlUuid, _>(expired_delivery)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<Text, _>(fixture.client_public_id.clone())
    .bind::<Timestamptz, _>(past)
    .bind::<Timestamptz, _>(past)
    .bind::<SqlUuid, _>(kept_delivery)
    .bind::<Timestamptz, _>(future)
    .execute(&mut connection)
    .await
    .expect("logout-delivery fixture should insert");

    let expired_audit = Uuid::now_v7();
    let kept_audit = Uuid::now_v7();
    sql_query(
        "INSERT INTO scim_audit_events \
             (id, tenant_id, scim_token_id, event_type, scopes, created_at) \
         VALUES ($1, $2, NULL, 'scim_token_used', '[]'::jsonb, $3), \
                ($4, $2, NULL, 'scim_token_used', '[]'::jsonb, CURRENT_TIMESTAMP)",
    )
    .bind::<SqlUuid, _>(expired_audit)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Timestamptz, _>(old)
    .bind::<SqlUuid, _>(kept_audit)
    .execute(&mut connection)
    .await
    .expect("scim audit-event fixture should insert");

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let result = maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert!(
        result.revocations >= 1,
        "expired revocations must be reclaimed"
    );
    assert!(result.scim_security_events >= 1);
    assert!(result.logout_deliveries >= 1);
    assert!(result.scim_audit_events >= 1);

    for (table, kept_id) in [
        ("access_token_revocations", kept_revocation),
        ("scim_security_events", kept_security_event),
        ("backchannel_logout_deliveries", kept_delivery),
        ("scim_audit_events", kept_audit),
    ] {
        let kept = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(kept_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("retained row count should query");
        assert_eq!(
            kept.count, 1,
            "rows inside their retention window must survive ({table})"
        );
    }
    for (table, expired_id) in [
        ("access_token_revocations", expired_revocation),
        ("scim_security_events", expired_security_event),
        ("backchannel_logout_deliveries", expired_delivery),
        ("scim_audit_events", expired_audit),
    ] {
        let gone = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE id = $1"
        ))
        .bind::<SqlUuid, _>(expired_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("expired row count should query");
        assert_eq!(gone.count, 0, "expired rows must be reclaimed ({table})");
    }
}

async fn insert_audit_event(connection: &mut AsyncPgConnection, event_id: Uuid) {
    sql_query(
        "SELECT public.nazo_persist_security_audit_event(\
             $1, 'test_event', 'test', '{}'::jsonb, clock_timestamp())",
    )
    .bind::<SqlUuid, _>(event_id)
    .execute(connection)
    .await
    .expect("audit event fixture should insert");
}

/// Acknowledge the whole committed batch through the real exporter path.
async fn ack_batch(
    repository: &nazo_postgres::AuditLedgerRepository,
    batch: &nazo_persistence::SecurityAuditBatch,
    generation: i64,
    deployment_id: &str,
) -> Result<(), nazo_identity::ports::RepositoryError> {
    repository
        .ack_batch(nazo_persistence::SecurityAuditBatchAck {
            generation,
            deployment_id: deployment_id.to_owned(),
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            event_count: batch.event_count(),
            last_hash: batch.last_hash.clone(),
            batch_digest: batch.digest.clone(),
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_ack_deletes_delivery_rows_atomically() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (_fixture, mut connection) = fixture(&database_url).await;
    let repository =
        nazo_postgres::AuditLedgerRepository::new(create_pool(&database_url, 2).unwrap());
    let deployment_id: String = sql_query(
        "SELECT anchor_deployment_id::text AS deployment \
         FROM security_audit_chain_state WHERE singleton",
    )
    .get_result::<DeploymentRow>(&mut connection)
    .await
    .expect("anchor deployment should read")
    .deployment
    .unwrap_or_else(|| "maint-dep".to_owned());

    // Drain any residual pending rows left by sibling tests so the fixture
    // owns the whole committed prefix.
    loop {
        match repository
            .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
            .await
            .expect("residual batches should be claimable")
        {
            nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) => {
                ack_batch(&repository, &batch, batch.generation, &deployment_id)
                    .await
                    .expect("residual batch should be acknowledged");
            }
            nazo_persistence::SecurityAuditBatchClaim::Busy => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            nazo_persistence::SecurityAuditBatchClaim::Blocked { reason } => {
                panic!("residual blocked batch: {reason}");
            }
            nazo_persistence::SecurityAuditBatchClaim::Empty => break,
        }
    }

    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    for event_id in [first, second] {
        insert_audit_event(&mut connection, event_id).await;
        assert_eq!(event_row_count(&mut connection, event_id).await, 1);
    }

    let batch = match repository
        .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
        .await
        .expect("the pending events should form a claimable batch")
    {
        nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    assert_eq!(
        batch
            .deliveries
            .iter()
            .map(|delivery| delivery.event_id)
            .collect::<Vec<_>>(),
        vec![first, second]
    );

    // A stale generation ack deletes nothing and fails closed.
    assert!(matches!(
        ack_batch(&repository, &batch, batch.generation + 1, &deployment_id).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));
    assert_eq!(event_row_count(&mut connection, first).await, 1);
    assert_eq!(event_row_count(&mut connection, second).await, 1);

    // The live generation ack deletes every member row and advances the
    // anchor in the same transaction.
    ack_batch(&repository, &batch, batch.generation, &deployment_id)
        .await
        .expect("the committed batch should acknowledge");
    assert_eq!(event_row_count(&mut connection, first).await, 0);
    assert_eq!(event_row_count(&mut connection, second).await, 0);
    assert!(matches!(
        repository
            .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
            .await
            .expect("an empty pending set should report Empty"),
        nazo_persistence::SecurityAuditBatchClaim::Empty
    ));
    // Repeating the settled acknowledgement is a stale claim, not a duplicate.
    assert!(matches!(
        ack_batch(&repository, &batch, batch.generation, &deployment_id).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));

    // The acknowledgement already reclaimed every delivered copy: the
    // receiver is the durable audit store, so the OLTP event and chain-entry
    // rows for this batch are gone.
    for event_id in [first, second] {
        let row = sql_query(
            "SELECT COUNT(*)::bigint AS count \
             FROM security_audit_events WHERE event_id = $1",
        )
        .bind::<SqlUuid, _>(event_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("event count should query");
        assert_eq!(row.count, 0, "delivered events are reclaimed at ack");
        let chain = sql_query(
            "SELECT COUNT(*)::bigint AS count \
             FROM security_audit_chain_entries WHERE event_id = $1",
        )
        .bind::<SqlUuid, _>(event_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("chain count should query");
        assert_eq!(
            chain.count, 0,
            "delivered chain entries are reclaimed at ack"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reclaim_scopes_family_authority_to_tenant() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    clear_expired_tokens(&mut connection).await;
    let family_id = Uuid::now_v7();
    let past = Utc::now() - Duration::hours(1);
    let future = Utc::now() + Duration::hours(1);

    // Tenant B gets a real tenant/user/client triple: tenant_id on the
    // refresh tables is a hard foreign key, not a label.
    let suffix = Uuid::now_v7().simple().to_string();
    let tenant_b = sql_query(format!(
        "WITH t AS ( \
             INSERT INTO tenants (slug, display_name) \
             VALUES ('tenant-b-{suffix}', 'Tenant B') RETURNING id \
         ), r AS ( \
             INSERT INTO realms (tenant_id, slug, display_name) \
             SELECT id, 'realm-b-{suffix}', 'Realm B' FROM t RETURNING id \
         ), o AS ( \
             INSERT INTO organizations (tenant_id, slug, display_name) \
             SELECT id, 'org-b-{suffix}', 'Org B' FROM t RETURNING id \
         ), u AS ( \
             INSERT INTO users (tenant_id, realm_id, organization_id, username, email, password_hash) \
             SELECT t.id, r.id, o.id, 'tb-{suffix}', 'tb-{suffix}@example.test', 'test-only-hash' \
             FROM t, r, o RETURNING id, tenant_id \
         ), c AS ( \
             INSERT INTO oauth_clients ( \
                 tenant_id, realm_id, organization_id, client_id, client_name, client_type, redirect_uris, \
                 scopes, grant_types, token_endpoint_auth_method, security_policy) \
             SELECT t.id, r.id, o.id, 'tbc-{suffix}', 'Tenant B Client', 'confidential', \
                 '[\"https://client.example/callback\"]'::jsonb, \
                 '[\"openid\", \"offline_access\"]'::jsonb, \
                 '[\"authorization_code\", \"refresh_token\"]'::jsonb, \
                 'client_secret_basic', \
                 '{{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,\"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,\"session_management\":false,\"allow_cross_device_flows\":false,\"allow_confidential_oidc_without_pkce\":false}}'::jsonb \
             FROM t, r, o RETURNING id, tenant_id \
         ) \
         SELECT t.id AS tenant_id, u.id AS user_id, c.id AS client_id FROM t, u, c"
    ))
    .get_result::<TenantFixtureRow>(&mut connection)
    .await
    .expect("tenant-B fixture should insert");

    // Tenant A: two expired members of family X (a chain).
    let a_parent = insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        family_id,
        None,
        past,
    )
    .await;
    insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        family_id,
        Some(a_parent),
        past,
    )
    .await;
    // Tenant B: the same family id, one expired member linked to an active
    // successor — the family stays live and must never be touched.
    let b_parent = insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        tenant_b.tenant_id,
        tenant_b.client_id,
        tenant_b.user_id,
        family_id,
        None,
        past,
    )
    .await;
    let b_active = insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        tenant_b.tenant_id,
        tenant_b.client_id,
        tenant_b.user_id,
        family_id,
        Some(b_parent),
        future,
    )
    .await;

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    maintenance
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");

    let a_left = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant-A count should query")
    .count;
    assert_eq!(a_left, 0, "tenant-A expired family must be reclaimed");

    // Tenant B's live family row survives; its already-expired spent proof is
    // reclaimed on its own schedule, not by the family sweep.
    let b_rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_b.tenant_id)
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant-B count should query")
    .count;
    assert_eq!(b_rows, 1, "tenant-B family must be untouched");

    let b_current = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 AND current_member_id = $3 \
           AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(tenant_b.tenant_id)
    .bind::<SqlUuid, _>(family_id)
    .bind::<SqlUuid, _>(b_active)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant-B current member should query")
    .count;
    assert_eq!(
        b_current, 1,
        "tenant-B's live current member must not be displaced"
    );
}

/// The spent-proof sweep is bounded at 256 rows per batch; an expired family
/// takes its remaining proofs down by cascade in the same batch. Both sweeps
/// must converge without stalling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_family_reclaim_stays_bounded_per_batch() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
    clear_expired_tokens(&mut connection).await;
    let live_family = Uuid::now_v7();
    let dead_family = Uuid::now_v7();
    let past = Utc::now() - Duration::hours(2);

    // A live family with 10,000 expired spent proofs: the sweep must peel 256
    // per batch while the family row stays.
    let live_head = insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        live_family,
        None,
        Utc::now() + Duration::hours(1),
    )
    .await;
    sql_query(
        "INSERT INTO oauth_refresh_spent_tokens (\
             tenant_id, refresh_token_blake3, token_family_id, member_id, \
             successor_member_id, spent_at, expires_at) \
         SELECT $1, decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'), \
                $2, gen_random_uuid(), $3, $4, $5 \
         FROM generate_series(1, 10000)",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(live_family)
    .bind::<SqlUuid, _>(live_head)
    .bind::<Timestamptz, _>(past)
    .bind::<Timestamptz, _>(past + Duration::hours(1))
    .execute(&mut connection)
    .await
    .expect("large spent fixture should insert");

    // An expired family with 1,000 expired spent proofs: the family delete
    // cascades them in one batch.
    let dead_head = insert_refresh_leaf_in_tenant(
        &mut connection,
        &fixture,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        dead_family,
        None,
        past,
    )
    .await;
    sql_query(
        "INSERT INTO oauth_refresh_spent_tokens (\
             tenant_id, refresh_token_blake3, token_family_id, member_id, \
             successor_member_id, spent_at, expires_at) \
         SELECT $1, decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'), \
                $2, gen_random_uuid(), $3, $4, $5 \
         FROM generate_series(1, 1000)",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(dead_family)
    .bind::<SqlUuid, _>(dead_head)
    .bind::<Timestamptz, _>(past)
    .bind::<Timestamptz, _>(past + Duration::hours(1))
    .execute(&mut connection)
    .await
    .expect("dead-family spent fixture should insert");

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 4).unwrap());
    let mut spent_total = 0_u64;
    for round in 0..64_u32 {
        let result = maintenance
            .cleanup_batch()
            .await
            .expect("cleanup batch should succeed");
        assert!(
            result.spent_refresh_proofs <= 256,
            "one batch must never exceed the 256-row budget"
        );
        assert!(
            result.refresh_tokens <= 256,
            "the family sweep is bounded per batch too"
        );
        spent_total += result.spent_refresh_proofs;
        if !result.saturated && result.spent_refresh_proofs == 0 && result.refresh_tokens == 0 {
            break;
        }
        assert!(round < 63, "refresh-state reclaim must converge, not stall");
    }
    assert_eq!(
        spent_total, 10_000,
        "the dead family's proofs left by cascade are not double-counted; \
         only the live family's sweep drains through the bounded cursor"
    );
    assert_eq!(
        family_row_count(&mut connection, dead_family).await,
        0,
        "the expired family and its proofs must be gone"
    );
    assert_eq!(
        family_row_count(&mut connection, live_family).await,
        1,
        "the live family keeps its row; all expired proofs are swept"
    );
}

/// A spent proof expires on its own `expires_at` — the sweep deletes expired
/// proofs while the family's live current member and still-valid proofs are
/// untouched, and a retained proof keeps resolving through the token
/// repository for replay detection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_spent_proofs_reclaim_while_valid_proofs_and_live_family_survive() {
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let Some(database_url) = database_url() else {
        return;
    };
    let (fixture, mut connection) = fixture(&database_url).await;
    clear_expired_tokens(&mut connection).await;

    let family_id = Uuid::now_v7();
    let now = Utc::now();
    let live = insert_refresh_leaf(
        &mut connection,
        &fixture,
        family_id,
        None,
        now + Duration::hours(1),
    )
    .await;

    // Two proofs already past their own expiry; one still inside it.
    let raw_alive = format!("spent-alive-{}", Uuid::now_v7());
    for (seed, expires_at) in [
        ("dead-a", now - Duration::minutes(5)),
        ("dead-b", now - Duration::minutes(1)),
        (&*raw_alive, now + Duration::hours(1)),
    ] {
        sql_query(
            "INSERT INTO oauth_refresh_spent_tokens (\
                 tenant_id, refresh_token_blake3, token_family_id, member_id, \
                 successor_member_id, spent_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<sql_types::Binary, _>(blake3::hash(seed.as_bytes()).as_bytes().to_vec())
        .bind::<SqlUuid, _>(family_id)
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(live)
        .bind::<Timestamptz, _>(now - Duration::minutes(30))
        .bind::<Timestamptz, _>(expires_at)
        .execute(&mut connection)
        .await
        .expect("spent proof fixture should insert");
    }

    let repository = SecurityStateMaintenanceRepository::new(
        create_pool(&database_url, 2).expect("pool should build"),
    );
    let batch = repository
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    assert_eq!(
        batch.spent_refresh_proofs, 2,
        "only the proofs past their own expiry may be reclaimed"
    );

    #[derive(QueryableByName)]
    struct ProofRow {
        #[diesel(sql_type = sql_types::Binary)]
        refresh_token_blake3: Vec<u8>,
    }
    let proofs = sql_query(
        "SELECT refresh_token_blake3 FROM oauth_refresh_spent_tokens \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(family_id)
    .load::<ProofRow>(&mut connection)
    .await
    .expect("proof rows should load");
    assert_eq!(
        proofs
            .iter()
            .map(|row| row.refresh_token_blake3.clone())
            .collect::<Vec<_>>(),
        vec![blake3::hash(raw_alive.as_bytes()).as_bytes().to_vec()],
        "the still-valid proof must be the only survivor"
    );

    let tokens = nazo_postgres::TokenRepository::new(
        create_pool(&database_url, 2).expect("pool should build"),
    );
    let spent = tokens
        .by_raw_refresh_token(SYSTEM_TENANT, &raw_alive)
        .await
        .expect("lookup should succeed")
        .expect("a valid spent proof must still resolve for replay detection");
    assert_eq!(spent.token_family_id, family_id);
    assert!(
        spent.revoked_at.is_some(),
        "a spent presentation resolves revoked so the grant can classify it"
    );

    assert_eq!(
        family_row_count(&mut connection, family_id).await,
        2,
        "one live family row plus the one still-valid spent proof must survive"
    );
}

async fn audit_counts(connection: &mut AsyncPgConnection) -> (i64, i64) {
    let events = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events")
        .get_result::<CountRow>(connection)
        .await
        .expect("events count should query")
        .count;
    let chain = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_chain_entries")
        .get_result::<CountRow>(connection)
        .await
        .expect("chain count should query")
        .count;
    (events, chain)
}

async fn event_row_count(connection: &mut AsyncPgConnection, event_id: Uuid) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count \
         FROM security_audit_events WHERE event_id = $1",
    )
    .bind::<SqlUuid, _>(event_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("event count should query")
    .count
}

async fn chain_row_count(connection: &mut AsyncPgConnection, event_id: Uuid) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count \
         FROM security_audit_chain_entries WHERE event_id = $1",
    )
    .bind::<SqlUuid, _>(event_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("chain count should query")
    .count
}

/// Acknowledgement is the only retention boundary: it reclaims the delivered
/// event and chain-entry rows in the same transaction that advances the
/// anchor, an unacknowledged event keeps both rows, and the append-only
/// guard still rejects deletes without the reclaim permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acked_audit_rows_leave_the_ledger_and_unacked_rows_stay() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (_fixture, mut connection) = fixture(&database_url).await;
    let repository =
        nazo_postgres::AuditLedgerRepository::new(create_pool(&database_url, 2).unwrap());
    let deployment_id: String = sql_query(
        "SELECT anchor_deployment_id::text AS deployment \
         FROM security_audit_chain_state WHERE singleton",
    )
    .get_result::<DeploymentRow>(&mut connection)
    .await
    .expect("anchor deployment should read")
    .deployment
    .unwrap_or_else(|| "maint-dep".to_owned());

    // Drain residual pending rows so the fixture owns the committed prefix.
    loop {
        match repository
            .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
            .await
            .expect("residual batches should be claimable")
        {
            nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) => {
                ack_batch(&repository, &batch, batch.generation, &deployment_id)
                    .await
                    .expect("residual batch should be acknowledged");
            }
            nazo_persistence::SecurityAuditBatchClaim::Busy => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            nazo_persistence::SecurityAuditBatchClaim::Blocked { reason } => {
                panic!("residual blocked batch: {reason}");
            }
            nazo_persistence::SecurityAuditBatchClaim::Empty => break,
        }
    }

    // Two events claimed and acknowledged: both delivery copies leave in
    // the ack transaction, and the anchor lands on the batch tail.
    let acked_ids: Vec<Uuid> = (0..2).map(|_| Uuid::now_v7()).collect();
    for event_id in &acked_ids {
        insert_audit_event(&mut connection, *event_id).await;
    }
    let batch = match repository
        .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
        .await
        .expect("the pending events should form a claimable batch")
    {
        nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    let (events_before, chain_before) = audit_counts(&mut connection).await;
    ack_batch(&repository, &batch, batch.generation, &deployment_id)
        .await
        .expect("the batch should acknowledge");
    let (events_after, chain_after) = audit_counts(&mut connection).await;
    assert_eq!(
        events_before - events_after,
        2,
        "acked events leave security_audit_events"
    );
    assert_eq!(
        chain_before - chain_after,
        2,
        "acked chain entries leave security_audit_chain_entries"
    );
    for event_id in &acked_ids {
        assert_eq!(event_row_count(&mut connection, *event_id).await, 0);
        assert_eq!(chain_row_count(&mut connection, *event_id).await, 0);
    }

    // A fully delivered chain is still a valid chain: head reads through
    // `WHERE chain_valid`, so this returning a row at all proves the empty
    // post-delivery chain is accepted, with the anchor at the head.
    let health = repository
        .anchor_health()
        .await
        .expect("a fully delivered ledger must stay healthy");
    assert_eq!(health.last_exported_sequence, Some(health.head_sequence));
    assert!(!health.pending_orphan_exists);

    // One event claimed (chain entry exists) but never acknowledged keeps
    // both rows until its batch is delivered.
    let unacked = Uuid::now_v7();
    insert_audit_event(&mut connection, unacked).await;
    let pending_batch = match repository
        .claim_batch(&deployment_id, 256, 1024 * 1024, 60)
        .await
        .expect("the unacked event should claim")
    {
        nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    repository
        .fail_batch(pending_batch.generation, Utc::now(), "test-hold", false)
        .await
        .expect("batch should return to pending");
    assert_eq!(event_row_count(&mut connection, unacked).await, 1);
    assert_eq!(chain_row_count(&mut connection, unacked).await, 1);

    // The append-only guard still rejects direct deletes — both with no
    // permit and under the retired archive permit name.
    let rejected = sql_query("DELETE FROM security_audit_events WHERE true")
        .execute(&mut connection)
        .await;
    assert!(rejected.is_err(), "append-only guard must reject deletes");
    connection
        .batch_execute("SET nazo.audit_archive = 'on'")
        .await
        .expect("retired permit name should still set");
    let retired = sql_query("DELETE FROM security_audit_events WHERE true")
        .execute(&mut connection)
        .await;
    assert!(
        retired.is_err(),
        "the retired archive permit must not authorize deletes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_state_cleanup_is_bounded_and_preserves_live_ownership() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let (fixture, mut connection) = fixture(&database_url).await;
    let tag = Uuid::now_v7().simple().to_string();
    let expired_parent = Uuid::now_v7();
    let skew_parent = Uuid::now_v7();
    let live_parent = Uuid::now_v7();
    for (id, age) in [
        (expired_parent, -172800_i64),
        (skew_parent, -1),
        (live_parent, 3600),
    ] {
        sql_query(
            "INSERT INTO openid4vci_access_grants \
             (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) \
             VALUES ($1,$1::text,$2,$3,$4,'[\"pid\"]','[]',CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP + make_interval(secs => $5))",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<SqlUuid, _>(fixture.user_id)
        .bind::<Text, _>(&fixture.client_public_id)
        .bind::<sql_types::Double, _>(age as f64)
        .execute(&mut connection).await.unwrap();
    }
    // A single expired parent has more than one batch of each child. It must
    // survive the first round rather than cascading the remaining children.
    for (table, columns, values) in [
        (
            "openid4vci_deferred_transactions",
            "id,transaction_hash,token_id,credential_configuration_id,credential_format,holder_bindings,payload_ciphertext,ready_at,created_at,expires_at",
            "gen_random_uuid(),$2 || '-' || g,$1,'pid','dc+sd-jwt','[{}]','ciphertext'::bytea,CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP - interval '2 days'",
        ),
        (
            "openid4vci_notifications",
            "notification_id,token_id,issued_at,expires_at",
            "$2 || '-' || g,$1,CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP - interval '2 days'",
        ),
        (
            "openid4vci_issuance_responses",
            "issuance_id,token_id,request_digest,body_ciphertext,encoding,status,created_at,expires_at",
            "gen_random_uuid(),$1,md5($2 || '-' || g) || md5($2 || '-' || g),'ciphertext'::bytea,'json',200,CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP - interval '2 days'",
        ),
    ] {
        sql_query(format!(
            "INSERT INTO {table} ({columns}) SELECT {values} FROM generate_series(1, 300) AS g"
        ))
        .bind::<SqlUuid, _>(expired_parent)
        .bind::<Text, _>(&tag)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    sql_query(
        "INSERT INTO openid4vci_offers \
         (id,tenant_id,subject_id,credential_configuration_ids,grants_ciphertext,created_at,expires_at) \
         SELECT gen_random_uuid(),$1,$2,'[\"pid\"]','ciphertext'::bytea,CURRENT_TIMESTAMP - interval '3 days', \
                CASE WHEN g = 301 THEN CURRENT_TIMESTAMP + interval '1 hour' ELSE CURRENT_TIMESTAMP - interval '2 days' END \
         FROM generate_series(1,301) AS g",
    ).bind::<SqlUuid, _>(SYSTEM_TENANT).bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut connection).await.unwrap();
    sql_query(
        "INSERT INTO openid4vci_nonces (nonce_hash,created_at,expires_at) \
         SELECT $1 || '-' || g,CURRENT_TIMESTAMP - interval '3 days', \
                CASE WHEN g = 301 THEN CURRENT_TIMESTAMP + interval '1 hour' ELSE CURRENT_TIMESTAMP - interval '2 days' END \
         FROM generate_series(1,301) AS g",
    ).bind::<Text, _>(&tag).execute(&mut connection).await.unwrap();
    // The grant category must itself be bounded, independent of its children.
    sql_query(
        "INSERT INTO openid4vci_access_grants \
         (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) \
         SELECT gen_random_uuid(),$4 || '-' || g,$1,$2,$3,'[\"pid\"]','[]',CURRENT_TIMESTAMP - interval '3 days',CURRENT_TIMESTAMP - interval '2 days' \
         FROM generate_series(1,300) AS g",
    ).bind::<SqlUuid, _>(SYSTEM_TENANT).bind::<SqlUuid, _>(fixture.user_id)
        .bind::<Text, _>(&fixture.client_public_id).bind::<Text, _>(&tag)
        .execute(&mut connection).await.unwrap();

    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    for round in 0..8 {
        let result = maintenance.cleanup_batch().await.unwrap();
        for count in [
            result.credential_offers,
            result.credential_nonces,
            result.credential_access_grants,
            result.deferred_credentials,
            result.credential_notifications,
            result.credential_responses,
        ] {
            assert!(
                count <= 256,
                "every credential lifecycle must keep its own batch bound"
            );
        }
        if round == 0 {
            assert!(result.saturated);
            let parent = sql_query("SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = $1")
                .bind::<SqlUuid, _>(expired_parent).get_result::<CountRow>(&mut connection).await.unwrap();
            assert_eq!(
                parent.count, 1,
                "an expired parent cannot cascade children beyond their budget"
            );
            for table in [
                "openid4vci_deferred_transactions",
                "openid4vci_notifications",
                "openid4vci_issuance_responses",
            ] {
                let children = sql_query(format!(
                    "SELECT COUNT(*)::bigint AS count FROM {table} WHERE token_id = $1"
                ))
                .bind::<SqlUuid, _>(expired_parent)
                .get_result::<CountRow>(&mut connection)
                .await
                .unwrap();
                assert!(
                    children.count >= 44,
                    "{table} must retain children beyond the batch limit"
                );
            }
        }
        let due = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants \
             WHERE subject_id = $1 AND expires_at < CURRENT_TIMESTAMP - interval '1 day'",
        )
        .bind::<SqlUuid, _>(fixture.user_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
        if due.count == 0 {
            break;
        }
        assert_ne!(
            round, 7,
            "the expired parent and independent grants must drain"
        );
    }
    let retained = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = ANY($1)",
    )
    .bind::<sql_types::Array<SqlUuid>, _>(vec![skew_parent, live_parent])
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        retained.count, 2,
        "live and recently expired ownership must survive verifier clock skew"
    );
    let offers =
        sql_query("SELECT COUNT(*)::bigint AS count FROM openid4vci_offers WHERE subject_id = $1")
            .bind::<SqlUuid, _>(fixture.user_id)
            .get_result::<CountRow>(&mut connection)
            .await
            .unwrap();
    assert_eq!(offers.count, 1);
    let nonces = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_nonces WHERE nonce_hash LIKE $1",
    )
    .bind::<Text, _>(format!("{tag}-%"))
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(nonces.count, 1);
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash LIKE $1")
        .bind::<Text, _>(format!("{tag}-%"))
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.client_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_credential_sweepers_skip_an_uncommitted_child_parent() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let (fixture, mut writer) = fixture(&database_url).await;
    let parent_id = Uuid::now_v7();
    let control_id = Uuid::now_v7();
    let notification_id = Uuid::now_v7().to_string();
    for id in [parent_id, control_id] {
        sql_query(
            "INSERT INTO openid4vci_access_grants \
             (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) \
             VALUES ($1,$1::text,$2,$3,$4,'[\"pid\"]','[]',TIMESTAMPTZ '1899-01-01 UTC',TIMESTAMPTZ '1900-01-01 UTC')",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<SqlUuid, _>(fixture.user_id)
        .bind::<Text, _>(&fixture.client_public_id)
        .execute(&mut writer)
        .await
        .unwrap();
    }
    writer.batch_execute("BEGIN").await.unwrap();
    sql_query(
        "INSERT INTO openid4vci_notifications (notification_id,token_id,expires_at) \
         VALUES ($1,$2,CURRENT_TIMESTAMP + interval '1 hour')",
    )
    .bind::<Text, _>(&notification_id)
    .bind::<SqlUuid, _>(parent_id)
    .execute(&mut writer)
    .await
    .unwrap();
    // INSERT has completed its immediate FK check and therefore holds KEY
    // SHARE on the expired parent. The child is still invisible to sweepers.
    // No timer or task scheduling assumption establishes this interleaving.
    let pool = create_pool(&database_url, 3).unwrap();
    let mut observer = get_conn(&pool).await.unwrap();
    let invisible = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_notifications WHERE notification_id = $1",
    )
    .bind::<Text, _>(&notification_id)
    .get_result::<CountRow>(&mut observer)
    .await
    .unwrap();
    assert_eq!(
        invisible.count, 0,
        "the racing child must still be uncommitted"
    );
    let first = SecurityStateMaintenanceRepository::new(pool.clone());
    let second = SecurityStateMaintenanceRepository::new(pool.clone());
    let (first_result, second_result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(first.cleanup_batch(), second.cleanup_batch())
        })
        .await
        .expect("both sweepers must skip the FK-locked parent without waiting for its writer");
    for result in [first_result.unwrap(), second_result.unwrap()] {
        assert!(result.credential_access_grants <= 256);
        assert!(result.credential_notifications <= 256);
    }
    let retained = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(parent_id)
    .get_result::<CountRow>(&mut observer)
    .await
    .unwrap();
    assert_eq!(retained.count, 1);
    let reclaimed = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(control_id)
    .get_result::<CountRow>(&mut observer)
    .await
    .unwrap();
    assert_eq!(
        reclaimed.count, 0,
        "the unlocked expired control proves reclaim still makes progress"
    );
    writer.batch_execute("COMMIT").await.unwrap();
    first.cleanup_batch().await.unwrap();
    let retained_child = sql_query(
        "SELECT COUNT(*)::bigint AS count \
         FROM openid4vci_notifications AS child \
         JOIN openid4vci_access_grants AS parent ON parent.token_id = child.token_id \
         WHERE child.notification_id = $1 AND child.expires_at > CURRENT_TIMESTAMP",
    )
    .bind::<Text, _>(&notification_id)
    .get_result::<CountRow>(&mut observer)
    .await
    .unwrap();
    assert_eq!(
        retained_child.count, 1,
        "a committed future child and its parent must not be cascaded away"
    );
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut observer)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.client_id)
        .execute(&mut observer)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contract_scan_advances_past_referenced_pages_and_revisits_after_wrap() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let (fixture, mut connection) = fixture(&database_url).await;
    let mut families = Vec::new();
    // Distinct persisted auth_time values give these live families distinct
    // contracts. Every referenced contract sorts before the orphan below.
    let future = Utc::now() + Duration::minutes(20);
    for offset in 0..300 {
        let family = Uuid::now_v7();
        insert_refresh_leaf(
            &mut connection,
            &fixture,
            family,
            None,
            future + Duration::seconds(offset),
        )
        .await;
        families.push(family);
    }
    sql_query(
        "UPDATE oauth_refresh_contracts AS contract SET created_at = TIMESTAMPTZ '1000-01-01 UTC' \
         FROM oauth_refresh_families AS family \
         WHERE family.tenant_id = contract.tenant_id AND family.contract_blake3 = contract.contract_blake3 \
           AND family.token_family_id = ANY($1)",
    )
    .bind::<sql_types::Array<SqlUuid>, _>(&families)
    .execute(&mut connection)
    .await
    .unwrap();
    let orphan = Uuid::now_v7();
    insert_refresh_leaf(
        &mut connection,
        &fixture,
        orphan,
        None,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    #[derive(QueryableByName)]
    struct ContractRow {
        #[diesel(sql_type = sql_types::Binary)]
        contract_blake3: Vec<u8>,
    }
    let orphan_digest = sql_query(
        "UPDATE oauth_refresh_contracts AS contract SET created_at = TIMESTAMPTZ '1001-01-01 UTC' \
         FROM oauth_refresh_families AS family \
         WHERE family.tenant_id = contract.tenant_id AND family.contract_blake3 = contract.contract_blake3 \
           AND family.tenant_id = $1 AND family.token_family_id = $2 \
         RETURNING contract.contract_blake3",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(orphan)
    .get_result::<ContractRow>(&mut connection)
    .await
    .unwrap()
    .contract_blake3;
    sql_query("DELETE FROM oauth_refresh_families WHERE tenant_id = $1 AND token_family_id = $2")
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<SqlUuid, _>(orphan)
        .execute(&mut connection)
        .await
        .unwrap();
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let first = maintenance.cleanup_batch().await.unwrap();
    assert_eq!(first.refresh_contracts, 0);
    assert!(
        first.saturated,
        "a referenced full page still advances the scan"
    );
    // A clone must continue the same scan, not restart at its referenced head.
    maintenance.clone().cleanup_batch().await.unwrap();
    let orphan_count = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_contracts WHERE tenant_id = $1 AND contract_blake3 = $2",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<sql_types::Binary, _>(&orphan_digest)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        orphan_count.count, 0,
        "referenced parents must not starve a later orphan"
    );

    // Remove a reference that this pass has already visited. A completed
    // pass must wrap and discover it without restarting the repository.
    let released = sql_query(
        "DELETE FROM oauth_refresh_families WHERE tenant_id = $1 AND token_family_id = $2 RETURNING contract_blake3",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(families[0])
    .get_result::<ContractRow>(&mut connection)
    .await
    .unwrap()
    .contract_blake3;
    for round in 0..8 {
        maintenance.cleanup_batch().await.unwrap();
        let count = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_contracts WHERE tenant_id = $1 AND contract_blake3 = $2",
        )
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<sql_types::Binary, _>(&released)
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
        if count.count == 0 {
            break;
        }
        assert_ne!(
            round, 7,
            "completed scans must revisit newly unreferenced contracts"
        );
    }
    let live = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families AS family \
         JOIN oauth_refresh_contracts AS contract USING (tenant_id, contract_blake3) \
         WHERE family.tenant_id = $1 AND family.token_family_id = ANY($2)",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<sql_types::Array<SqlUuid>, _>(&families)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        live.count, 299,
        "all still-referenced contracts must remain"
    );
    sql_query("DELETE FROM oauth_refresh_families WHERE tenant_id = $1 AND user_id = $2")
        .bind::<SqlUuid, _>(SYSTEM_TENANT)
        .bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    // Do not leave the centuries-old fixture at the head of sibling scans.
    sql_query(
        "DELETE FROM oauth_refresh_contracts WHERE tenant_id = $1 AND contract->>'subject' = $2",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(fixture.user_id.to_string())
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.client_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_scan_advances_past_referenced_pages_and_revisits_after_wrap() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE.acquire().await.unwrap();
    let (fixture, mut connection) = fixture(&database_url).await;
    let tag = Uuid::now_v7().simple().to_string();
    sql_query(
        "WITH parents AS ( \
             INSERT INTO openid4vci_access_grants \
             (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) \
             SELECT gen_random_uuid(),$4 || '-' || g,$1,$2,$3,'[\"pid\"]','[]',TIMESTAMPTZ '0999-01-01 UTC',TIMESTAMPTZ '1000-01-01 UTC' \
             FROM generate_series(1,300) AS g RETURNING token_id \
         ) INSERT INTO openid4vci_notifications (notification_id,token_id,expires_at) \
         SELECT token_id::text,token_id,CURRENT_TIMESTAMP + interval '1 hour' FROM parents",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.user_id)
    .bind::<Text, _>(&fixture.client_public_id)
    .bind::<Text, _>(&tag)
    .execute(&mut connection)
    .await
    .unwrap();
    let orphan = Uuid::now_v7();
    sql_query(
        "INSERT INTO openid4vci_access_grants \
         (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,created_at,expires_at) \
         VALUES ($1,$1::text,$2,$3,$4,'[\"pid\"]','[]',TIMESTAMPTZ '0999-01-01 UTC',TIMESTAMPTZ '1001-01-01 UTC')",
    )
    .bind::<SqlUuid, _>(orphan)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.user_id)
    .bind::<Text, _>(&fixture.client_public_id)
    .execute(&mut connection)
    .await
    .unwrap();
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    let first = maintenance.cleanup_batch().await.unwrap();
    assert_eq!(first.credential_access_grants, 0);
    assert!(first.saturated);
    maintenance.clone().cleanup_batch().await.unwrap();
    let count = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(orphan)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        count.count, 0,
        "a later childless grant must not starve behind a full referenced page"
    );
    #[derive(QueryableByName)]
    struct GrantRow {
        #[diesel(sql_type = SqlUuid)]
        token_id: Uuid,
    }
    let released = sql_query(
        "DELETE FROM openid4vci_notifications WHERE token_id = ( \
             SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1 ORDER BY expires_at,token_id LIMIT 1 \
         ) RETURNING token_id",
    )
    .bind::<SqlUuid, _>(fixture.user_id)
    .get_result::<GrantRow>(&mut connection)
    .await
    .unwrap()
    .token_id;
    for round in 0..8 {
        maintenance.cleanup_batch().await.unwrap();
        let count = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants WHERE token_id = $1",
        )
        .bind::<SqlUuid, _>(released)
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
        if count.count == 0 {
            break;
        }
        assert_ne!(
            round, 7,
            "a completed pass must revisit a parent whose child is later removed"
        );
    }
    let retained = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM openid4vci_access_grants AS parent \
         JOIN openid4vci_notifications AS child USING (token_id) WHERE parent.subject_id = $1",
    )
    .bind::<SqlUuid, _>(fixture.user_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        retained.count, 299,
        "unexpired children and their parents must survive every pass"
    );
    sql_query("DELETE FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.user_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.client_id)
        .execute(&mut connection)
        .await
        .unwrap();
}
