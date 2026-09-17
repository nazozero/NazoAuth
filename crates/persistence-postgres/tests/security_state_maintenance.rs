//! Bounded security-state maintenance coverage.
//!
//! One `cleanup_batch` performs at most 256 deletions per category. Refresh
//! reclaim walks leaves only, under the shared family advisory key, and never
//! touches a family that still has an unexpired member. OpenID4VP reads are
//! pure selects; the global presentation sweep belongs exclusively to this
//! worker.

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
struct FixtureIds {
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = Text)]
    client_public_id: String,
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
    let id = Uuid::now_v7();
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    sql_query(
        "INSERT INTO oauth_tokens (\
             id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id, \
             client_id, user_id, scopes, audience, authorization_details, \
             issued_at, expires_at, subject, oidc_auth_context) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
             '[\"openid\"]'::jsonb, '[\"resource://default\"]'::jsonb, '[]'::jsonb, \
             $8, $9, $10, $11::jsonb)",
    )
    .bind::<SqlUuid, _>(id)
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(token_hash)
    .bind::<SqlUuid, _>(family_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(rotated_from_id)
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(Some(fixture.user_id))
    .bind::<Timestamptz, _>(expires_at - Duration::hours(1))
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Text, _>(fixture.user_id.to_string())
    .bind::<sql_types::Jsonb, _>(
        serde_json::to_value(RefreshTokenAuthenticationContext {
            version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
            issuer: "https://issuer.example".to_owned(),
            audience: fixture.client_public_id.clone(),
            auth_time: (expires_at - Duration::hours(1)).timestamp() - 1,
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
            id_token_sid: None,
            acr: None,
            nonce: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
        })
        .expect("refresh auth context should serialize"),
    )
    .execute(connection)
    .await
    .expect("refresh leaf fixture should insert");
    id
}

async fn family_row_count(connection: &mut AsyncPgConnection, family_id: Uuid) -> i64 {
    sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_tokens WHERE token_family_id = $1")
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
    // The successor is still valid, so the family is not fully expired.
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
        2,
        "an unexpired successor must keep the whole family, ancestry included"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_generation_family_reclaims_leaves_first_over_cycles() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = CLEANUP_BATCH_GATE
        .acquire()
        .await
        .expect("cleanup-batch test gate should remain open");
    let (fixture, mut connection) = fixture(&database_url).await;
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
    for expected_remaining in [2_i64, 1, 0] {
        maintenance
            .cleanup_batch()
            .await
            .expect("cleanup batch should succeed");
        assert_eq!(
            family_row_count(&mut connection, family_id).await,
            expected_remaining,
            "only the current leaf may be reclaimed per cycle; the self-FK \
             ancestry chain must stay intact until each node becomes a leaf"
        );
    }
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
    // maintenance recheck after lock acquisition must see the family is no
    // longer fully expired even though the earlier scan listed it.
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
        2,
        "a family that gained an unexpired member after the candidate scan \
         must survive the post-lock recheck"
    );
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
        "CREATE TRIGGER {trigger} BEFORE DELETE ON oauth_tokens \
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
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_tokens"))
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
