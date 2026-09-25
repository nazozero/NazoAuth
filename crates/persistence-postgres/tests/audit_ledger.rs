use std::sync::Arc;

use chrono::Utc;
use diesel::{QueryableByName, sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{
    SecurityAuditBatch, SecurityAuditBatchAck, SecurityAuditBatchClaim, SecurityAuditExporter,
};
use nazo_postgres::{
    AuditLedgerRepository, MAX_SECURITY_AUDIT_PAYLOAD_BYTES, SecurityAuditEvent, create_pool,
    run_pending_migrations,
};
use serde_json::json;
use uuid::Uuid;

static AUDIT_LEDGER_CLAIM_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const AUDIT_LEDGER_UP: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/up.sql");
const AUDIT_LEDGER_DOWN: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/down.sql");
const SHARED_ANCHOR_UP: &str =
    include_str!("../../../migrations/20260905000100_shared_audit_anchor_state/up.sql");
const BATCH_DELIVERY_UP: &str =
    include_str!("../../../migrations/20260920000100_audit_anchor_batch_delivery/up.sql");
const BATCH_DELIVERY_DOWN: &str =
    include_str!("../../../migrations/20260920000100_audit_anchor_batch_delivery/down.sql");
const DELIVERY_RETENTION_UP: &str =
    include_str!("../../../migrations/20260924000100_audit_delivery_scoped_retention/up.sql");
const DELIVERY_RETENTION_DOWN: &str =
    include_str!("../../../migrations/20260924000100_audit_delivery_scoped_retention/down.sql");

#[test]
fn audit_ledger_migration_is_append_only_and_has_durable_outbox() {
    for required in [
        "security_audit_chain_state",
        "security_audit_events",
        "security_audit_event_outbox",
        "security_audit_events_append_only",
        "security_audit_events_no_truncate",
        "octet_length(event_hash) = 32",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "nazo_append_security_audit_event",
        "nazo_claim_security_audit_events",
        "nazo_ack_security_audit_event",
        "nazo_reschedule_security_audit_event",
        "nazo_security_audit_privilege_preflight",
        "nazo_security_audit_anchor_freshness",
        "nazo_security_audit_anchor_health",
        "REVOKE ALL ON TABLE",
        "FROM PUBLIC",
    ] {
        assert!(AUDIT_LEDGER_UP.contains(required), "missing {required}");
    }
    for required in [
        "DROP TRIGGER IF EXISTS security_audit_events_append_only",
        "DROP FUNCTION IF EXISTS public.nazo_append_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_claim_security_audit_events",
        "DROP FUNCTION IF EXISTS public.nazo_ack_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_reschedule_security_audit_event",
        "DROP FUNCTION IF EXISTS public.nazo_security_audit_privilege_preflight",
        "DROP FUNCTION IF EXISTS public.nazo_security_audit_anchor_health",
        "DROP TABLE IF EXISTS public.security_audit_event_outbox",
        "DROP TABLE IF EXISTS public.security_audit_events",
        "DROP TABLE IF EXISTS public.security_audit_chain_state",
    ] {
        assert!(AUDIT_LEDGER_DOWN.contains(required), "missing {required}");
    }
}

#[test]
fn shared_anchor_migration_persists_checkpoint_without_a_local_file() {
    for required in [
        "anchor_deployment_id",
        "nazo_observe_security_audit_anchor",
        "nazo_record_security_audit_genesis",
        "nazo_security_audit_shared_anchor_health",
        "nazo_security_audit_shared_privilege_preflight",
    ] {
        assert!(SHARED_ANCHOR_UP.contains(required), "missing {required}");
    }
}

#[test]
fn batch_delivery_migration_fences_one_batch_and_retires_per_event_state() {
    for required in [
        "batch_generation BIGINT NOT NULL DEFAULT 0",
        "ck_security_audit_batch_shape",
        "nazo_security_audit_batch_members",
        "nazo_claim_security_audit_pending",
        "nazo_open_security_audit_batch",
        "nazo_reclaim_security_audit_batch",
        "nazo_ack_security_audit_batch",
        "nazo_fail_security_audit_batch",
        "nazo_unblock_security_audit_batch",
        "pending_orphan_exists",
        "DROP FUNCTION public.nazo_claim_security_audit_events",
        "DROP FUNCTION public.nazo_ack_security_audit_event",
        "DROP FUNCTION public.nazo_reschedule_security_audit_event",
        "DROP COLUMN attempts",
        "DROP COLUMN available_at",
        "DROP COLUMN locked_at",
        "DROP COLUMN last_error",
    ] {
        assert!(BATCH_DELIVERY_UP.contains(required), "missing {required}");
    }
    for required in [
        "DROP FUNCTION public.nazo_security_audit_batch_members",
        "DROP FUNCTION public.nazo_claim_security_audit_pending",
        "DROP FUNCTION public.nazo_open_security_audit_batch",
        "DROP FUNCTION public.nazo_reclaim_security_audit_batch",
        "DROP FUNCTION public.nazo_ack_security_audit_batch",
        "DROP FUNCTION public.nazo_fail_security_audit_batch",
        "DROP FUNCTION public.nazo_unblock_security_audit_batch",
        "nazo_claim_security_audit_events",
        "nazo_ack_security_audit_event",
        "nazo_reschedule_security_audit_event",
    ] {
        assert!(BATCH_DELIVERY_DOWN.contains(required), "missing {required}");
    }
}

#[test]
fn delivery_scoped_retention_migration_reclaims_at_ack_and_drops_archive() {
    for required in [
        "nazo.audit_reclaim",
        "DELETE FROM public.security_audit_event_outbox",
        "DELETE FROM public.security_audit_chain_entries",
        "DELETE FROM public.security_audit_events",
        "DROP FUNCTION IF EXISTS public.nazo_archive_security_audit_prefix(BIGINT, TIMESTAMPTZ)",
        "DROP TABLE IF EXISTS public.security_audit_archive",
        "DROP TABLE IF EXISTS public.security_audit_archive_state",
    ] {
        assert!(
            DELIVERY_RETENTION_UP.contains(required),
            "missing {required}"
        );
    }
    for required in [
        "CREATE TABLE public.security_audit_archive",
        "nazo_archive_security_audit_prefix",
    ] {
        assert!(
            DELIVERY_RETENTION_DOWN.contains(required),
            "missing {required}"
        );
    }
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI audit ledger tests require an isolated NAZO_AUDIT_TEST_DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct EventHashRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    event_hash: Vec<u8>,
}

fn batch_ack(batch: &SecurityAuditBatch) -> SecurityAuditBatchAck {
    SecurityAuditBatchAck {
        generation: batch.generation,
        deployment_id: "test-deployment".to_owned(),
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        event_count: batch.event_count(),
        last_hash: batch.last_hash.clone(),
        batch_digest: batch.digest.clone(),
    }
}

async fn drain_outbox(repository: &AuditLedgerRepository) {
    loop {
        match repository
            .claim_batch("test-deployment", 256, 1024 * 1024, 60)
            .await
            .expect("existing audit batches should be claimable")
        {
            SecurityAuditBatchClaim::Claimed(batch) => {
                // A committed batch whose lease is still held cannot be acked by
                // a concurrent claim; the lease is owned by this caller.
                repository
                    .ack_batch(batch_ack(&batch))
                    .await
                    .expect("existing audit batch should be drainable");
            }
            SecurityAuditBatchClaim::Busy => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            SecurityAuditBatchClaim::Blocked { reason } => {
                panic!("drain cannot proceed past a blocked batch: {reason}");
            }
            SecurityAuditBatchClaim::Empty => break,
        }
    }
}

#[tokio::test]
async fn audit_ledger_append_is_chained_and_outboxed() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let pool = create_pool(database_url.clone(), 4).expect("audit pool should create");
    let repository = Arc::new(AuditLedgerRepository::new(pool));
    let initial_health = repository
        .anchor_health()
        .await
        .expect("initial shared anchor health should be readable");
    let genesis = SecurityAuditExporter::record_genesis(
        &repository,
        "test-deployment",
        &initial_health.head_hash,
    )
    .await;
    if initial_health.head_sequence == 0 {
        genesis.expect("an empty ledger should accept its genesis checkpoint");
    } else {
        assert!(matches!(genesis, Err(RepositoryError::Consistency(_))));
    }
    SecurityAuditExporter::observe_anchor(&repository, "test-deployment")
        .await
        .expect("the exporter should observe the complete shared anchor");
    drain_outbox(&repository).await;
    let first_id = Uuid::now_v7();
    let second_id = Uuid::now_v7();
    repository
        .append(SecurityAuditEvent {
            event_id: first_id,
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": "first"}),
            occurred_at: Utc::now(),
        })
        .await
        .expect("first audit event should append");
    repository
        .append(SecurityAuditEvent {
            event_id: second_id,
            event_type: "token_revoked".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": "second"}),
            occurred_at: Utc::now(),
        })
        .await
        .expect("second audit event should append");
    let pending_health = repository.anchor_health().await.unwrap();
    assert_eq!(
        pending_health.head_sequence, initial_health.head_sequence,
        "writer commits must not extend the global chain"
    );
    assert!(pending_health.pending_exists);
    let claimed = match repository
        .claim_batch("test-deployment", 10, 1024 * 1024, 60)
        .await
        .expect("audit outbox should claim")
    {
        SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    assert_eq!(claimed.deliveries.len(), 2);
    assert_eq!(claimed.deliveries[0].event_id, first_id);
    assert_eq!(claimed.deliveries[1].event_id, second_id);
    assert_eq!(
        claimed.deliveries[1].sequence,
        claimed.deliveries[0].sequence + 1
    );
    assert_eq!(claimed.first_sequence, claimed.deliveries[0].sequence);
    assert_eq!(claimed.last_sequence, claimed.deliveries[1].sequence);
    assert_eq!(claimed.digest.len(), 32);
    assert_eq!(claimed.attempts, 0);
    let second_sequence = claimed.last_sequence;

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("audit test database should connect");
    let previous =
        sql_query("SELECT event_hash FROM security_audit_chain_entries WHERE event_id = $1")
            .bind::<SqlUuid, _>(first_id)
            .get_result::<EventHashRow>(&mut connection)
            .await
            .expect("first audit hash should be readable");
    let second_previous = sql_query(
        "SELECT previous_hash AS event_hash FROM security_audit_chain_entries WHERE event_id = $1",
    )
    .bind::<SqlUuid, _>(second_id)
    .get_result::<EventHashRow>(&mut connection)
    .await
    .expect("second audit previous hash should be readable");
    assert_eq!(second_previous.event_hash, previous.event_hash);

    repository
        .ack_batch(batch_ack(&claimed))
        .await
        .expect("every claimed audit batch should be acknowledged");

    let health = repository
        .anchor_health()
        .await
        .expect("audit anchor health should be readable through its function");
    assert!(health.head_sequence >= second_sequence);
    assert_eq!(health.head_hash.len(), 32);
    assert!(!health.pending_exists);
    assert!(!health.pending_orphan_exists);
    assert!(health.batch.is_none());
    assert_eq!(health.last_exported_sequence, Some(health.head_sequence));
    assert_eq!(
        health.last_exported_hash.as_deref(),
        Some(health.head_hash.as_slice())
    );
    assert_eq!(health.deployment_id.as_deref(), Some("test-deployment"));
    assert!(health.observed_at.is_some());

    let restarted_repository = AuditLedgerRepository::new(
        create_pool(database_url.clone(), 2).expect("a second audit pool should create"),
    );
    let restarted_health = restarted_repository
        .anchor_health()
        .await
        .expect("another instance should read the shared audit checkpoint");
    assert_eq!(restarted_health, health);

    // The acknowledged pair was reclaimed with the batch; a fresh unacked
    // event is the row the append-only guard must still protect.
    let third_id = Uuid::now_v7();
    repository
        .append(SecurityAuditEvent {
            event_id: third_id,
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": "third"}),
            occurred_at: Utc::now(),
        })
        .await
        .expect("third audit event should append");
    let mutation =
        sql_query("UPDATE security_audit_events SET event_type = event_type WHERE event_id = $1")
            .bind::<SqlUuid, _>(third_id)
            .execute(&mut connection)
            .await;
    assert!(
        mutation.is_err(),
        "ledger mutation must be rejected by trigger"
    );
}

#[tokio::test]
async fn audit_ledger_rejects_invalid_events_and_enforces_batch_fencing() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let pool = create_pool(database_url.clone(), 2).expect("audit pool should create");
    let repository = AuditLedgerRepository::new(pool);
    drain_outbox(&repository).await;

    for event in [
        SecurityAuditEvent {
            event_id: uuid::Uuid::nil(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({}),
            occurred_at: Utc::now(),
        },
        SecurityAuditEvent {
            event_id: uuid::Uuid::now_v7(),
            event_type: "Token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({}),
            occurred_at: Utc::now(),
        },
        SecurityAuditEvent {
            event_id: uuid::Uuid::now_v7(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!("not-an-object"),
            occurred_at: Utc::now(),
        },
    ] {
        assert!(matches!(
            repository.append(event).await,
            Err(RepositoryError::Unexpected(_))
        ));
    }
    assert!(matches!(
        repository
            .append(SecurityAuditEvent {
                event_id: uuid::Uuid::now_v7(),
                event_type: "a".repeat(65),
                event_category: "token_lifecycle".to_owned(),
                payload: json!({}),
                occurred_at: Utc::now(),
            })
            .await,
        Err(RepositoryError::Unexpected(_))
    ));
    assert!(matches!(
        repository
            .append(SecurityAuditEvent {
                event_id: uuid::Uuid::now_v7(),
                event_type: "token_issued".to_owned(),
                event_category: "token_lifecycle".to_owned(),
                payload: json!({"body": "x".repeat(MAX_SECURITY_AUDIT_PAYLOAD_BYTES)}),
                occurred_at: Utc::now(),
            })
            .await,
        Err(RepositoryError::Unexpected(_))
    ));
    for (limit, lock_timeout_seconds) in [(0, 60), (257, 60), (1, 0), (1, 3_601)] {
        assert!(matches!(
            repository
                .claim_batch("test-deployment", limit, 1024 * 1024, lock_timeout_seconds)
                .await,
            Err(RepositoryError::Unexpected(_))
        ));
    }
    for max_envelope_bytes in [0, 64 * 1024, 2 * 1024 * 1024] {
        assert!(matches!(
            repository
                .claim_batch("test-deployment", 1, max_envelope_bytes, 60)
                .await,
            Err(RepositoryError::Unexpected(_))
        ));
    }

    let event = SecurityAuditEvent {
        event_id: uuid::Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: json!({"subject_hash": "idempotent"}),
        occurred_at: Utc::now(),
    };
    let event_id = event.event_id;
    repository
        .append(event.clone())
        .await
        .expect("a valid audit event should append");
    repository
        .append(event.clone())
        .await
        .expect("repeating an identical audit event should be idempotent");
    let mut collision = event;
    collision.payload = json!({"subject_hash": "collision"});
    assert!(matches!(
        repository.append(collision).await,
        Err(RepositoryError::Unexpected(_))
    ));

    let first = match repository
        .claim_batch("test-deployment", 10, 1024 * 1024, 60)
        .await
        .expect("the appended audit event should be claimable")
    {
        SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    assert!(
        first
            .deliveries
            .iter()
            .any(|delivery| delivery.event_id == event_id),
        "the appended audit event should be inside the claimed batch"
    );
    // A held lease cannot be claimed or acknowledged under a moved generation.
    let mut stale_ack = batch_ack(&first);
    stale_ack.generation += 1;
    assert!(matches!(
        repository.ack_batch(stale_ack).await,
        Err(RepositoryError::Consistency(_))
    ));
    repository
        .fail_batch(
            first.generation,
            Utc::now() - chrono::Duration::seconds(1),
            "temporary exporter failure",
            false,
        )
        .await
        .expect("a current batch should be reschedulable");
    let second = match repository
        .claim_batch("test-deployment", 10, 1024 * 1024, 60)
        .await
        .expect("a rescheduled batch should be claimable again")
    {
        SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a reclaimed batch, got {other:?}"),
    };
    assert_eq!(second.attempts, first.attempts + 1);
    assert!(second.generation > first.generation);
    assert_eq!(second.first_sequence, first.first_sequence);
    assert_eq!(second.last_sequence, first.last_sequence);
    assert_eq!(second.digest, first.digest);
    assert_eq!(second.deliveries.len(), first.deliveries.len());
    // The stale generation can no longer settle or reschedule the batch.
    assert!(matches!(
        repository.ack_batch(batch_ack(&first)).await,
        Err(RepositoryError::Consistency(_))
    ));
    repository
        .ack_batch(batch_ack(&second))
        .await
        .expect("the current batch should be acknowledged");
    assert!(matches!(
        repository.ack_batch(batch_ack(&second)).await,
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        repository
            .fail_batch(
                second.generation,
                Utc::now(),
                "late exporter failure",
                false,
            )
            .await,
        Err(RepositoryError::Consistency(_))
    ));
    let health = repository.anchor_health().await.unwrap();
    assert!(health.batch.is_none());
    assert!(!health.pending_exists);
    let freshness = repository
        .anchor_health()
        .await
        .expect("the immutable chain head should remain fresh");
    assert_eq!(freshness.head_hash.len(), 32);
    repository
        .check_available_with_policy(false)
        .await
        .expect("writer preflight should accept the isolated test database");
    repository
        .check_exporter_available_with_policy(false)
        .await
        .expect("exporter preflight should accept the isolated test database");
}

#[tokio::test]
async fn audit_ledger_append_batch_commits_atomically() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let pool = create_pool(database_url.clone(), 4).expect("audit pool should create");
    let repository = AuditLedgerRepository::new(pool);
    drain_outbox(&repository).await;

    // Empty batches are a no-op without a checkout.
    repository
        .append_batch(&[])
        .await
        .expect("an empty batch should succeed");

    // A single event keeps the established single-append semantics, including
    // the same idempotent replay result.
    let single = SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: json!({"subject_hash": "single"}),
        occurred_at: Utc::now(),
    };
    repository
        .append_batch(std::slice::from_ref(&single))
        .await
        .expect("a single-event batch should persist");
    repository
        .append_batch(std::slice::from_ref(&single))
        .await
        .expect("a repeated identical single-event batch should be idempotent");

    let mut batch: Vec<SecurityAuditEvent> = (0..64)
        .map(|index| SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": format!("batch-{index}")}),
            occurred_at: Utc::now(),
        })
        .collect();
    repository
        .append_batch(&batch)
        .await
        .expect("a 64-event batch should persist in one transaction");
    // Repeating the identical batch is idempotent: no duplicate events or
    // outbox entries appear.
    repository
        .append_batch(&batch)
        .await
        .expect("a repeated identical batch should be idempotent");

    #[derive(QueryableByName)]
    struct IdCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        value: i64,
    }
    let batch_ids: Vec<Uuid> = batch.iter().map(|event| event.event_id).collect();
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("audit test database should connect");
    for table in ["security_audit_events", "security_audit_event_outbox"] {
        let count = sql_query(format!(
            "SELECT count(*) AS value FROM public.{table} WHERE event_id = ANY($1)"
        ))
        .bind::<diesel::sql_types::Array<SqlUuid>, _>(&batch_ids)
        .get_result::<IdCount>(&mut connection)
        .await
        .expect("batch row count should be readable");
        assert_eq!(
            count.value, 64,
            "{table} must hold each batch event exactly once"
        );
    }

    // A payload collision part-way through the batch must roll the whole
    // transaction back: none of the preceding events may survive.
    let collided_id = batch[10].event_id;
    let mut failing: Vec<SecurityAuditEvent> = (0..8)
        .map(|index| SecurityAuditEvent {
            event_id: Uuid::now_v7(),
            event_type: "token_issued".to_owned(),
            event_category: "token_lifecycle".to_owned(),
            payload: json!({"subject_hash": format!("failing-{index}")}),
            occurred_at: Utc::now(),
        })
        .collect();
    failing.push(SecurityAuditEvent {
        event_id: collided_id,
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: json!({"subject_hash": "different-payload"}),
        occurred_at: Utc::now(),
    });
    let failing_ids: Vec<Uuid> = failing.iter().take(8).map(|event| event.event_id).collect();
    assert!(
        repository.append_batch(&failing).await.is_err(),
        "a batch colliding with an existing event must fail"
    );
    let count = sql_query(
        "SELECT count(*) AS value FROM public.security_audit_events WHERE event_id = ANY($1)",
    )
    .bind::<diesel::sql_types::Array<SqlUuid>, _>(&failing_ids)
    .get_result::<IdCount>(&mut connection)
    .await
    .expect("rolled-back row count should be readable");
    assert_eq!(
        count.value, 0,
        "a failed batch must not leave any of its events behind"
    );

    // Validation is not loosened inside a batch: an invalid payload rejects
    // the whole batch.
    let mut invalid = batch.pop().expect("the batch still has events");
    invalid.payload = json!("not-an-object");
    assert!(matches!(
        repository.append_batch(&[invalid]).await,
        Err(RepositoryError::Unexpected(_))
    ));

    // Batched rows still flow through the exporter claim/ack path unchanged.
    let claimed = match repository
        .claim_batch("test-deployment", 256, 1024 * 1024, 60)
        .await
        .expect("batched audit events should be claimable")
    {
        SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    };
    assert!(
        batch_ids
            .iter()
            .all(|id| claimed.deliveries.iter().any(|d| d.event_id == *id)),
        "every batched event must reach the exporter outbox"
    );
    repository
        .ack_batch(batch_ack(&claimed))
        .await
        .expect("the batched events should acknowledge normally");
}

const BOUNDED_CLAIM_UP: &str =
    include_str!("../../../migrations/20260925000100_audit_claim_bounded_scan/up.sql");
const BOUNDED_CLAIM_DOWN: &str =
    include_str!("../../../migrations/20260925000100_audit_claim_bounded_scan/down.sql");

#[test]
fn bounded_claim_migration_materializes_identities_before_joining() {
    for required in [
        "WITH chained AS MATERIALIZED",
        "ORDER BY chain.sequence",
        "IF v_claimed > 0 THEN RETURN",
        "WITH pending AS MATERIALIZED",
        "ORDER BY outbox.occurred_at, outbox.event_id",
        "autovacuum_analyze_scale_factor = 0",
        "autovacuum_analyze_threshold = 500",
        // Plan pinning is structural: without statistics a table estimates
        // near-empty and a backlog-proportional scan + sort can win on cost.
        // The claim must be index-driven at any statistics state.
        "SET enable_seqscan = off",
        "SET enable_bitmapscan = off",
    ] {
        assert!(BOUNDED_CLAIM_UP.contains(required), "missing {required}");
    }
    // The hot-path candidate read must not re-prove the chain/outbox
    // invariant: no anti-join, no offset, no unbounded sortable output.
    let branch_two = BOUNDED_CLAIM_UP
        .split("WITH pending AS MATERIALIZED")
        .nth(1)
        .expect("pending branch exists");
    assert!(!branch_two.contains("NOT EXISTS"));
    assert!(!BOUNDED_CLAIM_UP.contains("OFFSET"));
    for required in [
        "NOT EXISTS",
        "CREATE OR REPLACE FUNCTION public.nazo_claim_security_audit_pending",
        "RESET (autovacuum_analyze_scale_factor, autovacuum_analyze_threshold)",
    ] {
        assert!(BOUNDED_CLAIM_DOWN.contains(required), "missing {required}");
    }
}

async fn explain_plan(connection: &mut AsyncPgConnection, query: &str) -> String {
    #[derive(QueryableByName)]
    struct PlanRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        nazo_test_explain: String,
    }
    sql_query(
        "CREATE OR REPLACE FUNCTION pg_temp.nazo_test_explain(q TEXT) \
         RETURNS SETOF TEXT LANGUAGE plpgsql AS $$ \
         DECLARE r RECORD; BEGIN \
           FOR r IN EXECUTE q LOOP RETURN NEXT r.\"QUERY PLAN\"; END LOOP; \
         END $$",
    )
    .execute(connection)
    .await
    .expect("explain helper should install");
    sql_query(format!(
        "SELECT nazo_test_explain FROM pg_temp.nazo_test_explain(\
         'EXPLAIN (ANALYZE, FORMAT TEXT) {}')",
        query.replace('\'', "''")
    ))
    .load::<PlanRow>(connection)
    .await
    .expect("explain should run")
    .into_iter()
    .map(|row| row.nazo_test_explain)
    .collect::<Vec<_>>()
    .join("\n")
}

fn assert_bounded_claim_plan(plan: &str) {
    // A quicksort over at most 256 materialized identities is bounded and
    // acceptable; what must never appear is a table scan of the audit
    // relations or a spill to disk (external merge / temp blocks).
    assert!(
        !plan.contains("Seq Scan on public.security_audit")
            && !plan.contains("Seq Scan on security_audit")
            && !plan.contains("external merge")
            && !plan.contains("Temp Read Blocks")
            && !plan.contains("temp Written Blocks")
            && !plan.contains("Temp File"),
        "claim plan must stay index-bounded without scans or spills:\n{plan}"
    );
    assert!(
        plan.contains("Index Scan") || plan.contains("Index Only Scan"),
        "claim plan must drive from the ordering index:\n{plan}"
    );
}

const CHAINED_CLAIM_QUERY: &str = "\
    WITH chained AS MATERIALIZED (
        SELECT chain.event_id, chain.sequence, chain.previous_hash, chain.event_hash
        FROM public.security_audit_chain_entries AS chain
        WHERE chain.sequence > 0
        ORDER BY chain.sequence
        LIMIT 256
    )
    SELECT event.event_id, chained.sequence, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           chained.previous_hash, chained.event_hash
    FROM chained
    JOIN public.security_audit_event_outbox AS outbox
        ON outbox.event_id = chained.event_id
    JOIN public.security_audit_events AS event
        ON event.event_id = chained.event_id
    ORDER BY chained.sequence";

const PENDING_CLAIM_QUERY: &str = "\
    WITH pending AS MATERIALIZED (
        SELECT outbox.event_id, outbox.occurred_at
        FROM public.security_audit_event_outbox AS outbox
        ORDER BY outbox.occurred_at, outbox.event_id
        LIMIT 256
    )
    SELECT event.event_id, NULL::BIGINT, event.event_type::TEXT,
           event.event_category::TEXT, event.payload::TEXT, event.occurred_at,
           NULL::BYTEA, NULL::BYTEA
    FROM pending
    JOIN public.security_audit_events AS event
        ON event.event_id = pending.event_id
    ORDER BY pending.occurred_at, pending.event_id";

const CLAIM_ROWS_QUERY: &str =
    "SELECT count(*) AS value FROM public.nazo_claim_security_audit_pending(256)";

#[derive(QueryableByName)]
struct BigCount {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    value: i64,
}

#[tokio::test]
async fn audit_claim_is_bounded_without_planner_statistics() {
    let _claim_guard = AUDIT_LEDGER_CLAIM_TEST_LOCK.lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    run_pending_migrations(&database_url)
        .await
        .expect("audit ledger migration should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("fixture connection should establish");
    sql_query("SET nazo.audit_reclaim = 'on'")
        .execute(&mut connection)
        .await
        .expect("fixture cleanup must be permitted");
    for pending_rows in [0_i64, 10_000, 1_000_000, 15_000_000] {
        for cleanup in [
            "DELETE FROM public.security_audit_event_outbox",
            "DELETE FROM public.security_audit_chain_entries",
            "DELETE FROM public.security_audit_events",
        ] {
            sql_query(cleanup)
                .execute(&mut connection)
                .await
                .expect("fixture cleanup should delete prior rows");
        }
        if pending_rows > 0 {
            let started = std::time::Instant::now();
            sql_query(format!(
                "INSERT INTO public.security_audit_events \
                     (event_id, event_type, event_category, payload, occurred_at) \
                 SELECT gen_random_uuid(), 'token_issued', 'token_lifecycle', \
                        jsonb_build_object('fixture', 'cold_claim', 'g', g), \
                        '2026-01-01'::timestamptz + (g || ' microseconds')::interval \
                 FROM generate_series(1, {pending_rows}) AS g"
            ))
            .execute(&mut connection)
            .await
            .expect("fixture events should insert");
            sql_query(
                "INSERT INTO public.security_audit_event_outbox (event_id, occurred_at) \
                 SELECT event_id, occurred_at FROM public.security_audit_events \
                 WHERE payload->>'fixture' = 'cold_claim'",
            )
            .execute(&mut connection)
            .await
            .expect("fixture outbox rows should insert");
            eprintln!(
                "seeded {pending_rows} pending rows in {:?}",
                started.elapsed()
            );
        }
        // Planner statistics are deliberately absent or stale here: the claim
        // must stay bounded regardless of what the planner believes.
        for analyzed in [false, true] {
            if analyzed {
                sql_query("ANALYZE public.security_audit_event_outbox, public.security_audit_events, public.security_audit_chain_entries")
                    .execute(&mut connection)
                    .await
                    .expect("analyze should run");
            }
            // Standalone inner-query plans run under the same planner pinning
            // the function applies to itself, so they mirror the production
            // claim shape. The real function call below runs under default
            // GUCs and relies on its own SET clauses.
            sql_query("SET enable_seqscan = off")
                .execute(&mut connection)
                .await
                .expect("plan pinning should apply");
            sql_query("SET enable_bitmapscan = off")
                .execute(&mut connection)
                .await
                .expect("plan pinning should apply");
            let chained_plan = explain_plan(&mut connection, CHAINED_CLAIM_QUERY).await;
            assert_bounded_claim_plan(&chained_plan);
            let pending_plan = explain_plan(&mut connection, PENDING_CLAIM_QUERY).await;
            assert_bounded_claim_plan(&pending_plan);
            sql_query("RESET enable_seqscan")
                .execute(&mut connection)
                .await
                .expect("plan pinning should reset");
            sql_query("RESET enable_bitmapscan")
                .execute(&mut connection)
                .await
                .expect("plan pinning should reset");
            let started = std::time::Instant::now();
            let claimed = sql_query(CLAIM_ROWS_QUERY)
                .get_result::<BigCount>(&mut connection)
                .await
                .expect("claim should execute")
                .value;
            let elapsed = started.elapsed();
            assert!(claimed <= 256, "claim returned {claimed} rows");
            assert_eq!(
                claimed,
                pending_rows.min(256),
                "claim should return the bounded prefix"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(30),
                "claim at {pending_rows} pending rows (analyzed={analyzed}) took {elapsed:?}"
            );
            eprintln!(
                "pending={pending_rows} analyzed={analyzed} claimed={claimed} elapsed={elapsed:?}"
            );
        }
        if pending_rows == 10_000 {
            // A committed batch leaves chained prefix rows in the outbox. The
            // claim must return that prefix exclusively — never mixed with the
            // unchained arrivals behind it.
            let pool = create_pool(database_url.clone(), 2).expect("audit pool should create");
            let repository = AuditLedgerRepository::new(pool);
            let health = repository
                .anchor_health()
                .await
                .expect("anchor health should be readable");
            if health.head_sequence == 0 {
                SecurityAuditExporter::record_genesis(
                    &repository,
                    "test-deployment",
                    &health.head_hash,
                )
                .await
                .expect("genesis should record");
            }
            SecurityAuditExporter::observe_anchor(&repository, "test-deployment")
                .await
                .expect("exporter should observe the shared anchor");
            let batch = match repository
                .claim_batch("test-deployment", 256, 1024 * 1024, 60)
                .await
                .expect("pending fixture should be claimable")
            {
                SecurityAuditBatchClaim::Claimed(batch) => batch,
                other => panic!("expected a claimed batch, got {other:?}"),
            };
            #[derive(QueryableByName)]
            struct ChainedCount {
                #[diesel(sql_type = diesel::sql_types::BigInt)]
                value: i64,
            }
            let chained = sql_query(
                "SELECT count(*) AS value \
                 FROM public.nazo_claim_security_audit_pending(256) \
                 WHERE sequence IS NOT NULL",
            )
            .get_result::<ChainedCount>(&mut connection)
            .await
            .expect("claim should execute")
            .value;
            assert_eq!(
                chained,
                batch.event_count(),
                "a chained prefix must claim exclusively"
            );
            repository
                .ack_batch(batch_ack(&batch))
                .await
                .expect("fixture batch should ack");
        }
    }
    for cleanup in [
        "DELETE FROM public.security_audit_event_outbox",
        "DELETE FROM public.security_audit_chain_entries",
        "DELETE FROM public.security_audit_events",
    ] {
        sql_query(cleanup)
            .execute(&mut connection)
            .await
            .expect("fixture cleanup should delete prior rows");
    }
}
