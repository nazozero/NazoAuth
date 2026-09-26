//! Genuine upgrade-from-pre-schema verification for the pending-event-set
//! migration (20260927000100). Each case builds the real pre-upgrade schema
//! by replaying the audit lineage up to 20260925000100_audit_claim_bounded_scan
//! on a scratch database, seeds one pre-cutover state, runs the complete
//! migration in a single transaction like the Diesel runner does, and then
//! proves the delivered behavior on the migrated schema: event/order/
//! generation/digest preservation, chain head and anchor integrity, and
//! claim/fail/reclaim/ack retry semantics.
//!
//! A text-level guard check cannot substitute for these executions.

use chrono::{DateTime, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Binary, Bool, Nullable, Text, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_persistence::{
    SecurityAuditBatch, SecurityAuditBatchAck, SecurityAuditBatchClaim, SecurityAuditExporter,
};
use nazo_postgres::{AuditLedgerRepository, SecurityAuditEvent, create_pool};
use serde_json::json;
use uuid::Uuid;

const ORIGINAL: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/up.sql");
const SHARED: &str =
    include_str!("../../../migrations/20260905000100_shared_audit_anchor_state/up.sql");
const CUTOVER: &str =
    include_str!("../../../migrations/20260909000100_exporter_owned_audit_chain/up.sql");
const EXPORTED_RETENTION: &str =
    include_str!("../../../migrations/20260919000100_audit_outbox_exported_retention/up.sql");
const ACK_DELETE: &str =
    include_str!("../../../migrations/20260919000200_audit_outbox_ack_delete/up.sql");
const BATCH_DELIVERY: &str =
    include_str!("../../../migrations/20260920000100_audit_anchor_batch_delivery/up.sql");
const DELIVERY_RETENTION: &str =
    include_str!("../../../migrations/20260924000100_audit_delivery_scoped_retention/up.sql");
const BOUNDED_CLAIM: &str =
    include_str!("../../../migrations/20260925000100_audit_claim_bounded_scan/up.sql");
const PENDING_SET: &str =
    include_str!("../../../migrations/20260927000100_audit_pending_event_set/up.sql");

const PRE_UPGRADE: &[&str] = &[
    ORIGINAL,
    SHARED,
    CUTOVER,
    EXPORTED_RETENTION,
    ACK_DELETE,
    BATCH_DELIVERY,
    DELIVERY_RETENTION,
    BOUNDED_CLAIM,
];

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI audit upgrade tests require an isolated NAZO_AUDIT_TEST_DATABASE_URL");
    }
    url
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(QueryableByName)]
struct RegExists {
    #[diesel(sql_type = Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct EventOrderRow {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    occurred_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct ChainRow {
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Binary)]
    previous_hash: Vec<u8>,
    #[diesel(sql_type = Binary)]
    event_hash: Vec<u8>,
}

#[derive(QueryableByName)]
struct StateRow {
    #[diesel(sql_type = BigInt)]
    last_sequence: i64,
    #[diesel(sql_type = Binary)]
    last_hash: Vec<u8>,
    #[diesel(sql_type = Nullable<BigInt>)]
    anchor_sequence: Option<i64>,
    #[diesel(sql_type = Nullable<Binary>)]
    anchor_hash: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Text>)]
    anchor_deployment_id: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    batch_first_sequence: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    batch_last_sequence: Option<i64>,
    #[diesel(sql_type = Nullable<diesel::sql_types::Integer>)]
    batch_event_count: Option<i32>,
    #[diesel(sql_type = Nullable<Binary>)]
    batch_digest: Option<Vec<u8>>,
    #[diesel(sql_type = BigInt)]
    batch_generation: i64,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    batch_attempts: i32,
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    events: Vec<(Uuid, DateTime<Utc>)>,
    chain: Vec<(Uuid, i64, Vec<u8>, Vec<u8>)>,
    state: Vec<String>,
}

async fn count(connection: &mut AsyncPgConnection, sql: &str) -> i64 {
    sql_query(sql)
        .get_result::<Count>(connection)
        .await
        .expect("count query should run")
        .value
}

async fn reg_exists(connection: &mut AsyncPgConnection, reg: &str) -> bool {
    sql_query("SELECT to_regclass($1) IS NOT NULL AS value")
        .bind::<Text, _>(reg)
        .get_result::<RegExists>(connection)
        .await
        .expect("regclass probe should run")
        .value
}

async fn events_in_order(connection: &mut AsyncPgConnection) -> Vec<(Uuid, DateTime<Utc>)> {
    sql_query(
        "SELECT event_id, occurred_at FROM public.security_audit_events \
         ORDER BY occurred_at, event_id",
    )
    .load::<EventOrderRow>(connection)
    .await
    .expect("event ordering should be readable")
    .into_iter()
    .map(|row| (row.event_id, row.occurred_at))
    .collect()
}

async fn chain_rows(connection: &mut AsyncPgConnection) -> Vec<(Uuid, i64, Vec<u8>, Vec<u8>)> {
    sql_query(
        "SELECT event_id, sequence, previous_hash, event_hash \
         FROM public.security_audit_chain_entries ORDER BY sequence",
    )
    .load::<ChainRow>(connection)
    .await
    .expect("chain entries should be readable")
    .into_iter()
    .map(|row| {
        (
            row.event_id,
            row.sequence,
            row.previous_hash,
            row.event_hash,
        )
    })
    .collect()
}

async fn state_snapshot(connection: &mut AsyncPgConnection) -> Vec<String> {
    let row = sql_query(
        "SELECT last_sequence, last_hash, anchor_sequence, anchor_hash, \
                anchor_deployment_id, batch_first_sequence, batch_last_sequence, \
                batch_event_count, batch_digest, batch_generation, batch_attempts \
         FROM public.security_audit_chain_state WHERE singleton",
    )
    .get_result::<StateRow>(connection)
    .await
    .expect("chain state should be readable");
    vec![
        row.last_sequence.to_string(),
        hex(&row.last_hash),
        format!("{:?}", row.anchor_sequence),
        row.anchor_hash.as_deref().map(hex).unwrap_or_default(),
        row.anchor_deployment_id.unwrap_or_default(),
        format!("{:?}", row.batch_first_sequence),
        format!("{:?}", row.batch_last_sequence),
        format!("{:?}", row.batch_event_count),
        row.batch_digest.as_deref().map(hex).unwrap_or_default(),
        row.batch_generation.to_string(),
        row.batch_attempts.to_string(),
    ]
}

async fn snapshot(connection: &mut AsyncPgConnection) -> Snapshot {
    Snapshot {
        events: events_in_order(connection).await,
        chain: chain_rows(connection).await,
        state: state_snapshot(connection).await,
    }
}

async fn scratch_database(label: &str) -> (AsyncPgConnection, String) {
    let base = database_url().expect("caller checked database_url");
    let suffix = Uuid::now_v7().simple().to_string();
    let database = format!("audit_pending_{label}_{suffix}");
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&database);
    let mut owner = AsyncPgConnection::establish(url.as_str()).await.unwrap();
    for migration in PRE_UPGRADE {
        owner
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                connection.batch_execute(migration).await
            })
            .await
            .expect("pre-upgrade migration should apply");
    }
    (owner, url.to_string())
}

/// Persist real pending rows through the pre-upgrade persist function: each
/// call writes one event row and its outbox mirror, exactly like production.
async fn persist_pending(
    connection: &mut AsyncPgConnection,
    tag: &str,
    start: i64,
    n: i64,
) -> Vec<Uuid> {
    let mut ids = Vec::new();
    for i in start..start + n {
        let id = Uuid::now_v7();
        sql_query(
            "SELECT public.nazo_persist_security_audit_event(\
                    $1, 'token_issued', 'token_lifecycle', $2, $3) AS value",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<diesel::sql_types::Jsonb, _>(json!({"seed": tag, "i": i}))
        .bind::<Timestamptz, _>(
            DateTime::<Utc>::from_timestamp(1_750_000_000, 0).unwrap()
                + chrono::Duration::microseconds(i),
        )
        .get_result::<RegExists>(connection)
        .await
        .expect("pending seed should persist");
        ids.push(id);
    }
    ids
}

async fn anchor_observed(repository: &AuditLedgerRepository) {
    let health = repository
        .anchor_health()
        .await
        .expect("anchor health should be readable");
    if health.head_sequence == 0 {
        SecurityAuditExporter::record_genesis(repository, "upgrade-test", &health.head_hash)
            .await
            .expect("genesis should record");
    }
    SecurityAuditExporter::observe_anchor(repository, "upgrade-test")
        .await
        .expect("exporter should observe the shared anchor");
}

fn ack_of(batch: &SecurityAuditBatch) -> SecurityAuditBatchAck {
    SecurityAuditBatchAck {
        generation: batch.generation,
        deployment_id: "upgrade-test".to_owned(),
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        event_count: batch.event_count(),
        last_hash: batch.last_hash.clone(),
        batch_digest: batch.digest.clone(),
    }
}

async fn claim(repository: &AuditLedgerRepository) -> SecurityAuditBatchClaim {
    repository
        .claim_batch("upgrade-test", 256, 1024 * 1024, 60)
        .await
        .expect("claim should execute")
}

async fn claimed_batch(repository: &AuditLedgerRepository) -> SecurityAuditBatch {
    match claim(repository).await {
        SecurityAuditBatchClaim::Claimed(batch) => batch,
        other => panic!("expected a claimed batch, got {other:?}"),
    }
}

async fn migrate(connection: &mut AsyncPgConnection) -> Result<(), diesel::result::Error> {
    connection
        .transaction::<_, diesel::result::Error, _>(async |txn| {
            txn.batch_execute(PENDING_SET).await
        })
        .await
}

/// Assertions every migrated state must satisfy: the outbox is gone, the
/// pending-order index exists, and the event rows, chain entries, chain head,
/// anchor, generation and digest survive exactly as snapshotted.
async fn assert_migrated_shape(
    owner: &mut AsyncPgConnection,
    pre: &Snapshot,
    expected_pending: usize,
) {
    assert!(
        !reg_exists(owner, "public.security_audit_event_outbox").await,
        "outbox must be dropped"
    );
    assert!(
        reg_exists(owner, "public.idx_security_audit_events_pending_order").await,
        "pending order index must exist"
    );
    let post = snapshot(owner).await;
    assert_eq!(
        post.events, pre.events,
        "event rows must survive the migration unchanged"
    );
    assert_eq!(
        post.chain, pre.chain,
        "chain entries must survive the migration unchanged"
    );
    assert_eq!(
        post.state, pre.state,
        "chain state (head, anchor, generation, digest) must survive unchanged"
    );
    assert_eq!(
        post.events.len(),
        expected_pending,
        "pending event set size mismatch"
    );
}

async fn drain(repository: &AuditLedgerRepository) -> Vec<SecurityAuditBatch> {
    let mut batches = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        match claim(repository).await {
            SecurityAuditBatchClaim::Claimed(batch) => {
                repository
                    .ack_batch(ack_of(&batch))
                    .await
                    .expect("claimed batch should ack");
                batches.push(batch);
            }
            SecurityAuditBatchClaim::Empty => break,
            SecurityAuditBatchClaim::Busy => {
                assert!(std::time::Instant::now() < deadline, "drain stuck on Busy");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            SecurityAuditBatchClaim::Blocked { reason } => {
                panic!("unexpected blocked batch: {reason}")
            }
        }
    }
    batches
}

#[tokio::test]
async fn pending_set_upgrade_from_empty_state() {
    if database_url().is_none() {
        return;
    }
    let (mut owner, url) = scratch_database("empty").await;
    let pre = snapshot(&mut owner).await;
    assert!(pre.events.is_empty() && pre.chain.is_empty());
    migrate(&mut owner)
        .await
        .expect("empty upgrade should apply");
    assert_migrated_shape(&mut owner, &pre, 0).await;

    // The migrated schema must run the full delivery cycle.
    let repository = AuditLedgerRepository::new(create_pool(url, 2).unwrap());
    anchor_observed(&repository).await;
    repository
        .append_batch(
            &(0..8)
                .map(|i| SecurityAuditEvent {
                    event_id: Uuid::now_v7(),
                    event_type: "token_issued".to_owned(),
                    event_category: "token_lifecycle".to_owned(),
                    payload: json!({"post_upgrade": i}),
                    occurred_at: Utc::now(),
                })
                .collect::<Vec<_>>(),
        )
        .await
        .expect("post-upgrade appends should persist");
    let batches = drain(&repository).await;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].event_count(), 8);
    assert_eq!(
        count(
            &mut owner,
            "SELECT count(*) AS value FROM public.security_audit_events"
        )
        .await,
        0,
        "acked events must be deleted on the migrated schema"
    );
}

#[tokio::test]
async fn pending_set_upgrade_from_unchained_backlog() {
    if database_url().is_none() {
        return;
    }
    let (mut owner, url) = scratch_database("unchained").await;
    let ids = persist_pending(&mut owner, "unchained", 0, 600).await;
    let pre = snapshot(&mut owner).await;
    assert_eq!(pre.events.len(), 600);
    assert!(pre.chain.is_empty());
    assert_eq!(
        count(
            &mut owner,
            "SELECT count(*) AS value FROM public.security_audit_event_outbox"
        )
        .await,
        600,
        "pre-upgrade outbox must mirror every pending event"
    );
    migrate(&mut owner)
        .await
        .expect("unchained backlog upgrade should apply");
    assert_migrated_shape(&mut owner, &pre, 600).await;

    // Ordered pending claims on the migrated schema must deliver the exact
    // (occurred_at, event_id) prefix order the outbox index encoded.
    let repository = AuditLedgerRepository::new(create_pool(url, 2).unwrap());
    anchor_observed(&repository).await;
    let mut delivered = Vec::new();
    for batch in drain(&repository).await {
        assert_eq!(
            batch.first_sequence + batch.event_count() - 1,
            batch.last_sequence,
            "batch sequence range must be contiguous"
        );
        delivered.extend(batch.deliveries.iter().map(|d| d.event_id));
    }
    assert_eq!(
        delivered, ids,
        "delivery order must equal the pre-upgrade pending order"
    );
    let post = snapshot(&mut owner).await;
    assert!(post.events.is_empty(), "acked events must be deleted");
    assert_eq!(post.state[0], "600", "head sequence after drain");
    assert_eq!(post.state[2], "Some(600)", "anchor after drain");
}

#[tokio::test]
async fn pending_set_upgrade_from_inflight_batch() {
    if database_url().is_none() {
        return;
    }
    let (mut owner, url) = scratch_database("inflight").await;
    persist_pending(&mut owner, "inflight", 0, 512).await;
    let seed_repository = AuditLedgerRepository::new(create_pool(url.clone(), 2).unwrap());
    anchor_observed(&seed_repository).await;
    // The real claim protocol on the pre-upgrade schema: chain entries are
    // written and the batch lease committed in chain_state (bounded at 256).
    let batch = claimed_batch(&seed_repository).await;
    assert_eq!(batch.event_count(), 256);
    let pre = snapshot(&mut owner).await;
    assert_eq!(pre.state[5], "Some(1)", "batch must be in flight");
    migrate(&mut owner)
        .await
        .expect("in-flight upgrade should apply");
    assert_migrated_shape(&mut owner, &pre, 512).await;

    // The in-flight lease is still fenced after the migration: a fail
    // releases it, the identical range re-claims with a bumped generation,
    // and the ack retires exactly those rows.
    let repository = AuditLedgerRepository::new(create_pool(url.clone(), 2).unwrap());
    repository
        .fail_batch(batch.generation, Utc::now(), "upgrade-test", false)
        .await
        .expect("fail should release the lease");
    let reclaimed = claimed_batch(&repository).await;
    assert_eq!(reclaimed.first_sequence, batch.first_sequence);
    assert_eq!(reclaimed.last_sequence, batch.last_sequence);
    assert_eq!(reclaimed.digest, batch.digest);
    assert!(reclaimed.generation > batch.generation);
    repository
        .ack_batch(ack_of(&reclaimed))
        .await
        .expect("migrated in-flight batch should ack");
    assert_eq!(
        count(
            &mut owner,
            "SELECT count(*) AS value FROM public.security_audit_events"
        )
        .await,
        256,
        "the unchained tail must still be pending after the in-flight ack"
    );
    // The remaining pending events claim and ack normally on the new schema.
    let rest = drain(&repository).await;
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].first_sequence, 257);
    assert_eq!(rest[0].event_count(), 256);
    let post = snapshot(&mut owner).await;
    assert!(post.events.is_empty() && post.chain.is_empty());
    assert_eq!(post.state[0], "512", "head after full drain");
    assert_eq!(post.state[2], "Some(512)", "anchor after full drain");
}

#[tokio::test]
async fn pending_set_upgrade_from_mixed_backlog() {
    if database_url().is_none() {
        return;
    }
    let (mut owner, url) = scratch_database("mixed").await;
    let seed_repository = AuditLedgerRepository::new(create_pool(url.clone(), 2).unwrap());
    anchor_observed(&seed_repository).await;
    // Delivered-and-acked history: chain head advances, rows retire.
    persist_pending(&mut owner, "acked", 0, 300).await;
    drain(&seed_repository).await;
    // One committed in-flight batch behind a fresh unchained tail.
    persist_pending(&mut owner, "inflight", 300, 200).await;
    let inflight = claimed_batch(&seed_repository).await;
    assert_eq!(inflight.event_count(), 200);
    persist_pending(&mut owner, "pending", 500, 150).await;
    let pre = snapshot(&mut owner).await;
    assert_eq!(pre.events.len(), 350);
    assert_eq!(pre.chain.len(), 200);
    assert_eq!(pre.state[2], "Some(300)", "anchor after first delivery");
    migrate(&mut owner)
        .await
        .expect("mixed backlog upgrade should apply");
    assert_migrated_shape(&mut owner, &pre, 350).await;

    let repository = AuditLedgerRepository::new(create_pool(url, 2).unwrap());
    repository
        .fail_batch(inflight.generation, Utc::now(), "upgrade-test", false)
        .await
        .expect("fail should release the migrated in-flight lease");
    let delivered = drain(&repository).await;
    assert_eq!(delivered.len(), 2, "in-flight batch then pending tail");
    assert_eq!(delivered[0].first_sequence, 301);
    assert_eq!(delivered[0].digest, inflight.digest);
    assert_eq!(delivered[1].first_sequence, 501);
    assert_eq!(delivered[1].event_count(), 150);
    let post = snapshot(&mut owner).await;
    assert!(post.events.is_empty() && post.chain.is_empty());
    assert_eq!(post.state[0], "650", "head after full drain");
    assert_eq!(post.state[2], "Some(650)", "anchor after full drain");
}

#[tokio::test]
async fn pending_set_upgrade_rolls_back_on_divergence() {
    if database_url().is_none() {
        return;
    }
    // Divergence shape 1: an event row without its outbox mirror.
    let (mut owner, _url) = scratch_database("diverged_event").await;
    persist_pending(&mut owner, "divergent", 0, 32).await;
    sql_query(
        "INSERT INTO public.security_audit_events \
             (event_id, event_type, event_category, payload, occurred_at) \
         VALUES (gen_random_uuid(), 'token_issued', 'token_lifecycle', \
                 '{\"divergent\": true}'::jsonb, '2026-02-02'::timestamptz)",
    )
    .execute(&mut owner)
    .await
    .expect("orphan event fixture should insert");
    let before = snapshot(&mut owner).await;
    let result = migrate(&mut owner).await;
    assert!(result.is_err(), "divergent state must abort the migration");
    assert!(
        reg_exists(&mut owner, "public.security_audit_event_outbox").await,
        "rolled-back migration must leave the outbox in place"
    );
    assert!(
        !reg_exists(&mut owner, "public.idx_security_audit_events_pending_order").await,
        "rolled-back migration must not leave the pending index"
    );
    let after = snapshot(&mut owner).await;
    assert_eq!(after.events, before.events);
    assert_eq!(after.chain, before.chain);
    assert_eq!(after.state, before.state);

    // Divergence shape 2: an outbox row whose occurred_at drifted from its
    // event — the mirror-consistency guard must refuse the cutover.
    let (mut owner, _url) = scratch_database("diverged_clock").await;
    persist_pending(&mut owner, "drift", 0, 32).await;
    sql_query(
        "UPDATE public.security_audit_event_outbox \
         SET occurred_at = occurred_at + interval '1 second' \
         WHERE event_id = (SELECT event_id FROM public.security_audit_event_outbox \
                           ORDER BY occurred_at, event_id LIMIT 1)",
    )
    .execute(&mut owner)
    .await
    .expect("occurred_at drift fixture should apply");
    let before = snapshot(&mut owner).await;
    let result = migrate(&mut owner).await;
    assert!(result.is_err(), "drifted mirror must abort the migration");
    assert!(
        reg_exists(&mut owner, "public.security_audit_event_outbox").await,
        "rolled-back migration must leave the outbox in place"
    );
    let after = snapshot(&mut owner).await;
    assert_eq!(after.events, before.events);
    assert_eq!(after.state, before.state);
}
