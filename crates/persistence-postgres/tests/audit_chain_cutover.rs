use chrono::Utc;
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Binary, Bool, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_postgres::{AuditLedgerRepository, SecurityAuditEvent, create_pool};
use serde_json::json;
use uuid::Uuid;

const ORIGINAL: &str =
    include_str!("../../../migrations/20260805000100_security_audit_ledger/up.sql");
const SHARED: &str =
    include_str!("../../../migrations/20260905000100_shared_audit_anchor_state/up.sql");
const CUTOVER: &str =
    include_str!("../../../migrations/20260909000100_exporter_owned_audit_chain/up.sql");

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(QueryableByName)]
struct Allowed {
    #[diesel(sql_type = Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct ChainEntry {
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Binary)]
    previous_hash: Vec<u8>,
    #[diesel(sql_type = Binary)]
    event_hash: Vec<u8>,
}

fn event() -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload: json!({"tenant_id": Uuid::now_v7()}),
        occurred_at: Utc::now(),
    }
}

#[tokio::test]
async fn audit_cutover_preserves_history_and_moves_chain_authority_to_exporter() {
    let Some(base) = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires NAZO_AUDIT_TEST_DATABASE_URL"
        );
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let database = format!("audit_cutover_{suffix}");
    let writer_role = format!("audit_writer_{suffix}");
    let exporter_role = format!("audit_exporter_{suffix}");
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&database);
    let mut owner = AsyncPgConnection::establish(url.as_str()).await.unwrap();
    owner.batch_execute(ORIGINAL).await.unwrap();
    owner.batch_execute(SHARED).await.unwrap();
    let historical = Uuid::now_v7();
    sql_query("SELECT * FROM public.nazo_append_security_audit_event($1, 'token_issued', 'token_lifecycle', '{}'::jsonb, '2026-01-01'::timestamptz, decode(repeat('00',32),'hex'), decode(repeat('11',32),'hex'))")
        .bind::<SqlUuid, _>(historical).execute(&mut owner).await.unwrap();
    owner.batch_execute(&format!(
        "CREATE ROLE {writer_role} LOGIN PASSWORD '{suffix}' NOSUPERUSER NOINHERIT; \
         CREATE ROLE {exporter_role} LOGIN PASSWORD '{suffix}' NOSUPERUSER NOINHERIT; \
         GRANT USAGE ON SCHEMA public TO {writer_role}, {exporter_role}; \
         GRANT EXECUTE ON FUNCTION public.nazo_security_audit_chain_head_for_update(), \
             public.nazo_append_security_audit_event(UUID,TEXT,TEXT,JSONB,TIMESTAMPTZ,BYTEA,BYTEA) TO {writer_role}; \
         GRANT EXECUTE ON FUNCTION public.nazo_security_audit_shared_privilege_preflight(BOOLEAN,BOOLEAN,BOOLEAN), \
             public.nazo_security_audit_shared_anchor_health() TO {writer_role}, {exporter_role}; \
         GRANT EXECUTE ON FUNCTION public.nazo_claim_security_audit_events(BIGINT,INTEGER), \
             public.nazo_ack_security_audit_event(UUID,INTEGER,TEXT), \
             public.nazo_observe_security_audit_anchor(TEXT), public.nazo_record_security_audit_genesis(TEXT,BYTEA), \
             public.nazo_reschedule_security_audit_event(UUID,INTEGER,TIMESTAMPTZ,TEXT) TO {exporter_role};"
    )).await.unwrap();
    owner
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            connection.batch_execute(CUTOVER).await
        })
        .await
        .unwrap();

    let preserved = sql_query("SELECT sequence, previous_hash, event_hash FROM public.security_audit_chain_entries WHERE event_id = $1")
        .bind::<SqlUuid, _>(historical).get_result::<ChainEntry>(&mut owner).await.unwrap();
    assert_eq!(preserved.sequence, 1);
    assert_eq!(preserved.previous_hash, vec![0; 32]);
    assert_eq!(preserved.event_hash, vec![0x11; 32]);
    let removed = sql_query("SELECT to_regprocedure('public.nazo_append_security_audit_event(uuid,text,text,jsonb,timestamptz,bytea,bytea)') IS NULL AND to_regprocedure('public.nazo_ack_security_audit_event(uuid,integer)') IS NULL AS value")
        .get_result::<Allowed>(&mut owner).await.unwrap();
    assert!(removed.value);

    url.set_username(&writer_role).unwrap();
    url.set_password(Some(&suffix)).unwrap();
    let writer_url = url.to_string();
    let writer = AuditLedgerRepository::new(create_pool(writer_url.clone(), 2).unwrap());
    writer.check_available().await.unwrap();
    assert!(writer.check_exporter_available().await.is_err());
    let mut writer_connection = AsyncPgConnection::establish(&writer_url).await.unwrap();
    assert!(
        sql_query("SELECT * FROM public.nazo_security_audit_chain_head_for_update()")
            .execute(&mut writer_connection)
            .await
            .is_err()
    );
    assert!(sql_query("INSERT INTO public.security_audit_chain_entries VALUES (gen_random_uuid(), 2, decode(repeat('11',32),'hex'), decode(repeat('22',32),'hex'))")
        .execute(&mut writer_connection).await.is_err());

    url.set_username(&exporter_role).unwrap();
    let exporter_url = url.to_string();
    let exporter = AuditLedgerRepository::new(create_pool(exporter_url.clone(), 2).unwrap());
    exporter.check_exporter_available().await.unwrap();
    assert!(exporter.check_available().await.is_err());
    assert!(exporter.append(event()).await.is_err());

    let mut exporter_connection = AsyncPgConnection::establish(&exporter_url).await.unwrap();
    exporter_connection
        .batch_execute("BEGIN; SELECT * FROM public.nazo_security_audit_chain_head_for_update()")
        .await
        .unwrap();
    let committed = event();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        writer.append(committed.clone()),
    )
    .await
    .expect("holding the exporter head must not block a writer transaction")
    .unwrap();
    exporter_connection.batch_execute("ROLLBACK").await.unwrap();

    // A writer transaction that has not committed is invisible to the exporter,
    // and does not serialize another writer's independent audit event.
    let rolled_back = event();
    writer_connection.batch_execute("BEGIN").await.unwrap();
    nazo_postgres::append_fresh_security_audit_on_connection(&mut writer_connection, &rolled_back)
        .await
        .unwrap();
    let independent = event();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        writer.append(independent.clone()),
    )
    .await
    .expect("unrelated writer transactions must not share a chain lock")
    .unwrap();
    let claimed = exporter.claim_due(256, 60).await.unwrap();
    assert_eq!(claimed.len(), 3);
    assert_eq!(claimed[0].event_id, historical);
    assert_eq!(claimed[1].event_id, committed.event_id);
    assert_eq!(claimed[2].event_id, independent.event_id);
    assert_eq!(claimed[1].previous_hash, claimed[0].event_hash);
    assert_eq!(claimed[2].previous_hash, claimed[1].event_hash);
    writer_connection.batch_execute("ROLLBACK").await.unwrap();
    let absent = sql_query(
        "SELECT count(*)::bigint AS value FROM public.security_audit_events WHERE event_id = $1",
    )
    .bind::<SqlUuid, _>(rolled_back.event_id)
    .get_result::<Count>(&mut owner)
    .await
    .unwrap();
    assert_eq!(absent.value, 0);

    for delivery in claimed {
        exporter
            .mark_exported(delivery.event_id, delivery.attempts, "cutover-test")
            .await
            .unwrap();
    }
    let head_before_failure = exporter.anchor_health().await.unwrap().head_sequence;
    let good = event();
    let rejected = event();
    writer.append(good.clone()).await.unwrap();
    writer.append(rejected.clone()).await.unwrap();
    owner.batch_execute(&format!(
        "CREATE FUNCTION public.reject_test_chain_entry() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.event_id = '{}'::uuid THEN RAISE EXCEPTION 'injected chain failure'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER reject_test_chain_entry BEFORE INSERT ON public.security_audit_chain_entries \
         FOR EACH ROW EXECUTE FUNCTION public.reject_test_chain_entry();", rejected.event_id
    )).await.unwrap();
    assert!(exporter.claim_due(256, 60).await.is_err());
    let failed_state = sql_query("SELECT count(*)::bigint AS value FROM public.security_audit_event_outbox WHERE event_id IN ($1, $2) AND attempts = 0 AND locked_at IS NULL AND exported_at IS NULL")
        .bind::<SqlUuid, _>(good.event_id).bind::<SqlUuid, _>(rejected.event_id)
        .get_result::<Count>(&mut owner).await.unwrap();
    assert_eq!(
        failed_state.value, 2,
        "a chaining failure must roll back every claim in its batch"
    );
    assert_eq!(
        exporter.anchor_health().await.unwrap().head_sequence,
        head_before_failure
    );
    owner.batch_execute("DROP TRIGGER reject_test_chain_entry ON public.security_audit_chain_entries; DROP FUNCTION public.reject_test_chain_entry()").await.unwrap();
    let (first, second) = tokio::join!(exporter.claim_due(256, 60), exporter.claim_due(256, 60));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(
        first.len() + second.len(),
        2,
        "concurrent exporters must not duplicate an active claim"
    );
    let deliveries = if first.is_empty() { second } else { first };
    assert_eq!(deliveries[0].sequence, head_before_failure + 1);
    assert_eq!(deliveries[1].sequence, head_before_failure + 2);
    for delivery in &deliveries {
        exporter
            .reschedule(delivery.event_id, delivery.attempts, Utc::now(), "retry")
            .await
            .unwrap();
    }
    let retried = exporter.claim_due(256, 60).await.unwrap();
    for (original, retry) in deliveries.iter().zip(&retried) {
        assert_eq!(original.event_id, retry.event_id);
        assert_eq!(original.sequence, retry.sequence);
        assert_eq!(original.event_hash, retry.event_hash);
        assert_eq!(original.previous_hash, retry.previous_hash);
        assert_eq!(retry.attempts, original.attempts + 1);
    }
    assert_eq!(
        exporter.anchor_health().await.unwrap().head_sequence,
        head_before_failure + 2
    );
    assert!(
        owner
            .batch_execute("UPDATE public.security_audit_chain_entries SET sequence = sequence")
            .await
            .is_err()
    );
    assert!(
        owner
            .batch_execute("TRUNCATE public.security_audit_chain_entries")
            .await
            .is_err()
    );
    assert!(
        owner
            .batch_execute("UPDATE public.security_audit_events SET payload = payload")
            .await
            .is_err()
    );

    for delivery in retried {
        exporter
            .mark_exported(delivery.event_id, delivery.attempts, "cutover-test")
            .await
            .unwrap();
    }
    cancellation_and_lost_result(&mut owner, &writer, &exporter_url).await;

    drop((
        writer,
        exporter,
        writer_connection,
        exporter_connection,
        owner,
    ));
    admin
        .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!(
            "DROP ROLE {writer_role}; DROP ROLE {exporter_role}"
        ))
        .await
        .unwrap();
}

async fn cancellation_and_lost_result(
    owner: &mut AsyncPgConnection,
    writer: &AuditLedgerRepository,
    exporter_url: &str,
) {
    let application = format!("cancel_claim_{}", Uuid::now_v7().simple());
    let mut url = url::Url::parse(exporter_url).unwrap();
    url.query_pairs_mut()
        .append_pair("application_name", &application);
    let pool = create_pool(url.as_str(), 1).unwrap();
    let exporter = std::sync::Arc::new(AuditLedgerRepository::new(pool.clone()));
    let before = exporter.anchor_health().await.unwrap().head_sequence;
    let pending = event();
    writer.append(pending.clone()).await.unwrap();
    owner
        .batch_execute(
            "SELECT pg_advisory_lock(909090909); \
         CREATE FUNCTION public.gate_test_chain() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock(909090909); RETURN NEW; END $$; \
         CREATE TRIGGER gate_test_chain BEFORE INSERT ON public.security_audit_chain_entries \
         FOR EACH ROW EXECUTE FUNCTION public.gate_test_chain();",
        )
        .await
        .unwrap();
    let task_repository = exporter.clone();
    let task = tokio::spawn(async move { task_repository.claim_due(256, 60).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting = sql_query("SELECT count(*)::bigint AS value FROM pg_stat_activity WHERE application_name = $1 AND wait_event = 'advisory'")
                .bind::<Text, _>(&application).get_result::<Count>(owner).await.unwrap();
            if waiting.value == 1 { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("claim must reach the SQL gate after taking the head and claiming rows");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    owner
        .batch_execute("SELECT pg_advisory_unlock(909090909)")
        .await
        .unwrap();
    // Keep both the original repository and pool alive, and do not acquire
    // from that pool: recycling a returned connection must not be the cleanup.
    owner.batch_execute("SET statement_timeout = '2s'; BEGIN; SELECT * FROM public.nazo_security_audit_chain_head_for_update(); COMMIT").await
        .expect("an independent connection must acquire the head after cancellation");
    let unchanged = sql_query("SELECT count(*)::bigint AS value FROM public.security_audit_event_outbox o WHERE event_id = $1 AND attempts = 0 AND locked_at IS NULL AND NOT EXISTS (SELECT 1 FROM public.security_audit_chain_entries c WHERE c.event_id = o.event_id)")
        .bind::<SqlUuid, _>(pending.event_id).get_result::<Count>(owner).await.unwrap();
    assert_eq!(
        unchanged.value, 1,
        "cancelled claim must leave raw event without claim or chain mutations"
    );
    owner.batch_execute("DROP TRIGGER gate_test_chain ON public.security_audit_chain_entries; DROP FUNCTION public.gate_test_chain(); SET statement_timeout = 0").await.unwrap();
    assert_eq!(
        exporter.anchor_health().await.unwrap().head_sequence,
        before
    );

    let committed = exporter.claim_due(256, 60).await.unwrap();
    assert_eq!(committed.len(), 1);
    let identity = (
        committed[0].event_id,
        committed[0].sequence,
        committed[0].previous_hash.clone(),
        committed[0].event_hash.clone(),
        committed[0].attempts,
    );
    drop(committed); // A successful COMMIT whose result never reaches the caller.
    sql_query("UPDATE public.security_audit_event_outbox SET locked_at = CURRENT_TIMESTAMP - INTERVAL '61 seconds' WHERE event_id = $1")
        .bind::<SqlUuid, _>(pending.event_id).execute(owner).await.unwrap();
    let reclaimed = exporter.claim_due(256, 60).await.unwrap();
    assert_eq!(reclaimed.len(), 1);
    let retry = &reclaimed[0];
    assert_eq!(
        (
            retry.event_id,
            retry.sequence,
            retry.previous_hash.clone(),
            retry.event_hash.clone(),
            retry.attempts
        ),
        (
            identity.0,
            identity.1,
            identity.2,
            identity.3,
            identity.4 + 1
        )
    );
    assert_eq!(
        exporter.anchor_health().await.unwrap().head_sequence,
        before + 1
    );
}
