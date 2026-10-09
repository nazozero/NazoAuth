//! Real PostgreSQL commit-boundary and physical-connection regression tests.
//! The configured audit fixture must be an isolated database with CREATEDB.
use std::time::{Duration, Instant};

use chrono::Utc;
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Integer, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use futures_util::TryStreamExt;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{SecurityAuditBatch, SecurityAuditBatchAck, SecurityAuditBatchClaim};
use nazo_postgres::{
    AuditLedgerRepository, DbPool, SecurityAuditEvent, create_pool, get_conn,
    run_pending_migrations,
};
use serde_json::json;
use uuid::Uuid;

#[derive(QueryableByName)]
struct Number {
    #[diesel(sql_type = Integer)]
    value: i32,
}
#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    value: i64,
}
#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type = Text)]
    value: String,
}

struct Fixture {
    admin: AsyncPgConnection,
    observer: AsyncPgConnection,
    name: String,
    url: String,
    pool: DbPool,
    repository: AuditLedgerRepository,
}
impl Fixture {
    async fn new() -> Option<Self> {
        let base = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok();
        if base.is_none() && std::env::var_os("CI").is_some() {
            panic!("isolated audit database is required");
        }
        let base = base?;
        let mut url = url::Url::parse(&base).unwrap();
        assert!(
            url.path().contains("audit_test"),
            "never run fault injection against an application database"
        );
        let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
        let name = format!("audit_commit_test_{}", Uuid::now_v7().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        url.set_path(&format!("/{name}"));
        url.query_pairs_mut().append_pair("application_name", &name);
        let url = url.to_string();
        run_pending_migrations(&url).await.unwrap();
        let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
        observer
            .batch_execute("SET application_name = 'audit-commit-observer'")
            .await
            .unwrap();
        observer.batch_execute(r#"
             CREATE TABLE revision_fault (mode text NOT NULL);
             INSERT INTO revision_fault VALUES ('off');
             CREATE FUNCTION revision_deferred_fault() RETURNS trigger LANGUAGE plpgsql AS $$
             DECLARE mode text;
             BEGIN
                 SELECT f.mode INTO mode FROM revision_fault f;
                 IF mode = 'raise' THEN
                     RAISE EXCEPTION 'revision late commit failure' USING ERRCODE = '23514';
                 ELSIF mode = 'gate' THEN
                     PERFORM pg_advisory_xact_lock(23020261008);
                 END IF;
                 RETURN NULL;
             END $$;
             CREATE CONSTRAINT TRIGGER revision_events_late AFTER INSERT ON security_audit_events
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION revision_deferred_fault();
             CREATE CONSTRAINT TRIGGER revision_state_late AFTER UPDATE ON security_audit_chain_state
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION revision_deferred_fault();
         "#).await.unwrap();
        let pool = create_pool(&url, 1).unwrap();
        let repository = AuditLedgerRepository::new(pool.clone());
        Some(Self {
            admin,
            observer,
            name,
            url,
            pool,
            repository,
        })
    }
    async fn mode(&mut self, mode: &str) {
        sql_query("UPDATE revision_fault SET mode = $1")
            .bind::<Text, _>(mode)
            .execute(&mut self.observer)
            .await
            .unwrap();
    }
    async fn pid(&self) -> i32 {
        let mut c = get_conn(&self.pool).await.unwrap();
        sql_query("SELECT pg_backend_pid() AS value")
            .get_result::<Number>(&mut c)
            .await
            .unwrap()
            .value
    }
    async fn snapshot(&mut self) -> String {
        sql_query("SELECT json_build_object('state',(SELECT row_to_json(s) FROM security_audit_chain_state s), 'events',(SELECT COALESCE(json_agg(row_to_json(e) ORDER BY event_id),'[]') FROM security_audit_events e), 'chain',(SELECT COALESCE(json_agg(row_to_json(c) ORDER BY sequence),'[]') FROM security_audit_chain_entries c))::text AS value").get_result::<Snapshot>(&mut self.observer).await.unwrap().value
    }
    async fn wait_pid(&mut self, pid: i32, waiting: bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let value = sql_query("SELECT COUNT(*)::bigint AS value FROM pg_stat_activity WHERE pid = $1 AND ($2 = 'gone' OR wait_event = 'advisory')")
                 .bind::<Integer,_>(pid).bind::<Text,_>(if waiting {"wait"} else {"gone"})
                 .get_result::<Count>(&mut self.observer).await.unwrap().value;
            if (waiting && value == 1) || (!waiting && value == 0) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "backend {pid} did not reach expected state waiting={waiting}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn close(mut self) {
        drop(self.repository);
        drop(self.pool);
        drop(self.observer);
        self.admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}
fn event() -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "mtls_trust_bundle_exported".into(),
        event_category: "trust_lifecycle".into(),
        payload: json!({"test":"commit-boundary"}),
        occurred_at: Utc::now(),
    }
}
fn ack(batch: &SecurityAuditBatch) -> SecurityAuditBatchAck {
    SecurityAuditBatchAck {
        generation: batch.generation,
        deployment_id: "test-deployment".into(),
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        event_count: batch.event_count(),
        last_hash: batch.last_hash.clone(),
        batch_digest: batch.digest.clone(),
    }
}
#[derive(Clone, Copy, Debug)]
enum Operation {
    Genesis,
    Observe,
    Singleton,
    Batch,
    Ack,
    Fail,
}
async fn invoke(
    repo: &AuditLedgerRepository,
    op: Operation,
    events: &[SecurityAuditEvent],
    batch: Option<&SecurityAuditBatch>,
) -> Result<(), RepositoryError> {
    match op {
        Operation::Genesis => {
            let hash = repo.anchor_health().await?.head_hash;
            repo.record_genesis("test-deployment", &hash).await
        }
        Operation::Observe => repo.observe_anchor("test-deployment").await,
        Operation::Singleton => repo.append(events[0].clone()).await,
        Operation::Batch => repo.append_batch(events).await,
        Operation::Ack => repo.ack_batch(ack(batch.unwrap())).await,
        Operation::Fail => {
            repo.fail_batch(batch.unwrap().generation, Utc::now(), "fixture", false)
                .await
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_data_row_is_not_a_commit_acknowledgement() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    f.mode("raise").await;
    let (client, connection) = tokio_postgres::connect(&f.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let e = event();
    let query = format!(
        "SELECT nazo_persist_security_audit_event('{}', '{}', '{}', '{{}}', now())",
        e.event_id, e.event_type, e.event_category
    );
    let rows = client
        .query_raw(&query, std::iter::empty::<&str>())
        .await
        .unwrap();
    tokio::pin!(rows);
    assert!(rows.try_next().await.unwrap().unwrap().get::<_, bool>(0));
    let error = rows.try_next().await.unwrap_err();
    assert_eq!(
        error.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    println!(
        "first DataRow=true, next result=23514 revision late commit failure; no durable event"
    );
    let count = sql_query("SELECT COUNT(*)::bigint AS value FROM security_audit_events")
        .get_result::<Count>(&mut f.observer)
        .await
        .unwrap()
        .value;
    assert_eq!(count, 0);
    drop(client);
    driver.abort();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_audit_mutation_rejects_late_commit_failure_cancel_and_disconnect() {
    for op in [
        Operation::Genesis,
        Operation::Observe,
        Operation::Singleton,
        Operation::Batch,
        Operation::Ack,
        Operation::Fail,
    ] {
        for fault in ["raise", "cancel", "disconnect"] {
            let Some(mut f) = Fixture::new().await else {
                return;
            };
            if !matches!(op, Operation::Genesis) {
                let hash = f.repository.anchor_health().await.unwrap().head_hash;
                f.repository
                    .record_genesis("test-deployment", &hash)
                    .await
                    .unwrap();
            }
            let events = vec![event(), event(), event()];
            let batch = if matches!(op, Operation::Ack | Operation::Fail) {
                f.repository.append_batch(&events).await.unwrap();
                let SecurityAuditBatchClaim::Claimed(b) = f
                    .repository
                    .claim_batch("test-deployment", 64, 1024 * 1024, 60)
                    .await
                    .unwrap()
                else {
                    panic!("must claim")
                };
                Some(b)
            } else {
                None
            };
            let before = f.snapshot().await;
            let pid = f.pid().await;
            if fault == "raise" {
                f.mode("raise").await;
                let error = invoke(&f.repository, op, &events, batch.as_ref())
                    .await
                    .unwrap_err();
                assert!(
                    error.to_string().contains("revision late commit failure"),
                    "{op:?}: {error}"
                );
                println!("{op:?}: late commit error propagated: {error}; backend={pid}");
            } else {
                f.mode("gate").await;
                f.observer
                    .batch_execute("SELECT pg_advisory_lock(23020261008)")
                    .await
                    .unwrap();
                let repo = f.repository.clone();
                let events = events.clone();
                let batch = batch.clone();
                let task =
                    tokio::spawn(async move { invoke(&repo, op, &events, batch.as_ref()).await });
                f.wait_pid(pid, true).await;
                assert!(!task.is_finished(), "no success before commit");
                if fault == "cancel" {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                } else {
                    f.observer
                        .batch_execute(&format!("SELECT pg_terminate_backend({pid})"))
                        .await
                        .unwrap();
                    assert!(task.await.unwrap().is_err());
                }
                f.observer
                    .batch_execute("SELECT pg_advisory_unlock(23020261008)")
                    .await
                    .unwrap();
                println!("{op:?}: {fault} at deferred commit, no early success, backend={pid}");
            }
            f.wait_pid(pid, false).await;
            f.mode("off").await;
            let after = f.snapshot().await;
            if fault != "cancel" {
                assert_eq!(
                    after, before,
                    "{op:?}/{fault}: failed transaction changed durable state"
                );
            }
            // Dropping a client future is not PostgreSQL ROLLBACK. The transaction
            // may commit after the peer closes. Its outcome stays unknown to the
            // cancelled caller; recovery must use the existing identity/fence.
            let replacement = f.pid().await;
            assert_ne!(
                pid, replacement,
                "uncertain physical connection must not return to pool"
            );
            println!(
                "{op:?}/{fault}: backend gone, replacement={replacement}, durable_changed={}",
                after != before
            );
            if matches!(op, Operation::Ack)
                && !f.repository.anchor_health().await.unwrap().pending_exists
            {
                let health = f.repository.anchor_health().await.unwrap();
                assert_eq!(
                    health.last_exported_sequence,
                    Some(batch.as_ref().unwrap().last_sequence)
                );
                assert_eq!(
                    health.last_exported_hash,
                    Some(batch.as_ref().unwrap().last_hash.clone())
                );
                assert!(
                    f.repository
                        .ack_batch(ack(batch.as_ref().unwrap()))
                        .await
                        .is_err()
                );
                assert!(matches!(
                    f.repository
                        .claim_batch("test-deployment", 64, 1024 * 1024, 60)
                        .await
                        .unwrap(),
                    SecurityAuditBatchClaim::Empty
                ));
            } else {
                invoke(&f.repository, op, &events, batch.as_ref())
                    .await
                    .unwrap();
            }
            assert_eq!(
                replacement,
                f.pid().await,
                "successful physical connection is reusable"
            );
            if matches!(op, Operation::Singleton | Operation::Batch) {
                invoke(&f.repository, op, &events, batch.as_ref())
                    .await
                    .unwrap();
                let count =
                    sql_query("SELECT COUNT(*)::bigint AS value FROM security_audit_events")
                        .get_result::<Count>(&mut f.observer)
                        .await
                        .unwrap()
                        .value;
                assert_eq!(
                    count,
                    if matches!(op, Operation::Singleton) {
                        1
                    } else {
                        3
                    },
                    "whole batch persisted once"
                );
                let mut changed = events[0].clone();
                changed.payload = json!({"conflict":true});
                assert!(f.repository.append(changed).await.is_err());
            }
            if let Some(batch) = batch {
                if matches!(op, Operation::Fail) {
                    let SecurityAuditBatchClaim::Claimed(next) = f
                        .repository
                        .claim_batch("test-deployment", 64, 1024 * 1024, 60)
                        .await
                        .unwrap()
                    else {
                        panic!("must reclaim")
                    };
                    assert_eq!(next.digest, batch.digest);
                    assert!(next.generation > batch.generation);
                    assert!(f.repository.ack_batch(ack(&batch)).await.is_err());
                    f.repository.ack_batch(ack(&next)).await.unwrap();
                }
                assert!(!f.repository.anchor_health().await.unwrap().pending_exists);
            }
            f.close().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_ack_with_lost_ready_for_query_recovers_from_the_durable_checkpoint() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let hash = f.repository.anchor_health().await.unwrap().head_hash;
    f.repository
        .record_genesis("test-deployment", &hash)
        .await
        .unwrap();
    f.repository
        .append_batch(&[event(), event()])
        .await
        .unwrap();
    let SecurityAuditBatchClaim::Claimed(batch) = f
        .repository
        .claim_batch("test-deployment", 64, 1024 * 1024, 60)
        .await
        .unwrap()
    else {
        panic!("must claim")
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut proxy_url = url::Url::parse(&f.url).unwrap();
    let backend = format!(
        "{}:{}",
        proxy_url.host_str().unwrap(),
        proxy_url.port().unwrap_or(5432)
    );
    proxy_url.set_host(Some("127.0.0.1")).unwrap();
    proxy_url.set_port(Some(address.port())).unwrap();
    proxy_url
        .query_pairs_mut()
        .append_pair("sslmode", "disable");
    let armed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let proxy_armed = armed.clone();
    let proxy_dropped = dropped.clone();
    let proxy = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(&backend).await.unwrap();
            let armed = proxy_armed.clone();
            let dropped = proxy_dropped.clone();
            connections.spawn(async move {
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let upload = async {
                    let _ = tokio::io::copy(&mut cr, &mut sw).await;
                };
                let download = async {
                    let mut mutation_row_seen = false;
                    while let Ok(tag) = sr.read_u8().await {
                        let len = sr.read_u32().await.unwrap();
                        assert!((4..=1024 * 1024).contains(&len));
                        let mut body = vec![0; (len - 4) as usize];
                        sr.read_exact(&mut body).await.unwrap();
                        if tag == b'D'
                            && body == [0, 1, 0, 0, 0, 1, 1]
                            && armed.as_ref().load(Ordering::SeqCst)
                        {
                            mutation_row_seen = true;
                        }
                        if tag == b'Z' && mutation_row_seen && armed.swap(false, Ordering::SeqCst) {
                            assert_eq!(body, b"I", "only drop an idle ReadyForQuery after commit");
                            dropped.store(true, Ordering::SeqCst);
                            break;
                        }
                        if cw.write_u8(tag).await.is_err() {
                            break;
                        }
                        if cw.write_u32(len).await.is_err() {
                            break;
                        }
                        if cw.write_all(&body).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! {_=upload=>{},_=download=>{}}
            });
        }
    });
    let pool = create_pool(proxy_url.as_str(), 1).unwrap();
    let repository = AuditLedgerRepository::new(pool.clone());
    let pid = {
        let mut c = get_conn(&pool).await.unwrap();
        sql_query("SELECT pg_backend_pid() AS value")
            .get_result::<Number>(&mut c)
            .await
            .unwrap()
            .value
    };
    armed.store(true, Ordering::SeqCst);
    assert!(
        repository.ack_batch(ack(&batch)).await.is_err(),
        "lost commit acknowledgement must not return success"
    );
    assert!(dropped.as_ref().load(Ordering::SeqCst));
    f.wait_pid(pid, false).await;
    let health = repository.anchor_health().await.unwrap();
    assert_eq!(health.last_exported_sequence, Some(batch.last_sequence));
    assert_eq!(health.last_exported_hash, Some(batch.last_hash.clone()));
    assert!(!health.pending_exists);
    assert!(matches!(
        repository
            .claim_batch("test-deployment", 64, 1024 * 1024, 60)
            .await
            .unwrap(),
        SecurityAuditBatchClaim::Empty
    ));
    repository.append(event()).await.unwrap();
    let SecurityAuditBatchClaim::Claimed(next) = repository
        .claim_batch("test-deployment", 64, 1024 * 1024, 60)
        .await
        .unwrap()
    else {
        panic!("must claim next")
    };
    assert!(
        repository.ack_batch(ack(&batch)).await.is_err(),
        "old ACK cannot settle a new batch"
    );
    assert!(repository.anchor_health().await.unwrap().pending_exists);
    repository.ack_batch(ack(&next)).await.unwrap();
    println!(
        "proxy dropped committed ACK ReadyForQuery(I): caller Err, original backend {pid} disposed, checkpoint recovered, stale generation rejected, next batch ACK succeeded"
    );
    drop(repository);
    drop(pool);
    proxy.abort();
    let _ = proxy.await;
    f.close().await;
}

#[tokio::test]
async fn fresh_audit_conflict_rolls_back_the_callers_business_transaction() {
    let Some(mut f) = Fixture::new().await else {
        return;
    };
    let event = event();
    f.repository.append(event.clone()).await.unwrap();
    f.observer.batch_execute("CREATE TABLE revision_business(value integer); INSERT INTO revision_business VALUES (1)").await.unwrap();
    let result = f
        .observer
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            sql_query("UPDATE revision_business SET value=2")
                .execute(&mut *connection)
                .await?;
            nazo_postgres::append_fresh_security_audit_on_connection(connection, &event).await
        })
        .await;
    assert!(result.is_err());
    assert_eq!(
        sql_query("SELECT value FROM revision_business")
            .get_result::<Number>(&mut f.observer)
            .await
            .unwrap()
            .value,
        1
    );
    f.close().await;
}
