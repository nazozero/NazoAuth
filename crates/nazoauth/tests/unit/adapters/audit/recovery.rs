use super::*;
use crate::adapters::audit_anchor::{AuditAnchorPreflightConfig, config::AuditAnchorMode};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::SecurityAuditAnchorHealth;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::Notify;

// The fixture projects recorded pending events; the production preflight is
// the only implementation that decides whether the snapshot permits work.
struct RecoveryLedger {
    available: AtomicBool,
    health_calls: AtomicU64,
    delay_health_once: AtomicBool,
    fail_slow_once: AtomicBool,
    attempts: Mutex<Vec<Vec<SecurityAuditEvent>>>,
    persisted: Mutex<Vec<SecurityAuditEvent>>,
    commit_gate: Mutex<Option<oneshot::Receiver<()>>>,
    append_started: Notify,
}

impl RecoveryLedger {
    fn new() -> Self {
        Self {
            available: AtomicBool::new(true),
            health_calls: AtomicU64::new(0),
            delay_health_once: AtomicBool::new(false),
            fail_slow_once: AtomicBool::new(false),
            attempts: Mutex::new(Vec::new()),
            persisted: Mutex::new(Vec::new()),
            commit_gate: Mutex::new(None),
            append_started: Notify::new(),
        }
    }
}

impl SecurityAuditLedger for RecoveryLedger {
    fn check_available(
        &self,
        _require_least_privilege: bool,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async { Ok(()) })
    }

    fn anchor_health(
        &self,
    ) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
        Box::pin(async move {
            self.health_calls.fetch_add(1, Ordering::SeqCst);
            if self.delay_health_once.swap(false, Ordering::SeqCst) {
                // Tokio's paused clock does not advance Utc. These two ageing
                // regressions deliberately use a short real wall-clock wait.
                tokio::time::sleep(Duration::from_millis(2100)).await;
            }
            if !self.available.load(Ordering::SeqCst) {
                return Err(RepositoryError::Unavailable);
            }
            let pending = self.persisted.lock().unwrap();
            Ok(SecurityAuditAnchorHealth {
                head_sequence: 0,
                head_hash: vec![0; 32],
                pending_exists: !pending.is_empty(),
                pending_estimate: pending.len().try_into().unwrap(),
                pending_orphan_exists: false,
                oldest_pending_occurred_at: pending.iter().map(|e| e.occurred_at).min(),
                last_exported_sequence: Some(0),
                last_exported_hash: Some(vec![0; 32]),
                last_exported_occurred_at: Some(Utc::now()),
                last_exported_at: Some(Utc::now()),
                deployment_id: Some("recovery-test".to_owned()),
                observed_at: Some(Utc::now()),
                batch: None,
            })
        })
    }

    fn append(&self, event: SecurityAuditEvent) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move { self.append_batch(std::slice::from_ref(&event)).await })
    }

    fn append_batch<'a>(
        &'a self,
        events: &'a [SecurityAuditEvent],
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push(events.to_vec());
            self.append_started.notify_one();
            let gate = { self.commit_gate.lock().unwrap().take() };
            if let Some(gate) = gate {
                gate.await.unwrap();
            }
            if self.fail_slow_once.swap(false, Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2100)).await;
                return Err(RepositoryError::Unavailable);
            }
            self.persisted.lock().unwrap().extend_from_slice(events);
            Ok(())
        })
    }
}

fn preflight(mode: AuditAnchorMode, max_lag: u64) -> AuditAnchorPreflight {
    AuditAnchorPreflight::new(AuditAnchorPreflightConfig {
        mode,
        deployment_id: "recovery-test".to_owned(),
        freshness: Duration::from_secs(30),
        max_lag: Duration::from_secs(max_lag),
    })
    .unwrap()
}

fn event_at(name: &str, occurred_at: DateTime<Utc>) -> QueuedAuditEvent {
    let mut event = prepare_event(name, serde_json::Map::new()).unwrap();
    event.occurred_at = occurred_at;
    event
}

#[test]
fn telemetry_expiry_uses_required_lag_boundary_and_preserves_unknown_clock_state() {
    let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let gate = preflight(AuditAnchorMode::Required, 10);
    assert!(!gate.telemetry_event_expired(now, now));
    assert!(!gate.telemetry_event_expired(now - chrono::Duration::seconds(10), now));
    assert!(gate.telemetry_event_expired(now - chrono::Duration::seconds(11), now));
    assert!(!gate.telemetry_event_expired(now + chrono::Duration::seconds(1), now));
    for mode in [AuditAnchorMode::Optional, AuditAnchorMode::Disabled] {
        assert!(
            !preflight(mode, 10)
                .telemetry_event_expired(now - chrono::Duration::hours(1), now)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn old_telemetry_backlog_cannot_re_poison_required_admission_after_recovery() {
    let ledger = Arc::new(RecoveryLedger::new());
    let gate = preflight(AuditAnchorMode::Required, 10);
    let (sender, receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
    for _ in 0..130 {
        sender
            .try_send(
                event_at("login_success", Utc::now() - chrono::Duration::hours(1)).into(),
            )
            .unwrap();
    }
    let fresh = event_at("login_success", Utc::now());
    let fresh_id = fresh.event_id;
    let original_payload = fresh.payload.clone();
    let original_time = fresh.occurred_at;
    sender.try_send(fresh.into()).unwrap();
    drop(sender);
    tokio::time::timeout(
        Duration::from_secs(5),
        run_audit_persist_worker(receiver, ledger.clone(), Some(gate.clone())),
    )
    .await
    .expect("old in-memory telemetry must not recreate an unhealthy durable backlog");
    let health = ledger.anchor_health().await.unwrap();
    gate.ensure_fresh(&health)
        .expect("only the fresh event may influence Required admission");
    let persisted = ledger.persisted.lock().unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].event_id, fresh_id);
    assert_eq!(persisted[0].payload, original_payload);
    assert_eq!(persisted[0].occurred_at, original_time);
    assert_eq!(ledger.attempts.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn all_expired_unattempted_telemetry_can_leave_memory_without_a_healthy_database() {
    let ledger = Arc::new(RecoveryLedger::new());
    ledger.available.store(false, Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel(2);
    sender
        .try_send(event_at("login_success", Utc::now() - chrono::Duration::hours(1)).into())
        .unwrap();
    drop(sender);
    tokio::time::timeout(
        Duration::from_secs(1),
        run_audit_persist_worker(
            receiver,
            ledger.clone(),
            Some(preflight(AuditAnchorMode::Required, 10)),
        ),
    )
    .await
    .expect("expired unattempted telemetry does not require a database write to discard");
    assert!(ledger.attempts.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn required_class_and_unknown_names_are_never_expired_on_the_telemetry_channel() {
    let ledger = Arc::new(RecoveryLedger::new());
    let (sender, receiver) = mpsc::channel(3);
    let when = Utc::now() - chrono::Duration::hours(1);
    let required = event_at("mtls_trust_bundle_exported", when);
    let mut unknown = event_at("login_success", when);
    unknown.event_type = "future_unknown_evidence".to_owned();
    let required_id = required.event_id;
    let unknown_id = unknown.event_id;
    sender.try_send(required.into()).unwrap();
    sender.try_send(unknown.into()).unwrap();
    sender
        .try_send(event_at("login_success", when).into())
        .unwrap();
    drop(sender);
    run_audit_persist_worker(
        receiver,
        ledger.clone(),
        Some(preflight(AuditAnchorMode::Required, 10)),
    )
    .await;
    let persisted = ledger.persisted.lock().unwrap();
    assert_eq!(
        persisted.iter().map(|e| e.event_id).collect::<Vec<_>>(),
        vec![required_id, unknown_id]
    );
}

#[tokio::test]
async fn a_required_waiter_cannot_be_expired_even_for_a_telemetry_event_name() {
    let ledger = Arc::new(RecoveryLedger::new());
    let (release, commit) = oneshot::channel();
    *ledger.commit_gate.lock().unwrap() = Some(commit);
    let (sender, receiver) = mpsc::channel(1);
    let (completion, mut persisted) = oneshot::channel();
    let event = event_at("login_success", Utc::now() - chrono::Duration::hours(1));
    let id = event.event_id;
    sender
        .try_send(AuditPersistRequest {
            event,
            completion: Some(completion),
        })
        .unwrap();
    drop(sender);
    let worker = tokio::spawn(run_audit_persist_worker(
        receiver,
        ledger.clone(),
        Some(preflight(AuditAnchorMode::Required, 10)),
    ));
    tokio::time::timeout(Duration::from_secs(5), ledger.append_started.notified())
        .await
        .unwrap();
    assert!(matches!(
        persisted.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(ledger.persisted.lock().unwrap().is_empty());
    release.send(()).unwrap();
    assert_eq!(persisted.await.unwrap().unwrap().event_id, id);
    worker.await.unwrap();
}

#[tokio::test]
async fn telemetry_that_ages_during_the_health_query_is_checked_before_first_append() {
    let ledger = Arc::new(RecoveryLedger::new());
    ledger.delay_health_once.store(true, Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel(1);
    sender
        .try_send(event_at("login_success", Utc::now()).into())
        .unwrap();
    drop(sender);
    tokio::time::timeout(
        Duration::from_secs(10),
        run_audit_persist_worker(
            receiver,
            ledger.clone(),
            Some(preflight(AuditAnchorMode::Required, 1)),
        ),
    )
    .await
    .unwrap();
    assert!(ledger.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_attempted_batch_keeps_its_exact_identity_after_it_ages_and_returns_an_error() {
    let ledger = Arc::new(RecoveryLedger::new());
    ledger.fail_slow_once.store(true, Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel(2);
    for _ in 0..2 {
        sender
            .try_send(event_at("login_success", Utc::now()).into())
            .unwrap();
    }
    drop(sender);
    tokio::time::timeout(
        Duration::from_secs(10),
        run_audit_persist_worker(
            receiver,
            ledger.clone(),
            Some(preflight(AuditAnchorMode::Required, 1)),
        ),
    )
    .await
    .unwrap();
    let attempts = ledger.attempts.lock().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].len(), 2);
    assert_eq!(attempts[1].len(), 2);
    for (first, retry) in attempts[0].iter().zip(&attempts[1]) {
        assert_eq!(first.event_id, retry.event_id);
        assert_eq!(first.event_type, retry.event_type);
        assert_eq!(first.event_category, retry.event_category);
        assert_eq!(first.payload, retry.payload);
        assert_eq!(first.occurred_at, retry.occurred_at);
    }
    assert_eq!(ledger.persisted.lock().unwrap().len(), 2);
}
