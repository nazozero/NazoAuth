//! 结构化安全审计日志。

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use nazo_oauth_server::ports::audit::{AuditFuture, SecurityAudit};
use nazo_persistence::{SecurityAuditEvent, SecurityAuditLedger};

use super::audit_anchor::AuditAnchorPreflight;

pub(crate) const AUDIT_SCHEMA_VERSION: &str = "nazo.audit.v1";

tokio::task_local! {
    /// Set by the HTTP tenant resolver for the lifetime of the selected
    /// request future. Capture this authority before handing events to the
    /// deployment-wide asynchronous ledger worker.
    pub(crate) static REQUEST_TENANT: nazo_identity::TenantId;
}

/// Audit capability bound to one tenant and the process's existing durable sink.
#[derive(Clone)]
pub(crate) struct TenantSecurityAudit {
    tenant_id: nazo_identity::TenantId,
}

impl TenantSecurityAudit {
    pub(crate) fn new(tenant_id: nazo_identity::TenantId) -> Self {
        Self { tenant_id }
    }
}

impl SecurityAudit for TenantSecurityAudit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(ensure_audit_storage())
    }

    fn ensure_transactional_ready(&self) -> AuditFuture<'_> {
        Box::pin(ensure_transactional_audit_ready())
    }

    fn record(&self, event: &str, fields: serde_json::Map<String, serde_json::Value>) {
        enqueue_event(
            event,
            prepare_event_for_tenant(event, fields, Some(self.tenant_id)),
        );
    }

    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        let queued = prepare_event_for_tenant(event, fields, Some(self.tenant_id));
        Box::pin(async move { append_required_event(event, queued).await })
    }
}

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization_code",
    "client_secret",
    "dpop_proof",
    "client_assertion",
];

/// Audit evidence class: `Required` events are security evidence whose
/// durable persistence must not silently fail; `Telemetry` events are
/// best-effort operational signal. The class is metadata for routing checks
/// and observability, not a filter — both classes reach the durable sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditEventClass {
    Required,
    Telemetry,
}

const AUDIT_EVENT_DEFINITIONS: &[(&str, &str, AuditEventClass)] = &[
    // Reserved durable business fact: only the decision commit capability
    // creates this event; ordinary ledger append rejects it.
    (
        "authorization_decision_committed",
        "authorization",
        AuditEventClass::Required,
    ),
    (
        "admin_mutation_intent",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_identity_approval_issued",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_slot_created",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_slot_revoked",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_slot_rotated",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "system_tenant_admin_updated",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_recovery_root_rotation_approved",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "controller_recovery_root_rotated",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "admin_user_created",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "admin_user_updated",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "admin_grant_revoked",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "admin_access_request_rejected",
        "administration",
        AuditEventClass::Required,
    ),
    (
        "authorization_approved",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "authorization_denied",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "authorization_decision_intent",
        "authorization",
        AuditEventClass::Required,
    ),
    (
        "authorization_prompt_none_approved",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "ciba_authorization_approved",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "ciba_authorization_denied",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "ciba_authorization_started",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "ciba_authorization_intent",
        "authorization",
        AuditEventClass::Required,
    ),
    (
        "ciba_decision_intent",
        "authorization",
        AuditEventClass::Required,
    ),
    (
        "device_authorization_approved",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "device_authorization_denied",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "device_authorization_started",
        "authorization",
        AuditEventClass::Telemetry,
    ),
    (
        "device_decision_intent",
        "authorization",
        AuditEventClass::Required,
    ),
    (
        "client_assertion_replay_detected",
        "credential_replay",
        AuditEventClass::Required,
    ),
    (
        "client_created",
        "client_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "client_updated",
        "client_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "dynamic_client_configuration_read",
        "client_lifecycle",
        AuditEventClass::Telemetry,
    ),
    (
        "dynamic_client_configuration_updated",
        "client_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "dynamic_client_deleted",
        "client_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "dynamic_client_registered",
        "client_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "dpop_replay_detected",
        "credential_replay",
        AuditEventClass::Required,
    ),
    (
        "external_identity_linked",
        "identity_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "external_identity_relink_denied",
        "identity_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "external_identity_unlinked",
        "identity_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "federation_login_success",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "federation_provider_mismatch_rejected",
        "credential_replay",
        AuditEventClass::Required,
    ),
    (
        "federation_saml_replay_rejected",
        "credential_replay",
        AuditEventClass::Required,
    ),
    (
        "login_failure",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "login_success",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "mfa_backup_codes_regenerated",
        "authentication",
        AuditEventClass::Required,
    ),
    (
        "mfa_challenge_failure",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "mfa_challenge_success",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    ("mfa_disabled", "authentication", AuditEventClass::Required),
    (
        "mfa_step_up_success",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "mfa_totp_enabled",
        "authentication",
        AuditEventClass::Required,
    ),
    (
        "oidc_logout",
        "session_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "openid4vci_credential_dataset_deleted",
        "credential_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "openid4vci_credential_dataset_updated",
        "credential_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "mtls_trust_anchor_approved",
        "trust_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "mtls_trust_bundle_exported",
        "trust_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "mtls_trust_anchor_rejected",
        "trust_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "mtls_trust_anchor_requested",
        "trust_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "mtls_trust_anchor_revoked",
        "trust_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "passkey_login_failure",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "passkey_login_success",
        "authentication",
        AuditEventClass::Telemetry,
    ),
    (
        "passkey_registered",
        "authentication",
        AuditEventClass::Required,
    ),
    (
        "passkey_registration_rejected",
        "authentication",
        AuditEventClass::Required,
    ),
    (
        "refresh_reuse_detected",
        "token_replay",
        AuditEventClass::Required,
    ),
    (
        "scim_token_denied",
        "provisioning",
        AuditEventClass::Required,
    ),
    (
        "scim_token_used",
        "provisioning",
        AuditEventClass::Telemetry,
    ),
    ("token_issued", "token_lifecycle", AuditEventClass::Required),
    // Deliberate server-side retirement of a refresh family when the
    // (tenant, user, client) active-family cap evicts the oldest live family.
    (
        "refresh_family_capacity_retired",
        "token_lifecycle",
        AuditEventClass::Required,
    ),
    // Durable family invalidation at the public replay-retention cutover or
    // an authentication-class downgrade; the adapter appends atomically.
    (
        "refresh_family_security_revoked",
        "token_lifecycle",
        AuditEventClass::Required,
    ),
    // Retired intent marker: issuance commits the token row and `token_issued`
    // in one transaction, so no producer emits this.  It stays defined as
    // Required so any future accidental emission fails closed instead of
    // reaching the best-effort queue as an unknown event.
    (
        "token_issuance_intent",
        "token_lifecycle",
        AuditEventClass::Required,
    ),
    (
        "token_revoked",
        "token_lifecycle",
        AuditEventClass::Required,
    ),
];

const AUDIT_QUEUE_CAPACITY: usize = 4096;

/// Best-effort queue telemetry. Required events never enter this queue, so
/// these counters describe the telemetry path only; they are surfaced solely
/// through the `PERF_METRICS_ENABLED` endpoint.
static AUDIT_QUEUE_ENQUEUED: AtomicU64 = AtomicU64::new(0);
static AUDIT_QUEUE_PERSISTED: AtomicU64 = AtomicU64::new(0);
static AUDIT_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
static AUDIT_PERSIST_BATCHES: AtomicU64 = AtomicU64::new(0);
static AUDIT_PERSIST_BATCH_EVENTS: AtomicU64 = AtomicU64::new(0);
static AUDIT_PERSIST_MAX_BATCH: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the best-effort audit queue counters for the perf-only
/// metrics endpoint. `pending_in_process` = enqueued minus persisted, i.e.
/// events sitting in the channel or inside a retrying batch.
pub(crate) fn audit_queue_metrics() -> serde_json::Value {
    let enqueued = AUDIT_QUEUE_ENQUEUED.load(Ordering::Relaxed);
    let persisted = AUDIT_QUEUE_PERSISTED.load(Ordering::Relaxed);
    serde_json::json!({
        "enqueued": enqueued,
        "persisted": persisted,
        "dropped": AUDIT_QUEUE_DROPPED.load(Ordering::Relaxed),
        "pending_in_process": enqueued.saturating_sub(persisted),
        "persist_batches": AUDIT_PERSIST_BATCHES.load(Ordering::Relaxed),
        "persist_batch_events": AUDIT_PERSIST_BATCH_EVENTS.load(Ordering::Relaxed),
        "persist_max_batch": AUDIT_PERSIST_MAX_BATCH.load(Ordering::Relaxed),
    })
}

// These are process-lifetime handles: the request path currently resolves the
// durable sink through `ensure_audit_storage`, so bootstrap must install them
// exactly once before handlers start accepting traffic.
static PERSISTENT_AUDIT_SINK: OnceLock<PersistentAuditSink> = OnceLock::new();

struct PersistentAuditSink {
    telemetry: mpsc::Sender<AuditPersistRequest>,
    required: mpsc::Sender<AuditPersistRequest>,
    repository: RequiredAuditRepository,
}

#[derive(Debug)]
struct AuditPersistRequest {
    event: QueuedAuditEvent,
    completion: Option<oneshot::Sender<anyhow::Result<SecurityAuditEvent>>>,
}

impl From<QueuedAuditEvent> for AuditPersistRequest {
    fn from(event: QueuedAuditEvent) -> Self {
        Self {
            event,
            completion: None,
        }
    }
}

struct RequiredAuditRepository {
    repository: Arc<dyn SecurityAuditLedger>,
    require_least_privilege: bool,
    preflight: AuditAnchorPreflight,
}

#[derive(Clone, Debug)]
struct QueuedAuditEvent {
    event_id: Uuid,
    event_type: String,
    event_category: String,
    payload: serde_json::Value,
    occurred_at: chrono::DateTime<Utc>,
}

/// Install the durable audit sink once during application bootstrap.
///
/// Telemetry logs and tries its bounded channel without waiting. Standalone
/// Required records use an independent bounded channel and await the batch's
/// durable commit. Required failures return to the caller; Telemetry retries
/// its own failed batch without delaying the Required channel. Audit inside a
/// business transaction retains that transaction's fail-closed semantics.
pub(crate) fn install_persistent_audit_sink(
    repository: Arc<dyn SecurityAuditLedger>,
    require_least_privilege: bool,
    preflight: AuditAnchorPreflight,
) -> anyhow::Result<()> {
    if let Some(existing) = PERSISTENT_AUDIT_SINK.get() {
        if existing.repository.require_least_privilege != require_least_privilege
            || existing.repository.preflight != preflight
        {
            anyhow::bail!(
                "durable security audit sink was already installed with different configuration"
            );
        }
        return Ok(());
    }
    let (telemetry, telemetry_receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
    let (required, required_receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
    let candidate = PersistentAuditSink {
        telemetry,
        required,
        repository: RequiredAuditRepository {
            repository: repository.clone(),
            require_least_privilege,
            preflight,
        },
    };
    if let Err(candidate) = PERSISTENT_AUDIT_SINK.set(candidate) {
        let existing = PERSISTENT_AUDIT_SINK
            .get()
            .expect("sink was installed concurrently");
        if existing.repository.require_least_privilege
            != candidate.repository.require_least_privilege
            || existing.repository.preflight != candidate.repository.preflight
        {
            anyhow::bail!(
                "durable security audit sink was already installed with different configuration"
            );
        }
        return Ok(());
    }
    tokio::spawn(run_audit_persist_worker(
        telemetry_receiver,
        repository.clone(),
    ));
    tokio::spawn(run_audit_persist_worker(required_receiver, repository));
    Ok(())
}

/// Bound both batch size and additional coalescing time. Standalone Required
/// records wait for the committed batch; issuance audit stays in its transaction.
const AUDIT_PERSIST_BATCH_MAX: usize = 64;
const AUDIT_PERSIST_COALESCE_WINDOW: Duration = Duration::from_millis(10);

/// Drain one audit channel into the durable ledger. After the first event,
/// collect arrivals until the fixed window ends, the batch is full or the
/// channel closes; persist the batch in one transaction. Later arrivals do
/// not extend the first event's deadline.
/// Telemetry retries whole batches in order. A Required batch reports its first
/// failure to every caller and continues; it never shares Telemetry's retry
/// backlog. Split out of the
/// sink installer so tests can drive it with their own channel and ledger.
async fn run_audit_persist_worker(
    mut receiver: mpsc::Receiver<AuditPersistRequest>,
    repository: Arc<dyn SecurityAuditLedger>,
) {
    while let Some(first) = receiver.recv().await {
        let mut batch = vec![first];
        let coalesce = tokio::time::sleep(AUDIT_PERSIST_COALESCE_WINDOW);
        tokio::pin!(coalesce);
        while batch.len() < AUDIT_PERSIST_BATCH_MAX {
            tokio::select! {
                biased;
                _ = &mut coalesce => break,
                event = receiver.recv() => match event {
                    Some(event) => batch.push(event),
                    None => break,
                },
            }
        }
        let required = batch[0].completion.is_some();
        debug_assert!(
            batch
                .iter()
                .all(|request| request.completion.is_some() == required)
        );
        let (events, mut completions): (Vec<SecurityAuditEvent>, Vec<_>) = batch
            .into_iter()
            .map(|request| {
                let event = request.event;
                (SecurityAuditEvent {
                    event_id: event.event_id,
                    event_type: event.event_type,
                    event_category: event.event_category,
                    payload: event.payload,
                    occurred_at: event.occurred_at,
                }, request.completion)
            })
            .unzip();
        let batch_len = events.len() as u64;
        let mut retry_delay = Duration::from_millis(100);
        loop {
            match repository.append_batch(&events).await {
                Ok(()) => {
                    if !required {
                        AUDIT_QUEUE_PERSISTED.fetch_add(batch_len, Ordering::Relaxed);
                        AUDIT_PERSIST_BATCHES.fetch_add(1, Ordering::Relaxed);
                        AUDIT_PERSIST_BATCH_EVENTS.fetch_add(batch_len, Ordering::Relaxed);
                        AUDIT_PERSIST_MAX_BATCH.fetch_max(batch_len, Ordering::Relaxed);
                    }
                    let first_event_id = events[0].event_id;
                    for (event, completion) in events.into_iter().zip(completions) {
                        if let Some(completion) = completion {
                            let _ = completion.send(Ok(event));
                        }
                    }
                    tracing::debug!(
                        target: "audit.persistence",
                        batch_len,
                        first_event_id = %first_event_id,
                        persistence_status = "durable",
                        "security audit batch appended"
                    );
                    break;
                }
                Err(error) => {
                    tracing::error!(
                        target: "audit.persistence",
                        batch_len,
                        %error,
                        persistence_status = if required { "failed_required" } else { "retrying" },
                        "security audit batch persistence failed"
                    );
                    if required {
                        for completion in &mut completions {
                            if let Some(completion) = completion.take() {
                                let _ = completion.send(Err(anyhow::anyhow!(
                                    "security audit append failed: {error}"
                                )));
                            }
                        }
                        break;
                    }
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay + retry_delay, Duration::from_secs(5));
                }
            }
        }
    }
}

/// Preflight the durable ledger before a high-impact mutation.
///
/// When the mutation and this ledger do not share a transaction boundary,
/// callers should append a required `*_intent` event after this check and
/// before changing state. The committed outcome can then be emitted through
/// [`audit_event`] (or, where the stores are atomic, through
/// [`audit_event_required`]).
pub(crate) async fn ensure_audit_storage() -> anyhow::Result<()> {
    let Some(sink) = PERSISTENT_AUDIT_SINK.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    ensure_audit_storage_via(&sink.repository).await
}

async fn ensure_audit_storage_via(required: &RequiredAuditRepository) -> anyhow::Result<()> {
    required
        .repository
        .check_available(required.require_least_privilege)
        .await
        .map_err(|error| {
            anyhow::anyhow!("durable security audit repository unavailable: {error}")
        })?;
    ensure_anchor_fresh_if_required(required).await
}

/// Readiness for a mutation whose required audit record commits inside the
/// same transaction as the state change. The static writer capability was
/// verified once at startup and the commit's own `nazo_persist_...` call
/// fails closed if it was revoked since, so repeating the probe per request
/// buys nothing. The dynamic anchor-health gate is unchanged: required mode
/// still reads fresh health on every call.
pub(crate) async fn ensure_transactional_audit_ready() -> anyhow::Result<()> {
    let Some(sink) = PERSISTENT_AUDIT_SINK.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    ensure_transactional_audit_ready_via(&sink.repository).await
}

async fn ensure_transactional_audit_ready_via(
    required: &RequiredAuditRepository,
) -> anyhow::Result<()> {
    if required.preflight.is_required() {
        ensure_anchor_fresh(required).await
    } else {
        Ok(())
    }
}

async fn ensure_anchor_fresh_if_required(required: &RequiredAuditRepository) -> anyhow::Result<()> {
    if required.preflight.is_required() {
        ensure_anchor_fresh(required).await?;
    }
    Ok(())
}

async fn ensure_anchor_fresh(required: &RequiredAuditRepository) -> anyhow::Result<()> {
    let health =
        required.repository.anchor_health().await.map_err(|error| {
            anyhow::anyhow!("durable security audit health unavailable: {error}")
        })?;
    required.preflight.ensure_fresh(&health)
}

/// Append a high-impact audit outcome synchronously. Unlike [`audit_event`],
/// this path waits for a durable batch acknowledgement: the caller gets an
/// error when the channel or ledger is unavailable and must convert it to a fail-closed
/// response. The recommended sequence is `ensure_audit_storage().await`,
/// perform the mutation, then await this function with the committed outcome.
pub(crate) async fn audit_event_required(
    event: &str,
    fields: serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<()> {
    append_required_event(event, prepare_event(event, fields)).await
}

async fn append_required_event(
    event: &str,
    queued: Result<QueuedAuditEvent, &'static str>,
) -> anyhow::Result<()> {
    let queued =
        queued.map_err(|reason| anyhow::anyhow!("security audit event rejected: {reason}"))?;
    let Some(sink) = PERSISTENT_AUDIT_SINK.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    append_required_via(&sink.required, event, queued).await
}

/// Required evidence has its own bounded channel and a commit barrier. It
/// cannot be dropped as Telemetry or wait behind a retrying Telemetry batch.
async fn append_required_via(
    sink: &mpsc::Sender<AuditPersistRequest>,
    event: &str,
    queued: QueuedAuditEvent,
) -> anyhow::Result<()> {
    let (completion, persisted) = oneshot::channel();
    sink.try_send(AuditPersistRequest {
        event: queued,
        completion: Some(completion),
    })
    .map_err(|error| {
        let reason = match error {
            mpsc::error::TrySendError::Full(_) => "queue_full",
            mpsc::error::TrySendError::Closed(_) => "sink_closed",
        };
        anyhow::anyhow!("required security audit event not accepted: {reason}")
    })?;
    let persisted = persisted
        .await
        .map_err(|_| anyhow::anyhow!("required security audit worker stopped before commit"))??;
    tracing::info!(
        target: "audit",
        event,
        fields = %persisted.payload,
        event_id = %persisted.event_id,
        persistence_status = "durable",
        "security audit event"
    );
    Ok(())
}

fn enqueue_event(event: &str, queued: Result<QueuedAuditEvent, &'static str>) {
    debug_assert!(audit_event_name_valid(event));
    debug_assert!(audit_event_category(event).is_some());
    let queued = match queued {
        Ok(queued) => queued,
        Err(reason) => {
            tracing::error!(
                target: "audit.persistence",
                event,
                persistence_status = "rejected",
                reason,
                "security audit event was rejected"
            );
            return;
        }
    };
    tracing::info!(
        target: "audit",
        event,
        fields = %queued.payload,
        "security audit event"
    );
    let Some(sink) = PERSISTENT_AUDIT_SINK.get() else {
        tracing::error!(
            target: "audit.persistence",
            event,
            persistence_status = "not_configured",
            "security audit event has no durable sink"
        );
        return;
    };
    enqueue_into_sink(&sink.telemetry, event, queued);
}

fn enqueue_into_sink(
    sink: &mpsc::Sender<AuditPersistRequest>,
    event: &str,
    queued: QueuedAuditEvent,
) {
    let required_class = audit_event_is_required(event);
    if required_class {
        // Required evidence should go through `audit_event_required` or a
        // transactional append; the best-effort queue can drop on saturation.
        // Warn once per event name so a high-rate event cannot flood logs.
        static MISROUTED_REQUIRED_SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> =
            OnceLock::new();
        let first_seen = MISROUTED_REQUIRED_SEEN
            .get_or_init(|| Mutex::new(std::collections::HashSet::new()))
            .lock()
            .map(|mut seen| seen.insert(event.to_owned()))
            .unwrap_or(false);
        if first_seen {
            tracing::warn!(
                target: "audit.persistence",
                event,
                persistence_status = "misrouted_required",
                "required-class audit event emitted through best-effort queue"
            );
        }
    }
    match sink.try_send(queued.into()) {
        Ok(()) => {
            AUDIT_QUEUE_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            AUDIT_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
            let reason = match error {
                mpsc::error::TrySendError::Full(_) => "queue_full",
                mpsc::error::TrySendError::Closed(_) => "sink_closed",
            };
            tracing::error!(
                target: "audit.persistence",
                event,
                persistence_status = if required_class { "dropped_required" } else { "not_queued" },
                reason,
                "security audit event could not enter durable sink"
            );
        }
    }
}

fn prepare_event(
    event: &str,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Result<QueuedAuditEvent, &'static str> {
    prepare_event_for_tenant(
        event,
        fields,
        REQUEST_TENANT.try_with(|tenant| *tenant).ok(),
    )
}

fn prepare_event_for_tenant(
    event: &str,
    mut fields: serde_json::Map<String, serde_json::Value>,
    tenant_id: Option<nazo_identity::TenantId>,
) -> Result<QueuedAuditEvent, &'static str> {
    if let Some(tenant_id) = tenant_id {
        let tenant = serde_json::json!(tenant_id);
        if fields
            .get("tenant_id")
            .is_some_and(|declared| declared != &tenant)
        {
            return Err("tenant_context_mismatch");
        }
        fields.insert("tenant_id".to_owned(), tenant);
    }
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }
    let Some(category) = audit_event_category(event) else {
        return Err("unknown_event_type");
    };
    fields.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(AUDIT_SCHEMA_VERSION.to_owned()),
    );
    fields.insert(
        "event_category".to_owned(),
        serde_json::Value::String(category.to_owned()),
    );
    let payload = serde_json::Value::Object(fields);
    let payload_size = serde_json::to_vec(&payload)
        .map_err(|_| "payload_serialization_failed")?
        .len();
    if payload_size > nazo_persistence::MAX_SECURITY_AUDIT_PAYLOAD_BYTES {
        return Err("payload_too_large");
    }
    Ok(QueuedAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: event.to_owned(),
        event_category: category.to_owned(),
        payload,
        occurred_at: Utc::now(),
    })
}

fn audit_event_category(event: &str) -> Option<&'static str> {
    AUDIT_EVENT_DEFINITIONS
        .iter()
        .find_map(|(name, category, _)| (*name == event).then_some(*category))
}

fn audit_event_is_required(event: &str) -> bool {
    AUDIT_EVENT_DEFINITIONS
        .iter()
        .find_map(|(name, _, class)| {
            (*name == event).then_some(matches!(class, AuditEventClass::Required))
        })
        .unwrap_or(true)
}

fn audit_event_name_valid(event: &str) -> bool {
    let mut chars = event.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/audit.rs"]
mod tests;
