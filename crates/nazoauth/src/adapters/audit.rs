//! 结构化安全审计日志。

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use tokio::sync::mpsc;
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
static PERSISTENT_AUDIT_SINK: OnceLock<mpsc::Sender<QueuedAuditEvent>> = OnceLock::new();
static REQUIRED_AUDIT_REPOSITORY: OnceLock<RequiredAuditRepository> = OnceLock::new();

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
/// The request path remains synchronous: it writes the structured event to
/// tracing and performs a bounded `try_send` into a worker. The worker retries
/// database failures indefinitely, preserving the event after it has entered
/// the queue. Queue saturation/disconnection is reported as a distinct,
/// machine-searchable failure instead of being silently swallowed. Actions
/// that already have a transactional security repository retain their own
/// fail-closed semantics; this sink is the durable evidence/export path for
/// the broader application audit vocabulary.
pub(crate) fn install_persistent_audit_sink(
    repository: Arc<dyn SecurityAuditLedger>,
    require_least_privilege: bool,
    preflight: AuditAnchorPreflight,
) -> anyhow::Result<()> {
    if PERSISTENT_AUDIT_SINK.get().is_some() {
        let Some(existing) = REQUIRED_AUDIT_REPOSITORY.get() else {
            anyhow::bail!("durable security audit sink is partially installed");
        };
        if existing.require_least_privilege != require_least_privilege
            || existing.preflight != preflight
        {
            anyhow::bail!(
                "durable security audit sink was already installed with different configuration"
            );
        }
        return Ok(());
    }
    let candidate = RequiredAuditRepository {
        repository: repository.clone(),
        require_least_privilege,
        preflight: preflight.clone(),
    };
    if let Err(candidate) = REQUIRED_AUDIT_REPOSITORY.set(candidate) {
        let Some(existing) = REQUIRED_AUDIT_REPOSITORY.get() else {
            anyhow::bail!("durable security audit repository installation raced bootstrap");
        };
        if existing.require_least_privilege != candidate.require_least_privilege
            || existing.preflight != candidate.preflight
        {
            anyhow::bail!(
                "durable security audit repository was already installed with different configuration"
            );
        }
    }
    let (sender, receiver) = mpsc::channel(AUDIT_QUEUE_CAPACITY);
    if PERSISTENT_AUDIT_SINK.set(sender).is_err() {
        return Ok(());
    }

    tokio::spawn(run_audit_persist_worker(receiver, repository));
    Ok(())
}

/// Upper bound for one opportunistic persist batch. The worker never waits to
/// fill a batch: it appends immediately whatever is already queued, so a lone
/// event is still persisted without added latency.
const AUDIT_PERSIST_BATCH_MAX: usize = 64;

/// Drain the best-effort queue into the durable ledger. After the first event
/// arrives, already-queued events are pulled in non-blocking up to
/// `AUDIT_PERSIST_BATCH_MAX`; the batch is then persisted in one transaction.
/// A failed batch is retained whole and retried with exponential backoff, so
/// the oldest unpersisted batch still blocks all later ones. Split out of the
/// sink installer so tests can drive it with their own channel and ledger.
async fn run_audit_persist_worker(
    mut receiver: mpsc::Receiver<QueuedAuditEvent>,
    repository: Arc<dyn SecurityAuditLedger>,
) {
    while let Some(first) = receiver.recv().await {
        let mut batch = vec![first];
        while batch.len() < AUDIT_PERSIST_BATCH_MAX {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        let events: Vec<SecurityAuditEvent> = batch
            .iter()
            .map(|event| SecurityAuditEvent {
                event_id: event.event_id,
                event_type: event.event_type.clone(),
                event_category: event.event_category.clone(),
                payload: event.payload.clone(),
                occurred_at: event.occurred_at,
            })
            .collect();
        let batch_len = events.len() as u64;
        let mut retry_delay = Duration::from_millis(100);
        loop {
            match repository.append_batch(&events).await {
                Ok(()) => {
                    AUDIT_QUEUE_PERSISTED.fetch_add(batch_len, Ordering::Relaxed);
                    AUDIT_PERSIST_BATCHES.fetch_add(1, Ordering::Relaxed);
                    AUDIT_PERSIST_BATCH_EVENTS.fetch_add(batch_len, Ordering::Relaxed);
                    AUDIT_PERSIST_MAX_BATCH.fetch_max(batch_len, Ordering::Relaxed);
                    tracing::debug!(
                        target: "audit.persistence",
                        batch_len,
                        first_event_id = %events[0].event_id,
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
                        persistence_status = "retrying",
                        "security audit batch persistence failed"
                    );
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
    let Some(required) = REQUIRED_AUDIT_REPOSITORY.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    ensure_audit_storage_via(required).await
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
    let Some(required) = REQUIRED_AUDIT_REPOSITORY.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    ensure_transactional_audit_ready_via(required).await
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
/// this path never drops an event into the in-process queue: the caller gets an
/// error when the ledger is unavailable and must convert it to a fail-closed
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
    let Some(required) = REQUIRED_AUDIT_REPOSITORY.get() else {
        anyhow::bail!("durable security audit repository is not configured");
    };
    append_required_via(&required.repository, event, queued).await
}

/// The required evidence path is deliberately separate from the best-effort
/// queue: a direct ledger append whose failure is returned to the caller.
async fn append_required_via(
    repository: &Arc<dyn SecurityAuditLedger>,
    event: &str,
    queued: QueuedAuditEvent,
) -> anyhow::Result<()> {
    repository
        .append(SecurityAuditEvent {
            event_id: queued.event_id,
            event_type: queued.event_type.clone(),
            event_category: queued.event_category.clone(),
            payload: queued.payload.clone(),
            occurred_at: queued.occurred_at,
        })
        .await
        .map_err(|error| anyhow::anyhow!("security audit append failed: {error}"))?;
    tracing::info!(
        target: "audit",
        event,
        fields = %queued.payload,
        event_id = %queued.event_id,
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
    enqueue_into_sink(sink, event, queued);
}

fn enqueue_into_sink(sink: &mpsc::Sender<QueuedAuditEvent>, event: &str, queued: QueuedAuditEvent) {
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
    match sink.try_send(queued) {
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
