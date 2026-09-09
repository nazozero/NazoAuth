use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use serde_json::Value;
use uuid::Uuid;

use nazo_identity::ports::RepositoryError;

use crate::{DbPool, pool::DiscardOnDrop};

/// The maximum JSON payload accepted by the durable audit ledger.
///
/// Audit events deliberately contain identifiers and hashes, not bearer
/// credentials. A bounded payload keeps the in-process queue and the database
/// outbox from becoming an unbounded memory/storage sink when a caller makes a
/// programming mistake.
pub use nazo_persistence::{
    MAX_SECURITY_AUDIT_PAYLOAD_BYTES, SecurityAuditAnchorHealth, SecurityAuditEvent,
    SecurityAuditOutboxDelivery,
};

#[derive(Clone)]
pub struct AuditLedgerRepository {
    pool: DbPool,
}

impl AuditLedgerRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Verify that the durable writer API is available before a
    /// caller starts a high-impact management operation. Strict mode rejects
    /// superusers, table owners, and any direct ledger table privilege.
    pub async fn check_available(&self) -> Result<(), RepositoryError> {
        self.check_available_with_policy(true).await
    }

    /// The policy switch is explicit so isolated development fixtures can opt
    /// out of strict role checks without weakening the function API boundary.
    /// Function EXECUTE grants are required in both modes.
    pub async fn check_available_with_policy(
        &self,
        require_least_privilege: bool,
    ) -> Result<(), RepositoryError> {
        self.check_capabilities(require_least_privilege, true, false)
            .await
    }

    /// Verify the exporter API. The writer role does not receive chain
    /// assignment or claim/ack EXECUTEs, so it cannot use this preflight.
    pub async fn check_exporter_available(&self) -> Result<(), RepositoryError> {
        self.check_exporter_available_with_policy(true).await
    }

    pub async fn check_exporter_available_with_policy(
        &self,
        require_least_privilege: bool,
    ) -> Result<(), RepositoryError> {
        self.check_capabilities(require_least_privilege, false, true)
            .await
    }

    async fn check_capabilities(
        &self,
        require_least_privilege: bool,
        require_append: bool,
        require_exporter: bool,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let privileges = sql_query(
            "SELECT policy_satisfied \
             FROM public.nazo_security_audit_shared_privilege_preflight($1, $2, $3)",
        )
        .bind::<diesel::sql_types::Bool, _>(require_least_privilege)
        .bind::<diesel::sql_types::Bool, _>(require_append)
        .bind::<diesel::sql_types::Bool, _>(require_exporter)
        .get_result::<AuditPrivilegePreflightRow>(&mut connection)
        .await
        .map_err(map_error)?;
        if !privileges.policy_satisfied {
            return Err(RepositoryError::Consistency(
                "security audit privilege preflight failed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Return the exporter checkpoint and durable backlog without granting the
    /// exporter direct SELECT/UPDATE privileges on any audit table.
    pub async fn anchor_health(&self) -> Result<SecurityAuditAnchorHealth, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(
            "SELECT last_sequence AS head_sequence, last_hash AS head_hash, \
                    pending_count, oldest_pending_occurred_at, \
                    anchor_sequence AS last_exported_sequence, \
                    anchor_hash AS last_exported_hash, \
                    anchor_occurred_at AS last_exported_occurred_at, \
                    anchor_accepted_at AS last_exported_at, \
                    anchor_deployment_id AS deployment_id, \
                    anchor_observed_at AS observed_at \
             FROM public.nazo_security_audit_shared_anchor_health() \
             WHERE chain_valid",
        )
        .get_result::<SecurityAuditAnchorHealthRow>(&mut connection)
        .await
        .map(Into::into)
        .map_err(map_error)
    }

    pub async fn observe_anchor(&self, deployment_id: &str) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result = sql_query("SELECT public.nazo_observe_security_audit_anchor($1) AS changed")
            .bind::<diesel::sql_types::Text, _>(deployment_id)
            .get_result::<AuditMutationRow>(&mut connection)
            .await
            .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    pub async fn record_genesis(
        &self,
        deployment_id: &str,
        head_hash: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result =
            sql_query("SELECT public.nazo_record_security_audit_genesis($1, $2) AS changed")
                .bind::<diesel::sql_types::Text, _>(deployment_id)
                .bind::<diesel::sql_types::Binary, _>(head_hash)
                .get_result::<AuditMutationRow>(&mut connection)
                .await
                .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    /// Persist an event and its outbox entry atomically, without acquiring the chain head.
    pub async fn append(&self, event: SecurityAuditEvent) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        append_on_connection(&mut connection, &event)
            .await
            .map(|_| ())
            .map_err(map_error)
    }

    /// Claim and chain a batch in one exporter transaction. A retry returns
    /// its immutable chain entry instead of assigning a second sequence.
    pub async fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError> {
        if !(1..=256).contains(&limit) || !(1..=3_600).contains(&lock_timeout_seconds) {
            return Err(RepositoryError::Unexpected(
                "audit outbox claim limit or lock timeout is outside its safe bound".to_owned(),
            ));
        }
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let result = guard.connection().transaction::<_, diesel::result::Error, _>(async |connection| {
            let mut head = sql_query(
                "SELECT last_sequence, last_hash FROM public.nazo_security_audit_chain_head_for_update()",
            ).get_result::<ChainStateRow>(connection).await?;
            let previous_sequence = head.last_sequence;
            let previous_hash = head.last_hash.clone();
            let rows = sql_query(
                "SELECT event_id, attempts, sequence, event_type, event_category, \
                        payload, payload_canonical, occurred_at, previous_hash, event_hash \
                 FROM public.nazo_claim_security_audit_events($1, $2)",
            )
            .bind::<diesel::sql_types::BigInt, _>(limit)
            .bind::<diesel::sql_types::Integer, _>(lock_timeout_seconds)
            .load::<SecurityAuditOutboxRow>(connection).await?;
            let mut deliveries = Vec::with_capacity(rows.len());
            let mut event_ids = Vec::new();
            let mut event_hashes = Vec::new();
            for row in rows {
                let event = SecurityAuditEvent {
                    event_id: row.event_id, event_type: row.event_type,
                    event_category: row.event_category, payload: row.payload, occurred_at: row.occurred_at,
                };
                let (sequence, previous_hash, event_hash) = match (row.sequence, row.previous_hash, row.event_hash) {
                    (Some(sequence), Some(previous_hash), Some(event_hash)) => (sequence, previous_hash, event_hash),
                    (None, None, None) => {
                        head.last_sequence = head.last_sequence.checked_add(1)
                            .ok_or_else(|| invariant_error("security audit sequence overflow"))?;
                        let event_hash = hash_event(head.last_sequence, &head.last_hash, &event, row.payload_canonical.as_bytes()).to_vec();
                        let previous_hash = std::mem::replace(&mut head.last_hash, event_hash.clone());
                        event_ids.push(event.event_id);
                        event_hashes.push(event_hash.clone());
                        (head.last_sequence, previous_hash, event_hash)
                    }
                    _ => return Err(invariant_error("security audit chain entry is incomplete")),
                };
                deliveries.push(SecurityAuditOutboxDelivery {
                    event_id: event.event_id, sequence, event_type: event.event_type,
                    event_category: event.event_category, payload: event.payload, occurred_at: event.occurred_at,
                    previous_hash, event_hash, attempts: row.attempts,
                });
            }
            if !event_ids.is_empty() {
                sql_query("SELECT public.nazo_append_security_audit_chain($1, $2, $3, $4)")
                    .bind::<diesel::sql_types::BigInt, _>(previous_sequence)
                    .bind::<diesel::sql_types::Binary, _>(previous_hash)
                    .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(event_ids)
                    .bind::<diesel::sql_types::Array<diesel::sql_types::Binary>, _>(event_hashes)
                    .execute(connection).await?;
            }
            Ok(deliveries)
        }).await.map_err(map_error);
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }

    pub async fn mark_exported(
        &self,
        event_id: Uuid,
        expected_attempts: i32,
        deployment_id: &str,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result =
            sql_query("SELECT public.nazo_ack_security_audit_event($1, $2, $3) AS changed")
                .bind::<diesel::sql_types::Uuid, _>(event_id)
                .bind::<diesel::sql_types::Integer, _>(expected_attempts)
                .bind::<diesel::sql_types::Text, _>(deployment_id)
                .get_result::<AuditMutationRow>(&mut connection)
                .await
                .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    pub async fn reschedule(
        &self,
        event_id: Uuid,
        expected_attempts: i32,
        available_at: DateTime<Utc>,
        last_error: &str,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let result = sql_query(
            "SELECT public.nazo_reschedule_security_audit_event($1, $2, $3, $4) AS changed",
        )
        .bind::<diesel::sql_types::Uuid, _>(event_id)
        .bind::<diesel::sql_types::Integer, _>(expected_attempts)
        .bind::<diesel::sql_types::Timestamptz, _>(available_at)
        .bind::<diesel::sql_types::Text, _>(last_error)
        .get_result::<AuditMutationRow>(&mut connection)
        .await
        .map_err(map_error)?;
        require_current_outbox_claim(result.changed)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

/// Persist a fresh event in the caller's business transaction. An existing
/// event id is an error: the caller must recover its original business result.
pub async fn append_fresh_security_audit_on_connection(
    connection: &mut AsyncPgConnection,
    event: &SecurityAuditEvent,
) -> Result<(), diesel::result::Error> {
    if append_on_connection(connection, event).await? {
        Ok(())
    } else {
        Err(invariant_error(
            "security audit event already exists in the immutable ledger",
        ))
    }
}

async fn append_on_connection(
    connection: &mut AsyncPgConnection,
    event: &SecurityAuditEvent,
) -> Result<bool, diesel::result::Error> {
    validate_event_for_transaction(event)?;
    sql_query("SELECT public.nazo_persist_security_audit_event($1, $2, $3, $4, $5) AS changed")
        .bind::<diesel::sql_types::Uuid, _>(event.event_id)
        .bind::<diesel::sql_types::Text, _>(&event.event_type)
        .bind::<diesel::sql_types::Text, _>(&event.event_category)
        .bind::<diesel::sql_types::Jsonb, _>(&event.payload)
        .bind::<diesel::sql_types::Timestamptz, _>(event.occurred_at)
        .get_result::<AuditMutationRow>(connection)
        .await
        .map(|row| row.changed)
}

#[derive(QueryableByName)]
struct ChainStateRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    last_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    last_hash: Vec<u8>,
}

#[derive(QueryableByName)]
struct AuditPrivilegePreflightRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    policy_satisfied: bool,
}

#[derive(QueryableByName)]
struct SecurityAuditAnchorHealthRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    head_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    head_hash: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pending_count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    oldest_pending_occurred_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    last_exported_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    last_exported_hash: Option<Vec<u8>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_exported_occurred_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    last_exported_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    deployment_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    observed_at: Option<DateTime<Utc>>,
}

impl From<SecurityAuditAnchorHealthRow> for SecurityAuditAnchorHealth {
    fn from(row: SecurityAuditAnchorHealthRow) -> Self {
        Self {
            head_sequence: row.head_sequence,
            head_hash: row.head_hash,
            pending_count: row.pending_count,
            oldest_pending_occurred_at: row.oldest_pending_occurred_at,
            last_exported_sequence: row.last_exported_sequence,
            last_exported_hash: row.last_exported_hash,
            last_exported_occurred_at: row.last_exported_occurred_at,
            last_exported_at: row.last_exported_at,
            deployment_id: row.deployment_id,
            observed_at: row.observed_at,
        }
    }
}

#[derive(QueryableByName)]
struct AuditMutationRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    changed: bool,
}

#[derive(QueryableByName)]
struct SecurityAuditOutboxRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    event_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    attempts: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_type: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_category: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    payload: Value,
    #[diesel(sql_type = diesel::sql_types::Text)]
    payload_canonical: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    occurred_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    previous_hash: Option<Vec<u8>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    event_hash: Option<Vec<u8>>,
}

fn validate_event(event: &SecurityAuditEvent) -> Result<(), RepositoryError> {
    if event.event_id.is_nil()
        || !valid_identifier(&event.event_type)
        || !valid_identifier(&event.event_category)
        || !event.payload.is_object()
    {
        return Err(RepositoryError::Unexpected(
            "security audit event has invalid identity or payload".to_owned(),
        ));
    }
    Ok(())
}

fn validate_payload_size(event: &SecurityAuditEvent) -> Result<(), RepositoryError> {
    let payload_bytes = serde_json::to_vec(&event.payload)
        .map_err(|error| RepositoryError::Unexpected(format!("invalid audit payload: {error}")))?;
    if payload_bytes.len() > MAX_SECURITY_AUDIT_PAYLOAD_BYTES {
        return Err(RepositoryError::Unexpected(format!(
            "audit payload exceeds {MAX_SECURITY_AUDIT_PAYLOAD_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_event_for_transaction(event: &SecurityAuditEvent) -> Result<(), diesel::result::Error> {
    validate_event(event)
        .and_then(|()| validate_payload_size(event))
        .map_err(|error| {
            diesel::result::Error::SerializationError(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )))
        })
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= 64
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

fn hash_event(
    sequence: i64,
    previous_hash: &[u8],
    event: &SecurityAuditEvent,
    payload_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nazo.audit.v1\0");
    hasher.update(&sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(event.event_id.as_bytes());
    update_len_prefixed(&mut hasher, event.event_type.as_bytes());
    update_len_prefixed(&mut hasher, event.event_category.as_bytes());
    hasher.update(&event.occurred_at.timestamp_micros().to_be_bytes());
    update_len_prefixed(&mut hasher, payload_bytes);
    *hasher.finalize().as_bytes()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn invariant_error(message: &'static str) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
}

fn require_current_outbox_claim(changed: bool) -> Result<(), RepositoryError> {
    if changed {
        Ok(())
    } else {
        Err(RepositoryError::Consistency(
            "security audit outbox claim is stale or already terminal".to_owned(),
        ))
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/audit_ledger.rs"]
mod tests;
