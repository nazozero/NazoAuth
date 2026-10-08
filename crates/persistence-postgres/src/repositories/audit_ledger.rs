use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use nazo_identity::ports::RepositoryError;

use crate::{DbPool, get_conn, pool::DiscardOnDrop};

use nazo_persistence::audit_chain::{security_audit_batch_digest, security_audit_event_hash};
/// The maximum JSON payload accepted by the durable audit ledger.
///
/// Audit events deliberately contain identifiers and hashes, not bearer
/// credentials. A bounded payload keeps the in-process queue and the pending
/// event set from becoming an unbounded memory/storage sink when a caller
/// makes a programming mistake.
pub use nazo_persistence::{
    MAX_SECURITY_AUDIT_PAYLOAD_BYTES, SecurityAuditAnchorHealth, SecurityAuditBatch,
    SecurityAuditBatchAck, SecurityAuditBatchClaim, SecurityAuditBatchLease, SecurityAuditEvent,
    SecurityAuditPendingDelivery,
};

pub const MIN_ENVELOPE_BYTES: i64 = 128 * 1024;
pub const MAX_ENVELOPE_BYTES: i64 = 1024 * 1024;

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
    /// superuser/owner membership and reachable ledger table or column privileges.
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

    /// Return the exporter checkpoint, the committed batch lease and a cheap
    /// backlog projection without granting the exporter direct table access.
    pub async fn anchor_health(&self) -> Result<SecurityAuditAnchorHealth, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(
            "SELECT last_sequence AS head_sequence, last_hash AS head_hash, \
                    pending_exists, pending_estimate, pending_orphan_exists, \
                    oldest_pending_occurred_at, \
                    anchor_sequence AS last_exported_sequence, \
                    anchor_hash AS last_exported_hash, \
                    anchor_occurred_at AS last_exported_occurred_at, \
                    anchor_accepted_at AS last_exported_at, \
                    anchor_deployment_id AS deployment_id, \
                    anchor_observed_at AS observed_at, \
                    batch_first_sequence, batch_last_sequence, batch_event_count, \
                    batch_generation, batch_attempts, batch_available_at, batch_locked_until, \
                    batch_last_error, batch_blocked_reason \
             FROM public.nazo_security_audit_shared_anchor_health() \
             WHERE chain_valid",
        )
        .get_result::<SecurityAuditAnchorHealthRow>(&mut connection)
        .await
        .map(Into::into)
        .map_err(map_error)
    }

    pub async fn observe_anchor(&self, deployment_id: &str) -> Result<(), RepositoryError> {
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let changed = sql_query("SELECT public.nazo_observe_security_audit_anchor($1) AS changed")
            .bind::<diesel::sql_types::Text, _>(deployment_id)
            .load::<AuditMutationRow>(guard.connection())
            .await
            .and_then(single_audit_mutation)
            .map_err(map_error)?;
        guard.return_to_pool();
        require_current_audit_mutation(changed)
    }

    pub async fn record_genesis(
        &self,
        deployment_id: &str,
        head_hash: &[u8],
    ) -> Result<(), RepositoryError> {
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let changed =
            sql_query("SELECT public.nazo_record_security_audit_genesis($1, $2) AS changed")
                .bind::<diesel::sql_types::Text, _>(deployment_id)
                .bind::<diesel::sql_types::Binary, _>(head_hash)
                .load::<AuditMutationRow>(guard.connection())
                .await
                .and_then(single_audit_mutation)
                .map_err(map_error)?;
        guard.return_to_pool();
        require_current_audit_mutation(changed)
    }

    /// Persist an event atomically; the row is the pending delivery identity
    /// until the acknowledgement deletes it. The chain head is not touched.
    pub async fn append(&self, event: SecurityAuditEvent) -> Result<(), RepositoryError> {
        self.append_batch(std::slice::from_ref(&event)).await
    }

    /// Persist a queued batch in one checkout and one implicit transaction.
    /// Events beyond the first are written by a single set-based statement that
    /// calls `nazo_persist_security_audit_event` once per row inside the same
    /// statement, so per-event idempotent replay semantics are unchanged and
    /// any failure rolls the whole batch back. An indeterminate transaction
    /// outcome discards the physical connection instead of returning it to
    /// the pool.
    pub async fn append_batch(&self, events: &[SecurityAuditEvent]) -> Result<(), RepositoryError> {
        match events.len() {
            0 => return Ok(()),
            // A singleton still uses one statement, but must consume its
            // complete result stream before acknowledging the implicit commit.
            1 => {
                let mut guard = DiscardOnDrop(Some(self.connection().await?));
                append_on_connection(guard.connection(), &events[0])
                    .await
                    .map_err(map_error)?;
                guard.return_to_pool();
                return Ok(());
            }
            _ => {}
        }
        // Same validation order and error classification as the single-event
        // path: every event is checked before the batch statement runs.
        for event in events {
            validate_event_for_transaction(event).map_err(map_error)?;
        }
        let event_ids: Vec<Uuid> = events.iter().map(|event| event.event_id).collect();
        let event_types: Vec<&str> = events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        let event_categories: Vec<&str> = events
            .iter()
            .map(|event| event.event_category.as_str())
            .collect();
        let payloads: Vec<&serde_json::Value> = events.iter().map(|event| &event.payload).collect();
        let occurred_ats: Vec<DateTime<Utc>> =
            events.iter().map(|event| event.occurred_at).collect();
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        // The single statement already commits or rolls back every function
        // call together. Separate BEGIN/COMMIT round trips add no atomicity.
        // Keep the guard armed until the complete statement outcome is known.
        sql_query(
            "SELECT public.nazo_persist_security_audit_event(\
                    item.event_id, item.event_type, item.event_category, \
                    item.payload, item.occurred_at) AS changed \
             FROM unnest($1, $2, $3, $4, $5) AS \
                    item(event_id, event_type, event_category, payload, occurred_at)",
        )
        .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(event_ids)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Text>, _>(event_types)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Text>, _>(event_categories)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Jsonb>, _>(payloads)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Timestamptz>, _>(occurred_ats)
        .load::<AuditMutationRow>(guard.connection())
        .await
        .and_then(|rows| {
            if rows.len() == events.len() {
                Ok(())
            } else {
                Err(invariant_error(
                    "security audit batch returned an unexpected row count",
                ))
            }
        })
        .map_err(map_error)?;
        guard.return_to_pool();
        Ok(())
    }

    /// Claim the single in-flight batch inside one exporter transaction. The
    /// chain control row stays locked only for the database work: candidate
    /// selection, chain assignment, lease commit. HTTPS always happens after
    /// commit. A re-claim returns the identical committed range and content;
    /// only the fencing generation moves.
    pub async fn claim_batch(
        &self,
        deployment_id: &str,
        limit: i64,
        max_envelope_bytes: i64,
        lock_timeout_seconds: i32,
    ) -> Result<SecurityAuditBatchClaim, RepositoryError> {
        if !(1..=256).contains(&limit)
            || !(MIN_ENVELOPE_BYTES..=MAX_ENVELOPE_BYTES).contains(&max_envelope_bytes)
            || !(1..=3_600).contains(&lock_timeout_seconds)
            || deployment_id.is_empty()
            || deployment_id.len() > 255
        {
            return Err(RepositoryError::Unexpected(
                "audit batch claim arguments are outside their safe bounds".to_owned(),
            ));
        }
        let deployment_id = deployment_id.to_owned();
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let result = guard
            .connection()
            .transaction::<_, diesel::result::Error, _>(async |connection| {
                let head = sql_query(
                    "SELECT last_sequence, last_hash, anchor_sequence, \
                            batch_first_sequence, batch_last_sequence, batch_event_count, \
                            batch_digest, batch_attempts, batch_available_at, \
                            batch_locked_until, batch_blocked_reason \
                     FROM public.nazo_security_audit_chain_head_for_update()",
                )
                .get_result::<AuditChainHeadRow>(connection)
                .await?;
                if head.batch_last_sequence.is_some() {
                    return claim_inflight(connection, &head, &deployment_id, lock_timeout_seconds)
                        .await;
                }
                claim_fresh(
                    connection,
                    &head,
                    &deployment_id,
                    limit,
                    max_envelope_bytes,
                    lock_timeout_seconds,
                )
                .await
            })
            .await
            .map_err(map_error);
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }

    /// Durable whole-batch acknowledgement. The database verifies the fencing
    /// generation and receiver-bound range/content before reclaiming chain
    /// proofs, deleting ordinary events, marking retained decisions exported,
    /// and advancing the anchor in one transaction.
    pub async fn ack_batch(&self, ack: SecurityAuditBatchAck) -> Result<(), RepositoryError> {
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let changed = sql_query(
            "SELECT public.nazo_ack_security_audit_batch($1, $2, $3, $4, $5, $6, $7) AS changed",
        )
        .bind::<diesel::sql_types::BigInt, _>(ack.generation)
        .bind::<diesel::sql_types::BigInt, _>(ack.first_sequence)
        .bind::<diesel::sql_types::BigInt, _>(ack.last_sequence)
        .bind::<diesel::sql_types::Integer, _>(ack.event_count as i32)
        .bind::<diesel::sql_types::Binary, _>(&ack.last_hash)
        .bind::<diesel::sql_types::Binary, _>(&ack.batch_digest)
        .bind::<diesel::sql_types::Text, _>(&ack.deployment_id)
        .load::<AuditMutationRow>(guard.connection())
        .await
        .and_then(single_audit_mutation)
        .map_err(map_error)?;
        guard.return_to_pool();
        require_current_audit_mutation(changed)
    }

    /// Release the lease after a failed send/ack so the identical range is
    /// re-claimed after the backoff. `blocked` parks the batch until an
    /// operator reconciles and unblocks it; stale generations are a no-op.
    pub async fn fail_batch(
        &self,
        generation: i64,
        available_at: DateTime<Utc>,
        last_error: &str,
        blocked: bool,
    ) -> Result<(), RepositoryError> {
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let changed =
            sql_query("SELECT public.nazo_fail_security_audit_batch($1, $2, $3, $4) AS changed")
                .bind::<diesel::sql_types::BigInt, _>(generation)
                .bind::<diesel::sql_types::Timestamptz, _>(available_at)
                .bind::<diesel::sql_types::Text, _>(last_error)
                .bind::<diesel::sql_types::Bool, _>(blocked)
                .load::<AuditMutationRow>(guard.connection())
                .await
                .and_then(single_audit_mutation)
                .map_err(map_error)?;
        guard.return_to_pool();
        if changed {
            return Ok(());
        }
        Err(RepositoryError::Consistency(
            "security audit batch generation is stale or already settled".to_owned(),
        ))
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
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
    // A function's first DataRow is not an implicit-transaction commit ACK.
    // Drain through statement completion so late database errors propagate.
    // Inside a business transaction, its owner still awaits the final COMMIT.
    sql_query("SELECT public.nazo_persist_security_audit_event($1, $2, $3, $4, $5) AS changed")
        .bind::<diesel::sql_types::Uuid, _>(event.event_id)
        .bind::<diesel::sql_types::Text, _>(&event.event_type)
        .bind::<diesel::sql_types::Text, _>(&event.event_category)
        .bind::<diesel::sql_types::Jsonb, _>(&event.payload)
        .bind::<diesel::sql_types::Timestamptz, _>(event.occurred_at)
        .load::<AuditMutationRow>(connection)
        .await
        .and_then(single_audit_mutation)
}

/// Re-claim the committed in-flight batch. The identical sequence range and
/// content come back with a bumped fencing generation; anything else is an
/// inconsistency and fails closed.
async fn claim_inflight(
    connection: &mut AsyncPgConnection,
    head: &AuditChainHeadRow,
    deployment_id: &str,
    lock_timeout_seconds: i32,
) -> Result<SecurityAuditBatchClaim, diesel::result::Error> {
    if let Some(reason) = head.batch_blocked_reason.clone() {
        return Ok(SecurityAuditBatchClaim::Blocked { reason });
    }
    let now = Utc::now();
    if head.batch_locked_until.is_some_and(|until| until > now)
        || head.batch_available_at.is_some_and(|at| at > now)
    {
        return Ok(SecurityAuditBatchClaim::Busy);
    }
    let rows = sql_query(
        "SELECT event_id, sequence, event_type, event_category, payload_canonical, \
                occurred_at, previous_hash, event_hash \
         FROM public.nazo_security_audit_batch_members()",
    )
    .load::<SecurityAuditBatchMemberRow>(connection)
    .await?;
    let first_sequence = head.batch_first_sequence.unwrap_or_default();
    let last_sequence = head.batch_last_sequence.unwrap_or_default();
    let expected_count = head.batch_event_count.unwrap_or_default() as usize;
    if first_sequence != head.anchor_sequence.unwrap_or_default() + 1 {
        return Err(invariant_error(
            "security audit batch does not continue the anchor checkpoint",
        ));
    }
    let members_form_prefix = rows.len() == expected_count
        && first_sequence + expected_count as i64 - 1 == last_sequence
        && rows
            .iter()
            .enumerate()
            .all(|(offset, row)| row.sequence == Some(first_sequence + offset as i64));
    if !members_form_prefix {
        return Err(invariant_error(
            "security audit batch members no longer form the committed prefix",
        ));
    }
    let mut deliveries = Vec::with_capacity(rows.len());
    let mut event_hashes = Vec::with_capacity(rows.len());
    for row in rows {
        let event_hash = row
            .event_hash
            .ok_or_else(|| invariant_error("security audit batch member has no chain hash"))?;
        let hash: [u8; 32] = event_hash
            .as_slice()
            .try_into()
            .map_err(|_| invariant_error("security audit chain hash has an invalid length"))?;
        event_hashes.push(hash);
        deliveries.push(SecurityAuditPendingDelivery {
            event_id: row.event_id,
            sequence: row
                .sequence
                .ok_or_else(|| invariant_error("security audit batch member has no sequence"))?,
            event_type: row.event_type,
            event_category: row.event_category,
            payload_canonical: row.payload_canonical,
            occurred_at: row.occurred_at,
            previous_hash: row.previous_hash.ok_or_else(|| {
                invariant_error("security audit batch member has no previous hash")
            })?,
            event_hash,
        });
    }
    let previous_hash = deliveries
        .as_slice()
        .first()
        .map(|delivery| delivery.previous_hash.clone())
        .ok_or_else(|| invariant_error("security audit batch has no first member"))?;
    let last_hash = deliveries
        .iter()
        .next_back()
        .map(|delivery| delivery.event_hash.clone())
        .ok_or_else(|| invariant_error("security audit batch has no last member"))?;
    let digest = security_audit_batch_digest(
        deployment_id,
        first_sequence,
        last_sequence,
        expected_count as i64,
        &previous_hash,
        &last_hash,
        &event_hashes,
    )
    .to_vec();
    if head
        .batch_digest
        .as_deref()
        .is_some_and(|stored| stored != digest.as_slice())
    {
        return Err(invariant_error(
            "security audit batch content changed under the lease",
        ));
    }
    let generation =
        sql_query("SELECT public.nazo_reclaim_security_audit_batch($1, $2) AS generation")
            .bind::<diesel::sql_types::Binary, _>(&digest)
            .bind::<diesel::sql_types::Integer, _>(lock_timeout_seconds)
            .get_result::<AuditGenerationRow>(connection)
            .await?;
    Ok(SecurityAuditBatchClaim::Claimed(SecurityAuditBatch {
        generation: generation.generation,
        first_sequence,
        last_sequence,
        previous_hash,
        last_hash,
        digest,
        attempts: head.batch_attempts,
        deliveries,
    }))
}

/// Open a new batch over the pending set. Candidates arrive already ordered
/// (chained leftovers first, then occurred_at order); only the longest
/// envelope-fitting prefix is chained and committed.
async fn claim_fresh(
    connection: &mut AsyncPgConnection,
    head: &AuditChainHeadRow,
    deployment_id: &str,
    limit: i64,
    max_envelope_bytes: i64,
    lock_timeout_seconds: i32,
) -> Result<SecurityAuditBatchClaim, diesel::result::Error> {
    let rows = sql_query(
        "SELECT event_id, sequence, event_type, event_category, payload_canonical, \
                occurred_at, previous_hash, event_hash \
         FROM public.nazo_claim_security_audit_pending($1)",
    )
    .bind::<diesel::sql_types::BigInt, _>(limit)
    .load::<SecurityAuditBatchMemberRow>(connection)
    .await?;
    if rows.is_empty() {
        return Ok(SecurityAuditBatchClaim::Empty);
    }
    let mut next_sequence = head.last_sequence;
    let mut next_hash = head.last_hash.clone();
    let budget = usize::try_from(max_envelope_bytes)
        .map_err(|_| invariant_error("invalid audit envelope budget"))?;
    let mut used_event_bytes = 0_usize;
    let mut deliveries: Vec<SecurityAuditPendingDelivery> = Vec::with_capacity(rows.len());
    let mut new_event_ids = Vec::new();
    let mut new_event_hashes = Vec::new();
    for row in rows {
        let (sequence, previous_hash, event_hash, newly_chained) =
            match (row.sequence, row.previous_hash, row.event_hash) {
                (Some(sequence), Some(previous_hash), Some(event_hash)) => {
                    (sequence, previous_hash, event_hash, false)
                }
                (None, None, None) => {
                    let sequence = next_sequence
                        .checked_add(1)
                        .ok_or_else(|| invariant_error("security audit sequence overflow"))?;
                    let event_hash = security_audit_event_hash(
                        sequence,
                        &next_hash,
                        row.event_id,
                        &row.event_type,
                        &row.event_category,
                        row.occurred_at,
                        row.payload_canonical.as_bytes(),
                    )
                    .to_vec();
                    (sequence, next_hash.clone(), event_hash, true)
                }
                _ => return Err(invariant_error("security audit chain entry is incomplete")),
            };
        let delivery = SecurityAuditPendingDelivery {
            event_id: row.event_id,
            sequence,
            event_type: row.event_type,
            event_category: row.event_category,
            payload_canonical: row.payload_canonical,
            occurred_at: row.occurred_at,
            previous_hash,
            event_hash,
        };
        let event_bytes = nazo_persistence::audit_wire::security_audit_event_wire_length(&delivery)
            .map_err(|_| invariant_error("audit event wire serialization failed"))?;
        let header_bytes = nazo_persistence::audit_wire::security_audit_empty_envelope_wire_length(
            deployment_id,
            deliveries.as_slice().first().unwrap_or(&delivery),
            &delivery,
            (deliveries.len() + 1) as i64,
        )
        .map_err(|_| invariant_error("audit envelope wire serialization failed"))?;
        let bytes = header_bytes
            .checked_add(used_event_bytes)
            .and_then(|count| count.checked_add(event_bytes))
            .and_then(|count| count.checked_add(deliveries.len()))
            .ok_or_else(|| invariant_error("audit envelope byte count overflow"))?;
        if !deliveries.is_empty() && bytes > budget {
            break;
        }
        if deliveries.is_empty()
            && bytes > nazo_persistence::audit_wire::MAX_SECURITY_AUDIT_SINGLETON_ENVELOPE_BYTES
        {
            return Err(invariant_error(
                "audit singleton exceeds the legal-event wire bound",
            ));
        }
        if newly_chained {
            next_sequence = sequence;
            next_hash = delivery.event_hash.clone();
            new_event_ids.push(delivery.event_id);
            new_event_hashes.push(delivery.event_hash.clone());
        }
        used_event_bytes += event_bytes;
        deliveries.push(delivery);
    }
    if deliveries.is_empty() {
        return Err(invariant_error(
            "security audit event exceeds the committed envelope bound",
        ));
    }
    let first = deliveries.as_slice().first().expect("non-empty batch");
    let last = deliveries.iter().next_back().expect("non-empty batch");
    let event_hashes: Vec<[u8; 32]> = deliveries
        .iter()
        .map(|delivery| {
            delivery
                .event_hash
                .as_slice()
                .try_into()
                .map_err(|_| invariant_error("security audit chain hash has an invalid length"))
        })
        .collect::<Result<_, _>>()?;
    let digest = security_audit_batch_digest(
        deployment_id,
        first.sequence,
        last.sequence,
        deliveries.len() as i64,
        &first.previous_hash,
        &last.event_hash,
        &event_hashes,
    )
    .to_vec();
    let generation = sql_query(
        "SELECT public.nazo_finalize_security_audit_claim(\
            $1, $2, $3, $4, $5, $6, $7, $8, $9) AS generation",
    )
    .bind::<diesel::sql_types::BigInt, _>(head.last_sequence)
    .bind::<diesel::sql_types::Binary, _>(&head.last_hash)
    .bind::<diesel::sql_types::Array<diesel::sql_types::Uuid>, _>(new_event_ids)
    .bind::<diesel::sql_types::Array<diesel::sql_types::Binary>, _>(new_event_hashes)
    .bind::<diesel::sql_types::BigInt, _>(first.sequence)
    .bind::<diesel::sql_types::BigInt, _>(last.sequence)
    .bind::<diesel::sql_types::Integer, _>(deliveries.len() as i32)
    .bind::<diesel::sql_types::Binary, _>(&digest)
    .bind::<diesel::sql_types::Integer, _>(lock_timeout_seconds)
    .get_result::<AuditGenerationRow>(connection)
    .await?;
    Ok(SecurityAuditBatchClaim::Claimed(SecurityAuditBatch {
        generation: generation.generation,
        first_sequence: first.sequence,
        last_sequence: last.sequence,
        previous_hash: first.previous_hash.clone(),
        last_hash: last.event_hash.clone(),
        digest,
        attempts: 0,
        deliveries,
    }))
}

#[derive(QueryableByName)]
struct AuditChainHeadRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    last_sequence: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    last_hash: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    anchor_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    batch_first_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    batch_last_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    batch_event_count: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
    batch_digest: Option<Vec<u8>>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    batch_attempts: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    batch_available_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    batch_locked_until: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    batch_blocked_reason: Option<String>,
}

#[derive(QueryableByName)]
struct AuditGenerationRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    generation: i64,
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
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pending_exists: bool,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pending_estimate: i64,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pending_orphan_exists: bool,
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
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    batch_first_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    batch_last_sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
    batch_event_count: Option<i32>,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    batch_generation: i64,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    batch_attempts: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    batch_available_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    batch_locked_until: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    batch_last_error: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    batch_blocked_reason: Option<String>,
}

impl From<SecurityAuditAnchorHealthRow> for SecurityAuditAnchorHealth {
    fn from(row: SecurityAuditAnchorHealthRow) -> Self {
        let batch = row
            .batch_last_sequence
            .map(|last_sequence| SecurityAuditBatchLease {
                first_sequence: row.batch_first_sequence.unwrap_or_default(),
                last_sequence,
                event_count: i64::from(row.batch_event_count.unwrap_or_default()),
                generation: row.batch_generation,
                attempts: row.batch_attempts,
                available_at: row.batch_available_at,
                locked_until: row.batch_locked_until,
                last_error: row.batch_last_error,
                blocked_reason: row.batch_blocked_reason,
            });
        Self {
            head_sequence: row.head_sequence,
            head_hash: row.head_hash,
            pending_exists: row.pending_exists,
            pending_estimate: row.pending_estimate,
            pending_orphan_exists: row.pending_orphan_exists,
            oldest_pending_occurred_at: row.oldest_pending_occurred_at,
            last_exported_sequence: row.last_exported_sequence,
            last_exported_hash: row.last_exported_hash,
            last_exported_occurred_at: row.last_exported_occurred_at,
            last_exported_at: row.last_exported_at,
            deployment_id: row.deployment_id,
            observed_at: row.observed_at,
            batch,
        }
    }
}

#[derive(QueryableByName)]
struct AuditMutationRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    changed: bool,
}

// Validate the result shape only after `load` has consumed the entire stream.
// `false` is still a valid idempotent append result; mutation callers decide
// whether their operation instead requires a current generation/checkpoint.
fn single_audit_mutation(rows: Vec<AuditMutationRow>) -> Result<bool, diesel::result::Error> {
    match rows.as_slice() {
        [row] => Ok(row.changed),
        _ => Err(invariant_error(
            "security audit mutation must return exactly one row",
        )),
    }
}

#[derive(QueryableByName)]
struct SecurityAuditBatchMemberRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    event_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    sequence: Option<i64>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_type: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    event_category: String,
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
        || event.event_type == "authorization_decision_committed"
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

#[derive(Default)]
struct PayloadByteCount(usize);

impl std::io::Write for PayloadByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("audit payload byte count overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_payload_size(event: &SecurityAuditEvent) -> Result<(), RepositoryError> {
    let mut payload_bytes = PayloadByteCount::default();
    serde_json::to_writer(&mut payload_bytes, &event.payload)
        .map_err(|error| RepositoryError::Unexpected(format!("invalid audit payload: {error}")))?;
    if payload_bytes.0 > MAX_SECURITY_AUDIT_PAYLOAD_BYTES {
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

fn invariant_error(message: &'static str) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    )))
}

fn require_current_audit_mutation(changed: bool) -> Result<(), RepositoryError> {
    if changed {
        Ok(())
    } else {
        Err(RepositoryError::Consistency(
            "security audit mutation is stale or already terminal".to_owned(),
        ))
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/audit_ledger.rs"]
mod tests;
