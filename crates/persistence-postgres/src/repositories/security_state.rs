//! Bounded security-state maintenance.
//!
//! One batch per `cleanup_batch` call:
//! 1. `nazo_oauth_cleanup_expired_security_state()` — issuances, access-token
//!    revocations, SCIM audit events, backchannel logout deliveries and SCIM
//!    security events (256 rows each).
//! 2. Refresh spent proofs — deleted at their own `expires_at`; the proof
//!    only has readers inside the token's acceptance window, so expiry makes
//!    "present" and "absent" indistinguishable (`invalid_grant` either way).
//! 3. Refresh families — deleted once the current generation expired; spent
//!    proofs cascade because a spent proof's expiry never outlives the
//!    family's last `current_expires_at` (rotation only extends it).
//! 4. Orphaned refresh contracts — deleted once no family references them,
//!    behind a grace so an in-flight issuance can never lose a contract row
//!    it just inserted.
//! 5. `nazo_openid4vp_cleanup_expired_transactions()` — expired presentations.
//! 6. OpenID4VCI offer, nonce, deferred, notification and response expiry;
//!    access-grant ownership is retained through verifier clock skew and until
//!    its children have been reclaimed in their own bounded batches.
//!
//! Every category is a bounded batch (≤256 rows) on a single row per
//! authority; there is no member-history traversal. Family reclaim keeps the
//! shared advisory key: a writer holding `refresh_family_lock_key` causes the
//! candidate to be skipped this round, and expiry is rechecked under the lock
//! so a just-rotated family is never reclaimed mid-commit. Audit-ledger rows
//! are not a maintenance category: the
//! exporter's ACK removes the delivered event and chain-entry rows in
//! the same transaction that advances the durable anchor checkpoint, so
//! nothing accumulates for a sweeper to reclaim and no local archive copy
//! exists — the receiver is the sole authoritative audit history.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{
    CleanupBatchResult, SecurityStateMaintenanceFuture, SecurityStateMaintenancePort,
};

use crate::{DbConnection, DbPool, get_conn};

/// Per-category row budget per batch (matches the SQL function contract).
const CLEANUP_BATCH_LIMIT: i64 = 256;
/// Contracts only become deletable once no in-flight issuance can still be
/// attaching a family to them; an hour dwarfs any issuance transaction.
const ORPHAN_CONTRACT_GRACE_SECONDS: i64 = 3600;

#[derive(Clone)]
pub struct SecurityStateMaintenanceRepository {
    pool: DbPool,
    contract_cursor: Arc<tokio::sync::Mutex<Option<ContractSweepCursor>>>,
    grant_cursor: Arc<tokio::sync::Mutex<Option<GrantSweepCursor>>>,
}

// Cursors only schedule a bounded pass; PostgreSQL remains the authority for
// expiry and references. Clones share progress, and restart simply rescans.
#[derive(Clone)]
struct ContractSweepCursor {
    cutoff: DateTime<Utc>,
    created_at: DateTime<Utc>,
    tenant_id: uuid::Uuid,
    contract_blake3: Vec<u8>,
}

#[derive(QueryableByName)]
struct ContractSweepRow {
    #[diesel(sql_type = sql_types::Timestamptz)]
    cutoff: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: uuid::Uuid,
    #[diesel(sql_type = sql_types::Binary)]
    contract_blake3: Vec<u8>,
    #[diesel(sql_type = sql_types::Bool)]
    locked: bool,
}

#[derive(Clone)]
struct GrantSweepCursor {
    cutoff: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    token_id: uuid::Uuid,
}

#[derive(QueryableByName)]
struct GrantSweepRow {
    #[diesel(sql_type = sql_types::Timestamptz)]
    cutoff: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Uuid)]
    token_id: uuid::Uuid,
    #[diesel(sql_type = sql_types::Bool)]
    locked: bool,
}

#[derive(QueryableByName)]
struct GenericCleanupCounts {
    #[diesel(sql_type = sql_types::Integer)]
    deleted_issuances: i32,
    #[diesel(sql_type = sql_types::Integer)]
    deleted_access_token_revocations: i32,
    #[diesel(sql_type = sql_types::Integer)]
    deleted_scim_audit_events: i32,
    #[diesel(sql_type = sql_types::Integer)]
    deleted_backchannel_logout_deliveries: i32,
    #[diesel(sql_type = sql_types::Integer)]
    deleted_scim_security_events: i32,
}

#[derive(QueryableByName)]
struct PresentationCleanupCount {
    #[diesel(sql_type = sql_types::Integer)]
    deleted_transactions: i32,
}

#[derive(QueryableByName)]
struct CredentialExpiryCounts {
    #[diesel(sql_type = sql_types::BigInt)]
    offers: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    nonces: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    deferred: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    notifications: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    responses: i64,
    #[diesel(sql_type = sql_types::Bool)]
    grants_due: bool,
}

#[derive(Default)]
struct CredentialCleanupCounts {
    offers: u64,
    nonces: u64,
    grants: u64,
    deferred: u64,
    notifications: u64,
    responses: u64,
    saturated: bool,
}

impl SecurityStateMaintenanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            contract_cursor: Arc::new(tokio::sync::Mutex::new(None)),
            grant_cursor: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn generic_cleanup(&self) -> Result<GenericCleanupCounts, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query("SELECT * FROM nazo_oauth_cleanup_expired_security_state()")
            .get_result::<GenericCleanupCounts>(&mut connection)
            .await
            .map_err(map_error)
    }

    async fn presentation_cleanup(&self) -> Result<u64, RepositoryError> {
        let mut connection = self.connection().await?;
        let count = sql_query(
            "SELECT nazo_openid4vp_cleanup_expired_transactions() AS deleted_transactions",
        )
        .get_result::<PresentationCleanupCount>(&mut connection)
        .await
        .map_err(map_error)?;
        debug_assert!((0..=CLEANUP_BATCH_LIMIT as i32).contains(&count.deleted_transactions));
        Ok(count.deleted_transactions.max(0) as u64)
    }

    /// Delete spent proofs at their own expiry. An expired proof's only
    /// reader — the token endpoint — returns `invalid_grant` whether the row
    /// is present or absent, so the row has no post-expiry authority.
    async fn delete_expired_spent_proofs(&self) -> Result<(u64, bool), RepositoryError> {
        let mut connection = self.connection().await?;
        let deleted = sql_query(
            "WITH due AS ( \
                 SELECT tenant_id, refresh_token_blake3 \
                 FROM oauth_refresh_spent_tokens \
                 WHERE expires_at <= CURRENT_TIMESTAMP \
                 ORDER BY expires_at, refresh_token_blake3 \
                 LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_refresh_spent_tokens AS target \
             USING due \
             WHERE target.tenant_id = due.tenant_id \
               AND target.refresh_token_blake3 = due.refresh_token_blake3",
        )
        .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        Ok((deleted as u64, deleted as i64 >= CLEANUP_BATCH_LIMIT))
    }

    /// Delete families whose current generation expired. The cascade removes
    /// remaining spent proofs; the family's contract is reclaimed by the
    /// orphan sweep once unreferenced. Each candidate is reclaimed under the
    /// shared writer advisory key (try-lock — a held key skips the family this
    /// round) and expiry is rechecked under the lock, so a family whose writer
    /// just committed a new generation is never reclaimed mid-commit.
    async fn delete_expired_refresh_families(&self) -> Result<(u64, bool), RepositoryError> {
        #[derive(QueryableByName)]
        struct ExpiredFamily {
            #[diesel(sql_type = sql_types::Uuid)]
            tenant_id: uuid::Uuid,
            #[diesel(sql_type = sql_types::Uuid)]
            token_family_id: uuid::Uuid,
        }
        let mut connection = self.connection().await?;
        connection
            .build_transaction()
            .read_committed()
            .run::<(u64, bool), diesel::result::Error, _>(async |connection| {
                let due = sql_query(
                    "SELECT tenant_id, token_family_id \
                     FROM oauth_refresh_families \
                     WHERE current_expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY current_expires_at, token_family_id \
                     LIMIT $1",
                )
                .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
                .load::<ExpiredFamily>(connection)
                .await?;
                let saturated = due.len() as i64 >= CLEANUP_BATCH_LIMIT;
                if due.is_empty() {
                    return Ok((0, false));
                }
                let tenant_ids = due.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let family_ids = due
                    .iter()
                    .map(|row| row.token_family_id)
                    .collect::<Vec<_>>();
                let lock_keys = family_ids
                    .iter()
                    .map(|id| super::tokens::refresh_family_lock_key(*id))
                    .collect::<Vec<_>>();
                // Candidates are already bounded before this volatile function
                // runs. Keep exactly the writer's lock key; try-lock failures
                // skip that family without holding up unrelated candidates.
                let locked = sql_query(
                    "SELECT tenant_id, token_family_id \
                     FROM UNNEST($1::uuid[], $2::uuid[], $3::bigint[]) \
                          AS due(tenant_id, token_family_id, lock_key) \
                     WHERE pg_try_advisory_xact_lock(lock_key)",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&family_ids)
                .bind::<sql_types::Array<sql_types::BigInt>, _>(&lock_keys)
                .load::<ExpiredFamily>(connection)
                .await?;
                if locked.is_empty() {
                    return Ok((0, saturated));
                }
                let tenant_ids = locked.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let family_ids = locked
                    .iter()
                    .map(|row| row.token_family_id)
                    .collect::<Vec<_>>();
                // This must remain a separate READ COMMITTED statement. A
                // rotation can commit between the candidate snapshot and lock
                // acquisition; only a new snapshot sees its extended expiry.
                let deleted = sql_query(
                    "DELETE FROM oauth_refresh_families AS target \
                     USING UNNEST($1::uuid[], $2::uuid[]) AS due(tenant_id, token_family_id) \
                     WHERE target.tenant_id = due.tenant_id \
                       AND target.token_family_id = due.token_family_id \
                       AND target.current_expires_at <= CURRENT_TIMESTAMP",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&family_ids)
                .execute(connection)
                .await? as u64;
                Ok((deleted, saturated))
            })
            .await
            .map_err(map_error)
    }

    /// Delete contracts no family references, behind the in-flight-insert
    /// grace. An issuance writes the contract row and the family row in one
    /// transaction, so a committed-but-unreferenced contract is either a
    /// rolled-back remnant or a retired family's residue — both collectible.
    async fn delete_orphan_refresh_contracts(&self) -> Result<(u64, bool), RepositoryError> {
        // Wait for the process-local cursor before acquiring a pool lease.
        let mut cursor = self.contract_cursor.lock().await;
        let after = cursor.clone();
        let mut connection = self.connection().await?;
        let (deleted, saturated, next) = connection
            .build_transaction()
            .read_committed()
            .run::<_, diesel::result::Error, _>(async |connection| {
                let page = sql_query(
                    "WITH scan AS MATERIALIZED ( \
                         SELECT tenant_id, contract_blake3, created_at, \
                                COALESCE($3, CURRENT_TIMESTAMP - make_interval(secs => $2)) AS cutoff \
                         FROM oauth_refresh_contracts \
                         WHERE created_at < COALESCE($3, CURRENT_TIMESTAMP - make_interval(secs => $2)) \
                           AND (created_at, tenant_id, contract_blake3) > \
                               (COALESCE($4, '-infinity'::timestamptz), $5, $6) \
                         ORDER BY created_at, tenant_id, contract_blake3 LIMIT $1 \
                     ) \
                     SELECT scan.*, COALESCE(held.locked, FALSE) AS locked FROM scan \
                     LEFT JOIN LATERAL ( \
                         SELECT TRUE AS locked FROM oauth_refresh_contracts AS target \
                         WHERE target.tenant_id = scan.tenant_id \
                           AND target.contract_blake3 = scan.contract_blake3 \
                           AND NOT EXISTS (SELECT 1 FROM oauth_refresh_families AS family \
                                           WHERE family.tenant_id = target.tenant_id \
                                             AND family.contract_blake3 = target.contract_blake3) \
                         FOR UPDATE OF target SKIP LOCKED \
                     ) AS held ON TRUE \
                     ORDER BY scan.created_at, scan.tenant_id, scan.contract_blake3",
                )
                .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
                .bind::<sql_types::Double, _>(ORPHAN_CONTRACT_GRACE_SECONDS as f64)
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(after.as_ref().map(|row| row.cutoff))
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(after.as_ref().map(|row| row.created_at))
                .bind::<sql_types::Uuid, _>(after.as_ref().map_or(uuid::Uuid::nil(), |row| row.tenant_id))
                .bind::<sql_types::Binary, _>(after.as_ref().map_or(&[][..], |row| row.contract_blake3.as_slice()))
                .load::<ContractSweepRow>(connection)
                .await?;
                let saturated = page.len() as i64 >= CLEANUP_BATCH_LIMIT;
                // Advance past referenced and locked parents too. A fixed
                // cutoff closes this pass even as new contracts mature; a
                // short final page resets it so skipped parents are revisited.
                let next = if saturated {
                    page.last().map(|row| ContractSweepCursor {
                        cutoff: row.cutoff,
                        created_at: row.created_at,
                        tenant_id: row.tenant_id,
                        contract_blake3: row.contract_blake3.clone(),
                    })
                } else {
                    None
                };
                let locked = page.into_iter().filter(|row| row.locked).collect::<Vec<_>>();
                if locked.is_empty() {
                    return Ok((0, saturated, next));
                }
                let tenant_ids = locked.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let digests = locked.iter().map(|row| row.contract_blake3.clone()).collect::<Vec<_>>();
                // The held UPDATE locks conflict with both the writer's
                // contract-ensure KEY SHARE and family FK checks. This fresh
                // READ COMMITTED snapshot also sees references that committed
                // while the first statement was acquiring those locks.
                let deleted = sql_query(
                    "DELETE FROM oauth_refresh_contracts AS target \
                     USING UNNEST($1::uuid[], $2::bytea[]) AS due(tenant_id, contract_blake3) \
                     WHERE target.tenant_id = due.tenant_id \
                       AND target.contract_blake3 = due.contract_blake3 \
                       AND target.created_at < CURRENT_TIMESTAMP - make_interval(secs => $3) \
                       AND NOT EXISTS (SELECT 1 FROM oauth_refresh_families AS family \
                                       WHERE family.tenant_id = target.tenant_id \
                                         AND family.contract_blake3 = target.contract_blake3)",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Binary>, _>(&digests)
                .bind::<sql_types::Double, _>(ORPHAN_CONTRACT_GRACE_SECONDS as f64)
                .execute(connection)
                .await?;
                Ok((deleted as u64, saturated, next))
            })
            .await
            .map_err(map_error)?;
        // Failure or cancellation cannot advance progress past rolled-back
        // work. Losing this in-memory cursor only repeats a safe scan.
        *cursor = next;
        Ok((deleted, saturated))
    }

    async fn credential_cleanup(&self) -> Result<CredentialCleanupCounts, RepositoryError> {
        let mut cursor = self.grant_cursor.lock().await;
        let after = cursor.clone();
        let mut connection = self.connection().await?;
        // One statement handles the independent expiry categories. This also
        // avoids five empty round trips on deployments that have never enabled
        // credential issuance. Grants run afterwards, after child deletions are
        // committed, and retain ownership through verifier clock skew.
        let expired = sql_query(
            "WITH offers_due AS ( \
                     SELECT id FROM openid4vci_offers WHERE expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY expires_at, id LIMIT $1 FOR UPDATE SKIP LOCKED \
                 ), offers_deleted AS ( \
                     DELETE FROM openid4vci_offers AS target USING offers_due AS due \
                     WHERE target.id = due.id RETURNING 1 \
                 ), nonces_due AS ( \
                     SELECT nonce_hash FROM openid4vci_nonces WHERE expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY expires_at, nonce_hash LIMIT $1 FOR UPDATE SKIP LOCKED \
                 ), nonces_deleted AS ( \
                     DELETE FROM openid4vci_nonces AS target USING nonces_due AS due \
                     WHERE target.nonce_hash = due.nonce_hash RETURNING 1 \
                 ), deferred_due AS ( \
                     SELECT id FROM openid4vci_deferred_transactions WHERE expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY expires_at, id LIMIT $1 FOR UPDATE SKIP LOCKED \
                 ), deferred_deleted AS ( \
                     DELETE FROM openid4vci_deferred_transactions AS target USING deferred_due AS due \
                     WHERE target.id = due.id RETURNING 1 \
                 ), notifications_due AS ( \
                     SELECT notification_id FROM openid4vci_notifications WHERE expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY expires_at, notification_id LIMIT $1 FOR UPDATE SKIP LOCKED \
                 ), notifications_deleted AS ( \
                     DELETE FROM openid4vci_notifications AS target USING notifications_due AS due \
                     WHERE target.notification_id = due.notification_id RETURNING 1 \
                 ), responses_due AS ( \
                     SELECT issuance_id FROM openid4vci_issuance_responses WHERE expires_at <= CURRENT_TIMESTAMP \
                     ORDER BY expires_at, issuance_id LIMIT $1 FOR UPDATE SKIP LOCKED \
                 ), responses_deleted AS ( \
                     DELETE FROM openid4vci_issuance_responses AS target USING responses_due AS due \
                     WHERE target.issuance_id = due.issuance_id RETURNING 1 \
                 ) \
                 SELECT (SELECT COUNT(*) FROM offers_deleted) AS offers, \
                        (SELECT COUNT(*) FROM nonces_deleted) AS nonces, \
                        (SELECT COUNT(*) FROM deferred_deleted) AS deferred, \
                        (SELECT COUNT(*) FROM notifications_deleted) AS notifications, \
                        (SELECT COUNT(*) FROM responses_deleted) AS responses, \
                        EXISTS (SELECT 1 FROM openid4vci_access_grants \
                                WHERE expires_at <= CURRENT_TIMESTAMP - make_interval(secs => $2)) AS grants_due",
        )
        .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
        .bind::<sql_types::Double, _>(nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS as f64)
        .get_result::<CredentialExpiryCounts>(&mut connection)
        .await
        .map_err(map_error)?;
        let mut counts = CredentialCleanupCounts {
            offers: expired.offers as u64,
            nonces: expired.nonces as u64,
            deferred: expired.deferred as u64,
            notifications: expired.notifications as u64,
            responses: expired.responses as u64,
            ..CredentialCleanupCounts::default()
        };
        counts.saturated = [
            counts.offers,
            counts.nonces,
            counts.deferred,
            counts.notifications,
            counts.responses,
        ]
        .into_iter()
        .any(|count| count >= CLEANUP_BATCH_LIMIT as u64);
        if !expired.grants_due {
            *cursor = None;
            return Ok(counts);
        }
        let (grants, saturated, next) = connection
            .build_transaction()
            .read_committed()
            .run::<_, diesel::result::Error, _>(async |connection| {
                let page = sql_query(
                    "WITH scan AS MATERIALIZED ( \
                         SELECT token_id, expires_at, \
                                COALESCE($3, CURRENT_TIMESTAMP - make_interval(secs => $2)) AS cutoff \
                         FROM openid4vci_access_grants \
                         WHERE expires_at <= COALESCE($3, CURRENT_TIMESTAMP - make_interval(secs => $2)) \
                           AND (expires_at, token_id) > (COALESCE($4, '-infinity'::timestamptz), $5) \
                         ORDER BY expires_at, token_id LIMIT $1 \
                     ) \
                     SELECT scan.*, COALESCE(held.locked, FALSE) AS locked FROM scan \
                     LEFT JOIN LATERAL ( \
                         SELECT TRUE AS locked FROM openid4vci_access_grants AS target \
                         WHERE target.token_id = scan.token_id \
                           AND NOT EXISTS (SELECT 1 FROM openid4vci_deferred_transactions AS child WHERE child.token_id = target.token_id) \
                           AND NOT EXISTS (SELECT 1 FROM openid4vci_notifications AS child WHERE child.token_id = target.token_id) \
                           AND NOT EXISTS (SELECT 1 FROM openid4vci_issuance_responses AS child WHERE child.token_id = target.token_id) \
                         FOR UPDATE OF target SKIP LOCKED \
                     ) AS held ON TRUE \
                     ORDER BY scan.expires_at, scan.token_id",
                )
                .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
                .bind::<sql_types::Double, _>(nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS as f64)
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(after.as_ref().map(|row| row.cutoff))
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(after.as_ref().map(|row| row.expires_at))
                .bind::<sql_types::Uuid, _>(after.as_ref().map_or(uuid::Uuid::nil(), |row| row.token_id))
                .load::<GrantSweepRow>(connection)
                .await?;
                let saturated = page.len() as i64 >= CLEANUP_BATCH_LIMIT;
                let next = if saturated {
                    page.last().map(|row| GrantSweepCursor {
                        cutoff: row.cutoff,
                        expires_at: row.expires_at,
                        token_id: row.token_id,
                    })
                } else {
                    None
                };
                let ids = page.into_iter().filter(|row| row.locked).map(|row| row.token_id).collect::<Vec<_>>();
                if ids.is_empty() { return Ok((0, saturated, next)); }
                // FK inserts take KEY SHARE on the parent, so the held UPDATE
                // locks exclude new children. This separate READ COMMITTED
                // statement sees any child committed while candidates were
                // being acquired and leaves that parent for a later batch.
                let deleted = sql_query(
                    "DELETE FROM openid4vci_access_grants AS grant_row \
                     WHERE grant_row.token_id = ANY($1) \
                       AND grant_row.expires_at <= CURRENT_TIMESTAMP - make_interval(secs => $2) \
                       AND NOT EXISTS (SELECT 1 FROM openid4vci_deferred_transactions AS child WHERE child.token_id = grant_row.token_id) \
                       AND NOT EXISTS (SELECT 1 FROM openid4vci_notifications AS child WHERE child.token_id = grant_row.token_id) \
                       AND NOT EXISTS (SELECT 1 FROM openid4vci_issuance_responses AS child WHERE child.token_id = grant_row.token_id)",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&ids)
                .bind::<sql_types::Double, _>(nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS as f64)
                .execute(connection)
                .await?;
                Ok((deleted as u64, saturated, next))
            })
            .await
            .map_err(map_error)?;
        *cursor = next;
        counts.grants = grants;
        counts.saturated |= saturated;
        Ok(counts)
    }

    async fn connection(&self) -> Result<DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl SecurityStateMaintenancePort for SecurityStateMaintenanceRepository {
    fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
        Box::pin(async move {
            let generic = self.generic_cleanup().await?;
            let (refresh_tokens, families_saturated) =
                self.delete_expired_refresh_families().await?;
            let (spent_refresh_proofs, spent_saturated) =
                self.delete_expired_spent_proofs().await?;
            let (refresh_contracts, contracts_saturated) =
                self.delete_orphan_refresh_contracts().await?;
            let presentations = self.presentation_cleanup().await?;
            let credentials = self.credential_cleanup().await?;
            let saturated = families_saturated
                || spent_saturated
                || contracts_saturated
                || i64::from(generic.deleted_issuances) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_access_token_revocations) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_audit_events) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_backchannel_logout_deliveries) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_security_events) >= CLEANUP_BATCH_LIMIT
                || presentations >= CLEANUP_BATCH_LIMIT as u64
                || credentials.saturated;
            Ok(CleanupBatchResult {
                issuances: generic.deleted_issuances.max(0) as u64,
                refresh_tokens,
                spent_refresh_proofs,
                refresh_contracts,
                revocations: generic.deleted_access_token_revocations.max(0) as u64,
                scim_audit_events: generic.deleted_scim_audit_events.max(0) as u64,
                logout_deliveries: generic.deleted_backchannel_logout_deliveries.max(0) as u64,
                scim_security_events: generic.deleted_scim_security_events.max(0) as u64,
                presentations,
                credential_offers: credentials.offers,
                credential_nonces: credentials.nonces,
                credential_access_grants: credentials.grants,
                deferred_credentials: credentials.deferred,
                credential_notifications: credentials.notifications,
                credential_responses: credentials.responses,
                saturated,
            })
        })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
