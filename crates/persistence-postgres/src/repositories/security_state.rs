//! Bounded security-state maintenance.
//!
//! One batch per `cleanup_batch` call:
//! 1. `nazo_oauth_cleanup_expired_security_state()` — issuances, access-token
//!    revocations, SCIM audit events, backchannel logout deliveries and SCIM
//!    security events (256 rows each).
//! 2. Refresh-token family reclaim — fully expired families, per-family
//!    transactions under the shared advisory key (`family → token`).
//! 3. `nazo_openid4vp_cleanup_expired_transactions()` — expired presentations.
//! 4. `nazo_cleanup_exported_security_audit_outbox()` — exported audit-outbox
//!    delivery rows past their short observability grace period.
//!
//! There is no second family lock domain and no grant-scope lock here; a
//! writer holding the family advisory lock causes that family to be skipped
//! this round and reclaimed on a later one.

use chrono::Utc;
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{
    CleanupBatchResult, SecurityStateMaintenanceFuture, SecurityStateMaintenancePort,
};
use uuid::Uuid;

use crate::{DbConnection, DbPool, get_conn, pool::DiscardOnDrop};

use super::tokens::refresh_family_lock_key;

/// Per-category row budget per batch (matches the SQL function contract).
const CLEANUP_BATCH_LIMIT: i64 = 256;
/// Maximum distinct refresh families visited in one batch.
const FAMILY_LIMIT_PER_ROUND: usize = 256;

#[derive(Clone)]
pub struct SecurityStateMaintenanceRepository {
    pool: DbPool,
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
struct AuditOutboxCleanupCount {
    #[diesel(sql_type = sql_types::Integer)]
    deleted: i32,
}

#[derive(QueryableByName)]
struct ExpiredFamilyCandidate {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    token_family_id: Uuid,
}

#[derive(QueryableByName)]
struct FlagRow {
    #[diesel(sql_type = sql_types::Bool)]
    flag: bool,
}

impl SecurityStateMaintenanceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
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

    /// Reclaim exported audit-outbox delivery rows past their grace period.
    ///
    /// The outbox row is delivery bookkeeping for the exporter; the immutable
    /// `security_audit_events` record remains the evidence. Runtime roles hold
    /// no direct outbox privilege, so reclamation goes through the
    /// `SECURITY DEFINER` function owned by the migration owner.
    async fn audit_outbox_cleanup(&self) -> Result<u64, RepositoryError> {
        let mut connection = self.connection().await?;
        let count = sql_query(
            "SELECT public.nazo_cleanup_exported_security_audit_outbox() AS deleted",
        )
        .get_result::<AuditOutboxCleanupCount>(&mut connection)
        .await
        .map_err(map_error)?;
        Ok(count.deleted.max(0) as u64)
    }

    /// Reclaim refresh-token rows in families whose whole membership expired.
    ///
    /// Candidates are distinct families with no unexpired member, oldest
    /// family expiry first. One short transaction per family:
    /// `pg_try_advisory_xact_lock` shares the writer key so an active rotation
    /// skips the family, the no-unexpired-member recheck inside the lock
    /// closes the race where a new successor was committed after the scan, and
    /// the unlink step clears `rotated_from_id` references into the family so
    /// a bounded delete can remove every expired member in one pass instead of
    /// peeling one leaf per round.
    async fn reclaim_expired_refresh_families(&self) -> Result<(u64, bool), RepositoryError> {
        let cutoff = Utc::now();
        let mut scan = self.connection().await?;
        // The NOT EXISTS must inspect the whole family, so it stays outside
        // the expired-member prefilter: a family with any unexpired member is
        // never a candidate. The in-lock recheck below still guards the race
        // where a successor commits after this scan.
        let families = sql_query(
            "SELECT target.tenant_id, target.token_family_id \
             FROM oauth_tokens AS target \
             WHERE target.expires_at <= $1 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM oauth_tokens AS member \
                   WHERE member.token_family_id = target.token_family_id \
                     AND member.expires_at > $1) \
             GROUP BY target.tenant_id, target.token_family_id \
             ORDER BY MIN(target.expires_at), target.token_family_id \
             LIMIT $2",
        )
        .bind::<sql_types::Timestamptz, _>(cutoff)
        .bind::<sql_types::BigInt, _>(FAMILY_LIMIT_PER_ROUND as i64)
        .load::<ExpiredFamilyCandidate>(&mut scan)
        .await
        .map_err(map_error)?;
        let scan_saturated = families.len() >= FAMILY_LIMIT_PER_ROUND;
        drop(scan);

        if families.is_empty() {
            return Ok((0, scan_saturated));
        }

        // One guarded connection carries every short family transaction. A
        // completed transaction returns it cleanly; a dropped or failed one
        // discards the physical connection instead of pooling an open
        // transaction.
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let mut deleted = 0_u64;
        for candidate in &families {
            let tenant_id = candidate.tenant_id;
            let family_id = candidate.token_family_id;
            let remaining = CLEANUP_BATCH_LIMIT.saturating_sub(deleted as i64);
            if remaining <= 0 {
                break;
            }
            let outcome = guard
                .connection()
                .transaction::<u64, diesel::result::Error, _>(async |connection| {
                    let locked = sql_query("SELECT pg_try_advisory_xact_lock($1) AS flag")
                        .bind::<sql_types::BigInt, _>(refresh_family_lock_key(family_id))
                        .get_result::<FlagRow>(connection)
                        .await?;
                    if !locked.flag {
                        return Ok(0);
                    }
                    let still_expired = sql_query(
                        "SELECT NOT EXISTS ( \
                             SELECT 1 FROM oauth_tokens \
                             WHERE token_family_id = $1 \
                               AND expires_at > $2) AS flag",
                    )
                    .bind::<sql_types::Uuid, _>(family_id)
                    .bind::<sql_types::Timestamptz, _>(cutoff)
                    .get_result::<FlagRow>(connection)
                    .await?;
                    if !still_expired.flag {
                        return Ok(0);
                    }
                    // Unlink every reference into this family before deleting;
                    // `rotated_from_id` is a non-deferrable foreign key, so a
                    // whole-family delete fails while any row still points at
                    // a doomed member. Rotation only links inside a family and
                    // holds this advisory key, so under the lock the set of
                    // inbound references is fixed.
                    sql_query(
                        "UPDATE oauth_tokens SET rotated_from_id = NULL \
                         WHERE rotated_from_id IN ( \
                             SELECT id FROM oauth_tokens \
                             WHERE token_family_id = $1)",
                    )
                    .bind::<sql_types::Uuid, _>(family_id)
                    .execute(connection)
                    .await?;
                    let removed = sql_query(
                        "WITH doomed AS ( \
                             SELECT id FROM oauth_tokens \
                             WHERE tenant_id = $1 AND token_family_id = $2 \
                               AND expires_at <= $3 \
                             ORDER BY expires_at, id \
                             LIMIT $4 FOR UPDATE SKIP LOCKED \
                         ) \
                         DELETE FROM oauth_tokens AS target \
                         USING doomed WHERE target.id = doomed.id",
                    )
                    .bind::<sql_types::Uuid, _>(tenant_id)
                    .bind::<sql_types::Uuid, _>(family_id)
                    .bind::<sql_types::Timestamptz, _>(cutoff)
                    .bind::<sql_types::BigInt, _>(remaining)
                    .execute(connection)
                    .await?;
                    Ok(removed as u64)
                })
                .await;
            match outcome {
                Ok(removed) => deleted += removed,
                Err(error) => {
                    // The dropped transaction discards the connection via
                    // DiscardOnDrop; the batch fails and retries next cycle.
                    return Err(map_error(error));
                }
            }
        }
        guard.return_to_pool();
        // The scan limit means more families may wait; the row budget means
        // visited families or unvisited candidates still hold expired rows.
        let saturated = scan_saturated || deleted >= CLEANUP_BATCH_LIMIT as u64;
        Ok((deleted, saturated))
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
            let (refresh_tokens, refresh_saturated) =
                self.reclaim_expired_refresh_families().await?;
            let presentations = self.presentation_cleanup().await?;
            let audit_outbox_rows = self.audit_outbox_cleanup().await?;
            let saturated = refresh_saturated
                || i64::from(generic.deleted_issuances) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_access_token_revocations) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_audit_events) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_backchannel_logout_deliveries)
                    >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_security_events) >= CLEANUP_BATCH_LIMIT
                || presentations >= CLEANUP_BATCH_LIMIT as u64
                || audit_outbox_rows >= CLEANUP_BATCH_LIMIT as u64;
            Ok(CleanupBatchResult {
                issuances: generic.deleted_issuances.max(0) as u64,
                refresh_tokens,
                revocations: generic.deleted_access_token_revocations.max(0) as u64,
                scim_audit_events: generic.deleted_scim_audit_events.max(0) as u64,
                logout_deliveries: generic.deleted_backchannel_logout_deliveries.max(0) as u64,
                scim_security_events: generic.deleted_scim_security_events.max(0) as u64,
                presentations,
                audit_outbox_rows,
                saturated,
            })
        })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
