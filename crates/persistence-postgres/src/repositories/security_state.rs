//! Bounded security-state maintenance.
//!
//! One batch per `cleanup_batch` call:
//! 1. `nazo_oauth_cleanup_expired_security_state()` — issuances, access-token
//!    revocations, SCIM audit events, backchannel logout deliveries and SCIM
//!    security events (256 rows each).
//! 2. Refresh-token leaf reclaim — fully expired families, per-family
//!    transactions under the shared advisory key (`family → token`).
//! 3. `nazo_openid4vp_cleanup_expired_transactions()` — expired presentations.
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
struct ExpiredLeafCandidate {
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

    /// Reclaim expired refresh-token leaves whose whole family is expired.
    ///
    /// Candidates: expired leaf rows (no child) in families with no unexpired
    /// member. One short transaction per family; `pg_try_advisory_xact_lock`
    /// shares the writer key so an active rotation skips the family. The
    /// no-unexpired-member recheck inside the lock closes the race where a
    /// new successor was committed after the candidate scan.
    async fn reclaim_refresh_token_leaves(&self) -> Result<u64, RepositoryError> {
        let cutoff = Utc::now();
        let mut scan = self.connection().await?;
        let candidates = sql_query(
            "SELECT target.tenant_id, target.token_family_id \
             FROM oauth_tokens AS target \
             WHERE target.expires_at <= $1 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM oauth_tokens AS child \
                   WHERE child.rotated_from_id = target.id) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM oauth_tokens AS member \
                   WHERE member.token_family_id = target.token_family_id \
                     AND member.expires_at > $1) \
             ORDER BY target.expires_at, target.id \
             LIMIT 256",
        )
        .bind::<sql_types::Timestamptz, _>(cutoff)
        .load::<ExpiredLeafCandidate>(&mut scan)
        .await
        .map_err(map_error)?;
        drop(scan);

        let mut families: Vec<(Uuid, Uuid)> = Vec::new();
        for candidate in candidates {
            let key = (candidate.tenant_id, candidate.token_family_id);
            if !families.contains(&key) {
                if families.len() >= FAMILY_LIMIT_PER_ROUND {
                    break;
                }
                families.push(key);
            }
        }
        if families.is_empty() {
            return Ok(0);
        }

        // One guarded connection carries every short family transaction. A
        // completed transaction returns it cleanly; a dropped or failed one
        // discards the physical connection instead of pooling an open
        // transaction.
        let mut guard = DiscardOnDrop(Some(self.connection().await?));
        let mut deleted = 0_u64;
        for (tenant_id, family_id) in families {
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
                    let removed = sql_query(
                        "WITH leaf AS ( \
                             SELECT id FROM oauth_tokens \
                             WHERE tenant_id = $1 AND token_family_id = $2 \
                               AND expires_at <= $3 \
                               AND NOT EXISTS ( \
                                   SELECT 1 FROM oauth_tokens AS child \
                                   WHERE child.rotated_from_id = oauth_tokens.id) \
                             ORDER BY expires_at, id \
                             LIMIT $4 FOR UPDATE SKIP LOCKED \
                         ) \
                         DELETE FROM oauth_tokens AS target \
                         USING leaf WHERE target.id = leaf.id",
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
        Ok(deleted)
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
            let refresh_tokens = self.reclaim_refresh_token_leaves().await?;
            let presentations = self.presentation_cleanup().await?;
            Ok(CleanupBatchResult {
                issuances: generic.deleted_issuances.max(0) as u64,
                refresh_tokens,
                revocations: generic.deleted_access_token_revocations.max(0) as u64,
                scim_audit_events: generic.deleted_scim_audit_events.max(0) as u64,
                logout_deliveries: generic.deleted_backchannel_logout_deliveries.max(0) as u64,
                scim_security_events: generic.deleted_scim_security_events.max(0) as u64,
                presentations,
            })
        })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
