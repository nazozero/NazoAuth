//! Bounded security-state maintenance.
//!
//! One batch per `cleanup_batch` call:
//! 1. `nazo_oauth_cleanup_expired_security_state()` — issuances, access-token
//!    revocations, SCIM audit events, backchannel logout deliveries and SCIM
//!    security events (256 rows each).
//! 2. Refresh-token family reclaim — fully expired families, per-family
//!    transactions under the shared advisory key (`family → token`).
//! 3. `nazo_openid4vp_cleanup_expired_transactions()` — expired presentations.
//!
//! There is no second family lock domain and no grant-scope lock here; a
//! writer holding the family advisory lock causes that family to be skipped
//! this round and reclaimed on a later one. Audit-ledger rows are not a
//! maintenance category: the exporter's ACK removes the delivered event,
//! chain-entry and outbox rows in the same transaction that advances the
//! durable anchor checkpoint, so nothing accumulates for a sweeper to
//! reclaim and no local archive copy exists — the receiver is the sole
//! authoritative audit history.

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

/// A rotated member becomes a terminal stub only after the lost-response
/// successor edge can no longer matter: retries resolve the direct successor
/// within `LOST_REFRESH_TOKEN_RETRY_SECONDS` of the parent's revocation.
const TERMINAL_SPARSE_GRACE_SECONDS: i64 = super::tokens::LOST_REFRESH_TOKEN_RETRY_SECONDS;

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

    /// Rewrite dead members of still-live families to their terminal stub.
    ///
    /// A member qualifies only when it is expired AND its revocation is older
    /// than the lost-response window: it can never again be a rotation parent
    /// (rotation requires an unrevoked row), a lost-response successor (the
    /// successor must be unrevoked and unexpired), or a usable presentation
    /// (the endpoint rejects expired tokens before consulting context). The
    /// stub keeps only the hash-to-family mapping so reuse detection and
    /// family compromise still resolve; `rotated_from_id` is cleared so dead
    /// chains stop contributing traversal edges. Bounded, SKIP LOCKED, and
    /// independent of the family advisory lock because every candidate is a
    /// row no writer can legally transition.
    async fn sparsify_terminal_refresh_members(&self) -> Result<(u64, bool), RepositoryError> {
        let now = Utc::now();
        let grace_horizon = now - chrono::Duration::seconds(TERMINAL_SPARSE_GRACE_SECONDS);
        let mut connection = self.connection().await?;
        let rewritten = sql_query(
            "WITH candidates AS (                  SELECT id FROM oauth_tokens                  WHERE sparsified_at IS NULL                    AND revoked_at IS NOT NULL                    AND revoked_at <= $1                    AND expires_at <= $2                  ORDER BY expires_at, id                  LIMIT $3                  FOR UPDATE SKIP LOCKED              )              UPDATE oauth_tokens AS target              SET rotated_from_id = NULL,                  scopes = '[]'::jsonb,                  audience = '[]'::jsonb,                  authorization_details = '[]'::jsonb,                  subject = '',                  oidc_auth_context = 'null'::jsonb,                  dpop_jkt = NULL,                  mtls_x5t_s256 = NULL,                  client_attestation_jkt = NULL,                  sparsified_at = $2              FROM candidates              WHERE target.id = candidates.id",
        )
        .bind::<sql_types::Timestamptz, _>(grace_horizon)
        .bind::<sql_types::Timestamptz, _>(now)
        .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        Ok((rewritten as u64, rewritten as i64 >= CLEANUP_BATCH_LIMIT))
    }

    /// Reclaim refresh-token rows in families whose whole membership expired.
    ///
    /// Candidates are distinct `(tenant_id, token_family_id)` families with no
    /// unexpired member — the tenant is part of the family authority boundary
    /// because `token_family_id` is only unique per tenant. One short
    /// transaction per family: `pg_try_advisory_xact_lock` shares the writer
    /// key so an active rotation skips the family, the tenant-scoped
    /// no-unexpired-member recheck inside the lock closes the race where a
    /// new successor was committed after the scan, and each batch deletes a
    /// bounded descendant-closed slice of the family instead of unlinking the
    /// whole family up front.
    async fn reclaim_expired_refresh_families(&self) -> Result<(u64, bool), RepositoryError> {
        let cutoff = Utc::now();
        let mut scan = self.connection().await?;
        // The NOT EXISTS must inspect the whole family within the same tenant,
        // so it stays outside the expired-member prefilter: a family with any
        // unexpired member is never a candidate, and an identically named
        // family in another tenant cannot suppress or satisfy the check. The
        // in-lock recheck below still guards the race where a successor
        // commits after this scan.
        let families = sql_query(
            "SELECT target.tenant_id, target.token_family_id \
             FROM oauth_tokens AS target \
             WHERE target.expires_at <= $1 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM oauth_tokens AS member \
                   WHERE member.tenant_id = target.tenant_id \
                     AND member.token_family_id = target.token_family_id \
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
                    // The advisory key spans family ids without a tenant
                    // component: writers and maintenance share one lock domain
                    // so a same-named family in another tenant only serializes,
                    // never leaks. Keeping the key unchanged avoids opening a
                    // second lock domain for any writer.
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
                             WHERE tenant_id = $1 \
                               AND token_family_id = $2 \
                               AND expires_at > $3) AS flag",
                    )
                    .bind::<sql_types::Uuid, _>(tenant_id)
                    .bind::<sql_types::Uuid, _>(family_id)
                    .bind::<sql_types::Timestamptz, _>(cutoff)
                    .get_result::<FlagRow>(connection)
                    .await?;
                    if !still_expired.flag {
                        return Ok(0);
                    }
                    // Bounded descendant-first reclaim, two statements inside
                    // the family lock. First a bounded unlink clears
                    // `rotated_from_id` on up to `remaining` members outside
                    // the delete slice that still reference into it — a
                    // separate statement so the delete below can actually see
                    // which referrers survived. Then a closed-set delete
                    // removes up to `remaining` doomed rows: `blocked` marks
                    // every doomed member that a surviving referrer still
                    // points at (directly, or transitively through another
                    // blocked member), so the deleted slice is always
                    // descendant-closed and the self-FK can never dangle.
                    // Every batch performs at most `remaining` UPDATEs plus
                    // `remaining` DELETEs regardless of family size.
                    //
                    // Candidate ordering guarantees progress: newest rows
                    // first keeps long chains draining ~`remaining` rows per
                    // batch (children always outlive their parent's issued_at
                    // in real data), and the leaf-existence tiebreak ensures
                    // the top slice always contains at least one referrerless
                    // member even under pathological timestamp ties, so a
                    // batch can never select 256 permanently-blocked rows.
                    sql_query(
                        "WITH doomed AS ( \
                             SELECT target.id FROM oauth_tokens AS target \
                             WHERE target.tenant_id = $1 AND target.token_family_id = $2 \
                               AND target.expires_at <= $3 \
                             ORDER BY target.issued_at DESC, \
                                 EXISTS ( \
                                     SELECT 1 FROM oauth_tokens AS child \
                                     WHERE child.tenant_id = $1 \
                                       AND child.token_family_id = $2 \
                                       AND child.rotated_from_id = target.id), \
                                 target.id DESC \
                             LIMIT $4 FOR UPDATE SKIP LOCKED \
                         ), outside_refs AS ( \
                             SELECT orphan.id FROM oauth_tokens AS orphan \
                             WHERE orphan.tenant_id = $1 \
                               AND orphan.token_family_id = $2 \
                               AND orphan.rotated_from_id IN (SELECT id FROM doomed) \
                               AND orphan.id NOT IN (SELECT id FROM doomed) \
                             LIMIT $4 FOR UPDATE SKIP LOCKED \
                         ) \
                         UPDATE oauth_tokens AS orphan \
                         SET rotated_from_id = NULL \
                         FROM outside_refs \
                         WHERE orphan.id = outside_refs.id",
                    )
                    .bind::<sql_types::Uuid, _>(tenant_id)
                    .bind::<sql_types::Uuid, _>(family_id)
                    .bind::<sql_types::Timestamptz, _>(cutoff)
                    .bind::<sql_types::BigInt, _>(remaining)
                    .execute(connection)
                    .await?;
                    let removed = sql_query(
                        "WITH RECURSIVE doomed AS ( \
                             SELECT target.id FROM oauth_tokens AS target \
                             WHERE target.tenant_id = $1 AND target.token_family_id = $2 \
                               AND target.expires_at <= $3 \
                             ORDER BY target.issued_at DESC, \
                                 EXISTS ( \
                                     SELECT 1 FROM oauth_tokens AS child \
                                     WHERE child.tenant_id = $1 \
                                       AND child.token_family_id = $2 \
                                       AND child.rotated_from_id = target.id), \
                                 target.id DESC \
                             LIMIT $4 FOR UPDATE SKIP LOCKED \
                         ), blocked(id) AS ( \
                             SELECT d.id FROM doomed AS d \
                             WHERE EXISTS ( \
                                 SELECT 1 FROM oauth_tokens AS referrer \
                                 WHERE referrer.rotated_from_id = d.id \
                                   AND referrer.id NOT IN (SELECT id FROM doomed)) \
                             UNION \
                             SELECT target.id FROM oauth_tokens AS target \
                             JOIN oauth_tokens AS child \
                               ON child.rotated_from_id = target.id \
                             JOIN blocked ON blocked.id = child.id \
                             WHERE target.id IN (SELECT id FROM doomed) \
                         ) \
                         DELETE FROM oauth_tokens AS target \
                         USING doomed \
                         WHERE target.id = doomed.id \
                           AND target.id NOT IN (SELECT id FROM blocked)",
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
            let (sparsified_refresh_members, sparse_saturated) =
                self.sparsify_terminal_refresh_members().await?;
            let presentations = self.presentation_cleanup().await?;
            let saturated = refresh_saturated
                || sparse_saturated
                || i64::from(generic.deleted_issuances) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_access_token_revocations) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_audit_events) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_backchannel_logout_deliveries) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_security_events) >= CLEANUP_BATCH_LIMIT
                || presentations >= CLEANUP_BATCH_LIMIT as u64;
            Ok(CleanupBatchResult {
                issuances: generic.deleted_issuances.max(0) as u64,
                refresh_tokens,
                revocations: generic.deleted_access_token_revocations.max(0) as u64,
                scim_audit_events: generic.deleted_scim_audit_events.max(0) as u64,
                logout_deliveries: generic.deleted_backchannel_logout_deliveries.max(0) as u64,
                scim_security_events: generic.deleted_scim_security_events.max(0) as u64,
                presentations,
                sparsified_refresh_members,
                saturated,
            })
        })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
