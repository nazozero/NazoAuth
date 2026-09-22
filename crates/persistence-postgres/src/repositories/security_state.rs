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
//!
//! Every category is a bounded batch (≤256 rows) on a single row per
//! authority; there is no member-history traversal. Family reclaim keeps the
//! shared advisory key: a writer holding `refresh_family_lock_key` causes the
//! candidate to be skipped this round, and expiry is rechecked under the lock
//! so a just-rotated family is never reclaimed mid-commit. Audit-ledger rows
//! are not a maintenance category: the
//! exporter's ACK removes the delivered event, chain-entry and outbox rows in
//! the same transaction that advances the durable anchor checkpoint, so
//! nothing accumulates for a sweeper to reclaim and no local archive copy
//! exists — the receiver is the sole authoritative audit history.

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
        use diesel::{ExpressionMethods, QueryDsl};
        use diesel_async::AsyncConnection;

        #[derive(QueryableByName)]
        struct ExpiredFamily {
            #[diesel(sql_type = sql_types::Uuid)]
            tenant_id: uuid::Uuid,
            #[diesel(sql_type = sql_types::Uuid)]
            token_family_id: uuid::Uuid,
        }
        #[derive(QueryableByName)]
        struct LockRow {
            #[diesel(sql_type = sql_types::Bool)]
            acquired: bool,
        }

        let mut connection = self.connection().await?;
        connection
            .transaction::<(u64, bool), diesel::result::Error, _>(async |connection| {
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
                let mut deleted = 0_u64;
                for family in due {
                    let acquired = sql_query(
                        "SELECT pg_try_advisory_xact_lock($1) AS acquired",
                    )
                    .bind::<sql_types::BigInt, _>(super::tokens::refresh_family_lock_key(
                        family.token_family_id,
                    ))
                    .get_result::<LockRow>(connection)
                    .await?
                    .acquired;
                    if !acquired {
                        continue;
                    }
                    deleted += diesel::delete(
                        crate::schema::oauth_refresh_families::table
                            .filter(
                                crate::schema::oauth_refresh_families::tenant_id
                                    .eq(family.tenant_id),
                            )
                            .filter(
                                crate::schema::oauth_refresh_families::token_family_id
                                    .eq(family.token_family_id),
                            )
                            .filter(
                                crate::schema::oauth_refresh_families::current_expires_at
                                    .le(diesel::dsl::now),
                            ),
                    )
                    .execute(connection)
                    .await? as u64;
                }
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
        let mut connection = self.connection().await?;
        let deleted = sql_query(
            "WITH due AS ( \
                 SELECT c.tenant_id, c.contract_blake3 \
                 FROM oauth_refresh_contracts AS c \
                 WHERE c.created_at < CURRENT_TIMESTAMP - make_interval(secs => $2) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM oauth_refresh_families AS f \
                       WHERE f.tenant_id = c.tenant_id \
                         AND f.contract_blake3 = c.contract_blake3) \
                 ORDER BY c.created_at, c.contract_blake3 \
                 LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_refresh_contracts AS target \
             USING due \
             WHERE target.tenant_id = due.tenant_id \
               AND target.contract_blake3 = due.contract_blake3",
        )
        .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
        .bind::<sql_types::Double, _>(ORPHAN_CONTRACT_GRACE_SECONDS as f64)
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        Ok((deleted as u64, deleted as i64 >= CLEANUP_BATCH_LIMIT))
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
            let saturated = families_saturated
                || spent_saturated
                || contracts_saturated
                || i64::from(generic.deleted_issuances) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_access_token_revocations) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_audit_events) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_backchannel_logout_deliveries) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_security_events) >= CLEANUP_BATCH_LIMIT
                || presentations >= CLEANUP_BATCH_LIMIT as u64;
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
                saturated,
            })
        })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
