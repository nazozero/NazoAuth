//! Bounded security-state maintenance.
//!
//! One batch per `cleanup_batch` call:
//! 1. `nazo_oauth_cleanup_expired_security_state()` — issuances, access-token
//!    revocations, SCIM audit events, backchannel logout deliveries and SCIM
//!    security events (256 rows each).
//! 2. Refresh spent proofs — deleted at their own `expires_at`; the proof
//!    only has readers inside the token's acceptance window, so expiry makes
//!    "present" and "absent" indistinguishable (`invalid_grant` either way).
//! 3. Refresh families — terminal families are revoked or expired. Their
//!    spent proofs are drained under the family lock with one global 256-row
//!    budget per call; a parent is deleted only after its proofs are gone.
//! 4. Orphaned refresh contracts — deleted under parent row locks once no
//!    family references them. Issuance holds KEY SHARE through its commit.
//! 5. `nazo_openid4vp_cleanup_expired_transactions()` — expired presentations.
//! 6. OpenID4VCI offer, nonce, deferred, notification and response expiry;
//!    access-grant ownership is retained through verifier clock skew and until
//!    its children have been reclaimed in their own bounded batches.
//!
//! Every category is bounded (≤256 rows); there is no member-history
//! traversal. Family reclaim takes the writer's exclusive advisory key with a
//! try-lock; a PreserveExisting shared lock skips that candidate. Terminal
//! state is rechecked under the lock so a just-rotated family survives.
//! Ordinary audit
//! events and chain entries leave at exporter ACK. Authorization decisions
//! also own business consumption fences, so a bounded maintenance category
//! reclaims them only after export AND business retention have completed.

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
struct DecisionCleanupCount {
    #[diesel(sql_type = sql_types::BigInt)]
    deleted: i64,
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

    async fn decision_cleanup(&self) -> Result<u64, RepositoryError> {
        let mut connection = self.connection().await?;
        let row = sql_query("SELECT public.nazo_cleanup_authorization_decisions() AS deleted")
            .get_result::<DecisionCleanupCount>(&mut connection)
            .await
            .map_err(map_error)?;
        debug_assert!((0..=CLEANUP_BATCH_LIMIT).contains(&row.deleted));
        Ok(row.deleted.max(0) as u64)
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
                 ORDER BY expires_at \
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

    /// Reclaim terminal families under their writer advisory key. Each call
    /// deletes at most proof_budget spent proofs across all families, and a
    /// parent is removed only after no spent proofs remain. The fresh
    /// READ COMMITTED row-lock statement rechecks expiry after the advisory
    /// try-lock, so a just-rotated family is never reclaimed mid-commit.
    async fn delete_expired_refresh_families(
        &self,
        proof_budget: i64,
    ) -> Result<(u64, u64, bool), RepositoryError> {
        #[derive(QueryableByName)]
        struct FamilyId {
            #[diesel(sql_type = sql_types::Uuid)]
            tenant_id: uuid::Uuid,
            #[diesel(sql_type = sql_types::Uuid)]
            token_family_id: uuid::Uuid,
        }
        let mut connection = self.connection().await?;
        connection
            .build_transaction()
            .read_committed()
            .run::<(u64, u64, bool), diesel::result::Error, _>(async |connection| {
                // Each terminal class is an index-backed bounded scan. The
                // union has at most twice the family batch before its final cap.
                let candidates = sql_query(
                    "WITH expired AS MATERIALIZED ( \
                         SELECT tenant_id, token_family_id \
                         FROM oauth_refresh_families \
                         WHERE current_expires_at <= CURRENT_TIMESTAMP \
                         ORDER BY current_expires_at \
                         LIMIT $1 \
                     ), revoked AS MATERIALIZED ( \
                         SELECT tenant_id, token_family_id \
                         FROM oauth_refresh_families \
                         WHERE revoked_at IS NOT NULL \
                         ORDER BY revoked_at, tenant_id, token_family_id \
                         LIMIT $1 \
                     ), due AS MATERIALIZED ( \
                         SELECT tenant_id, token_family_id FROM expired \
                         UNION \
                         SELECT tenant_id, token_family_id FROM revoked \
                     ) \
                     SELECT tenant_id, token_family_id FROM due \
                     ORDER BY tenant_id, token_family_id LIMIT $1",
                )
                .bind::<sql_types::BigInt, _>(CLEANUP_BATCH_LIMIT)
                .load::<FamilyId>(connection)
                .await?;
                let candidate_saturated = candidates.len() as i64 >= CLEANUP_BATCH_LIMIT;
                if candidates.is_empty() {
                    return Ok((0, 0, false));
                }

                let tenant_ids = candidates
                    .iter()
                    .map(|row| row.tenant_id)
                    .collect::<Vec<_>>();
                let family_ids = candidates
                    .iter()
                    .map(|row| row.token_family_id)
                    .collect::<Vec<_>>();
                let lock_keys = family_ids
                    .iter()
                    .map(|id| super::tokens::refresh_family_lock_key(*id))
                    .collect::<Vec<_>>();
                // Match issuance/revocation locking. PreserveExisting's shared
                // lock makes this exclusive try-lock fail without waiting.
                let locked = sql_query(
                    "SELECT tenant_id, token_family_id \
                     FROM UNNEST($1::uuid[], $2::uuid[], $3::bigint[]) \
                          AS due(tenant_id, token_family_id, lock_key) \
                     WHERE pg_try_advisory_xact_lock(lock_key)",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&family_ids)
                .bind::<sql_types::Array<sql_types::BigInt>, _>(&lock_keys)
                .load::<FamilyId>(connection)
                .await?;
                if locked.is_empty() {
                    return Ok((0, 0, candidate_saturated));
                }

                let tenant_ids = locked.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let family_ids = locked
                    .iter()
                    .map(|row| row.token_family_id)
                    .collect::<Vec<_>>();
                // This separate statement gets a fresh READ COMMITTED snapshot
                // after advisory locks, rechecks terminal state, and skips
                // parent rows held by another cleanup transaction.
                let terminal = sql_query(
                    "SELECT family.tenant_id, family.token_family_id \
                     FROM oauth_refresh_families AS family \
                     JOIN UNNEST($1::uuid[], $2::uuid[]) \
                          AS due(tenant_id, token_family_id) \
                       ON family.tenant_id = due.tenant_id \
                      AND family.token_family_id = due.token_family_id \
                     WHERE family.current_expires_at <= CURRENT_TIMESTAMP \
                        OR family.revoked_at IS NOT NULL \
                     ORDER BY family.tenant_id, family.token_family_id \
                     FOR UPDATE OF family SKIP LOCKED",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&family_ids)
                .load::<FamilyId>(connection)
                .await?;
                if terminal.is_empty() {
                    return Ok((0, 0, candidate_saturated));
                }

                let terminal_tenants = terminal.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let terminal_families = terminal
                    .iter()
                    .map(|row| row.token_family_id)
                    .collect::<Vec<_>>();
                // LATERAL probes ix_orst_family for each locked parent. The
                // outer LIMIT is global, so this never becomes 256 proofs per
                // family. Child locks and deletes share this transaction.
                let deleted_proofs = sql_query(
                    "WITH limited_proofs AS MATERIALIZED ( \
                         SELECT proof.tenant_id, proof.refresh_token_blake3 \
                         FROM UNNEST($1::uuid[], $2::uuid[]) \
                              AS family(tenant_id, token_family_id) \
                         CROSS JOIN LATERAL ( \
                             SELECT spent.tenant_id, spent.refresh_token_blake3 \
                             FROM oauth_refresh_spent_tokens AS spent \
                             WHERE spent.tenant_id = family.tenant_id \
                               AND spent.token_family_id = family.token_family_id \
                             LIMIT $3 FOR UPDATE OF spent SKIP LOCKED \
                         ) AS proof \
                         LIMIT $3 \
                     ) \
                     DELETE FROM oauth_refresh_spent_tokens AS target \
                     USING limited_proofs AS due \
                     WHERE target.tenant_id = due.tenant_id \
                       AND target.refresh_token_blake3 = due.refresh_token_blake3",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&terminal_tenants)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&terminal_families)
                .bind::<sql_types::BigInt, _>(proof_budget)
                .execute(connection)
                .await? as u64;

                // Child existence, not the prior candidate snapshot, decides
                // whether each parent may now be deleted without a cascade.
                let deleted_families = sql_query(
                    "DELETE FROM oauth_refresh_families AS target \
                     USING UNNEST($1::uuid[], $2::uuid[]) AS due(tenant_id, token_family_id) \
                     WHERE target.tenant_id = due.tenant_id \
                       AND target.token_family_id = due.token_family_id \
                       AND NOT EXISTS ( \
                           SELECT 1 FROM oauth_refresh_spent_tokens AS spent \
                           WHERE spent.tenant_id = target.tenant_id \
                             AND spent.token_family_id = target.token_family_id \
                       )",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&terminal_tenants)
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&terminal_families)
                .execute(connection)
                .await? as u64;

                // Any locked parent not deleted still had proofs at the
                // DELETE snapshot. A concurrent expiry sweep may make this
                // conservatively request one extra pass.
                let families_remain = deleted_families < terminal.len() as u64;
                Ok((
                    deleted_families,
                    deleted_proofs,
                    candidate_saturated || families_remain,
                ))
            })
            .await
            .map_err(map_error)
    }

    /// Delete unreferenced contracts under the parent UPDATE lock. Issuance
    /// creates the contract and family in one transaction, or holds KEY SHARE
    /// on an existing contract until its family reference commits.
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
                                COALESCE($2, CURRENT_TIMESTAMP) AS cutoff \
                         FROM oauth_refresh_contracts \
                         WHERE created_at < COALESCE($2, CURRENT_TIMESTAMP) \
                           AND (created_at, tenant_id, contract_blake3) > \
                               (COALESCE($3, '-infinity'::timestamptz), $4, $5) \
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
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(
                    after.as_ref().map(|row| row.cutoff),
                )
                .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(
                    after.as_ref().map(|row| row.created_at),
                )
                .bind::<sql_types::Uuid, _>(
                    after
                        .as_ref()
                        .map_or(uuid::Uuid::nil(), |row| row.tenant_id),
                )
                .bind::<sql_types::Binary, _>(
                    after
                        .as_ref()
                        .map_or(&[][..], |row| row.contract_blake3.as_slice()),
                )
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
                let locked = page
                    .into_iter()
                    .filter(|row| row.locked)
                    .collect::<Vec<_>>();
                if locked.is_empty() {
                    return Ok((0, saturated, next));
                }
                let tenant_ids = locked.iter().map(|row| row.tenant_id).collect::<Vec<_>>();
                let digests = locked
                    .iter()
                    .map(|row| row.contract_blake3.clone())
                    .collect::<Vec<_>>();
                // The held UPDATE locks conflict with both the writer's
                // contract-ensure KEY SHARE and family FK checks. This fresh
                // READ COMMITTED snapshot also sees references that committed
                // while the first statement was acquiring those locks.
                let deleted = sql_query(
                    "DELETE FROM oauth_refresh_contracts AS target \
                     USING UNNEST($1::uuid[], $2::bytea[]) AS due(tenant_id, contract_blake3) \
                     WHERE target.tenant_id = due.tenant_id \
                       AND target.contract_blake3 = due.contract_blake3 \
                       AND NOT EXISTS (SELECT 1 FROM oauth_refresh_families AS family \
                                       WHERE family.tenant_id = target.tenant_id \
                                         AND family.contract_blake3 = target.contract_blake3)",
                )
                .bind::<sql_types::Array<sql_types::Uuid>, _>(&tenant_ids)
                .bind::<sql_types::Array<sql_types::Binary>, _>(&digests)
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
            let authorization_decisions = self.decision_cleanup().await?;
            let (expired_proofs, expired_saturated) = self.delete_expired_spent_proofs().await?;
            let proof_budget = CLEANUP_BATCH_LIMIT - expired_proofs as i64;
            let (refresh_tokens, terminal_proofs, families_saturated) =
                self.delete_expired_refresh_families(proof_budget).await?;
            let spent_refresh_proofs = expired_proofs + terminal_proofs;
            let (refresh_contracts, contracts_saturated) =
                self.delete_orphan_refresh_contracts().await?;
            let presentations = self.presentation_cleanup().await?;
            let credentials = self.credential_cleanup().await?;
            let saturated = authorization_decisions >= CLEANUP_BATCH_LIMIT as u64
                || families_saturated
                || expired_saturated
                || contracts_saturated
                || i64::from(generic.deleted_issuances) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_access_token_revocations) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_audit_events) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_backchannel_logout_deliveries) >= CLEANUP_BATCH_LIMIT
                || i64::from(generic.deleted_scim_security_events) >= CLEANUP_BATCH_LIMIT
                || presentations >= CLEANUP_BATCH_LIMIT as u64
                || credentials.saturated;
            Ok(CleanupBatchResult {
                authorization_decisions,
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
