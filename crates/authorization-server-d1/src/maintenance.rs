//! One bounded reclamation batch, driven by the host's scheduled event.

use nazo_identity::ports::RepositoryError;
use nazo_persistence::{
    CleanupBatchResult, CleanupScope, SecurityStateMaintenanceFuture, SecurityStateMaintenancePort,
};
use serde_json::json;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::NOW,
};

const MAX_PER_TABLE: usize = 1_000;

impl D1Provider {
    /// Reclaim expired state once. The cap bounds both candidates and deletions
    /// in each category; serving requests never runs a cleanup scan.
    pub async fn prune_expired(&self, max_per_table: usize) -> anyhow::Result<usize> {
        let (total, _) = self
            .cleanup_expired(max_per_table.min(MAX_PER_TABLE))
            .await?;
        Ok(total)
    }

    async fn cleanup_expired(&self, limit: usize) -> Result<(usize, CleanupBatchResult), DbError> {
        if limit == 0 {
            return Ok((0, CleanupBatchResult::default()));
        }
        let params: std::sync::Arc<[serde_json::Value]> =
            vec![json!(self.tenant_id), json!(limit)].into();
        let statements = vec![
            Statement::new(
                "DELETE FROM nazo_state WHERE tenant_id=?1 AND (kind,key) IN (SELECT kind,key FROM nazo_state WHERE tenant_id=?1 AND expires_at<=unixepoch() ORDER BY expires_at LIMIT ?2) RETURNING 1 AS removed",
                params.clone(),
            ),
            Statement::new(
                format!(
                    "DELETE FROM nazo_redemptions WHERE tenant_id=?1 AND (client_id,grant_hash) IN (SELECT client_id,grant_hash FROM nazo_redemptions WHERE tenant_id=?1 AND retain_until<={NOW} ORDER BY retain_until LIMIT ?2) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
            Statement::new(
                format!(
                    "DELETE FROM nazo_decisions WHERE tenant_id=?1 AND request_hash IN (SELECT request_hash FROM nazo_decisions WHERE tenant_id=?1 AND retain_until<={NOW} ORDER BY retain_until LIMIT ?2) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
            Statement::new(
                format!(
                    "DELETE FROM nazo_refresh_spent WHERE tenant_id=?1 AND token_hash IN (SELECT token_hash FROM nazo_refresh_spent WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
            // A family can own an unbounded public-client replay history. Only
            // delete a parent with no remaining proofs, so CASCADE stays empty.
            // LIMIT precedes the child lookup to bound candidate scans too.
            Statement::new(
                format!(
                    "DELETE FROM nazo_refresh_families WHERE tenant_id=?1 AND id IN (SELECT id FROM (SELECT id FROM nazo_refresh_families WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2) AS candidates WHERE NOT EXISTS (SELECT 1 FROM nazo_refresh_spent WHERE tenant_id=?1 AND family_id=candidates.id)) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
            Statement::new(
                format!(
                    "DELETE FROM nazo_revocations WHERE tenant_id=?1 AND jti_hash IN (SELECT jti_hash FROM nazo_revocations WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
            Statement::new(
                format!(
                    "SELECT count(*) AS candidates FROM (SELECT id FROM nazo_refresh_families WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2)"
                ),
                params,
            ),
        ];
        let results = self.database.batch(statements).await?;
        let counts = results[..6]
            .iter()
            .map(|result| result.rows.len())
            .collect::<Vec<_>>();
        let total = counts.iter().sum();
        let result = CleanupBatchResult {
            issuances: counts[1] as u64,
            authorization_decisions: counts[2] as u64,
            spent_refresh_proofs: counts[3] as u64,
            refresh_tokens: counts[4] as u64,
            revocations: counts[5] as u64,
            saturated: counts.contains(&limit)
                || results[6].rows[0]["candidates"]
                    .as_u64()
                    .ok_or(DbError::CorruptData)?
                    == limit as u64,
            ..CleanupBatchResult::default()
        };
        Ok((total, result))
    }
}

impl SecurityStateMaintenancePort for D1Provider {
    fn cleanup_batch(
        &self,
        _scope: CleanupScope,
    ) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
        Box::pin(async move {
            self.cleanup_expired(MAX_PER_TABLE)
                .await
                .map(|(_, result)| result)
                .map_err(|error| match error {
                    DbError::Unavailable => RepositoryError::Unavailable,
                    DbError::CorruptData => {
                        RepositoryError::Consistency("invalid D1 cleanup result".into())
                    }
                })
        })
    }
}
