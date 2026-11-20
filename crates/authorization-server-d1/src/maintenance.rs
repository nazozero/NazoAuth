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
        let mut statements = vec![
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
                    "DELETE FROM nazo_mfa_devices WHERE tenant_id=?1 AND token_hash IN (SELECT token_hash FROM nazo_mfa_devices WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2) RETURNING 1 AS removed"
                ),
                params.clone(),
            ),
        ];
        // Each child category is reclaimed before its parent. A parent with
        // remaining children is retained, avoiding unbounded FK cascades.
        let extra = [
            (
                "nazo_email_codes",
                "email_hash",
                "expires_at<=unixepoch()".to_owned(),
            ),
            ("nazo_logout_outbox", "id", format!("expires_at<={NOW}")),
            (
                "nazo_scim_event_receipts",
                "event_id,token_id",
                format!(
                    "event_id IN (SELECT id FROM nazo_scim_events WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2)"
                ),
            ),
            (
                "nazo_scim_events",
                "id",
                format!(
                    "expires_at<={NOW} AND NOT EXISTS (SELECT 1 FROM nazo_scim_event_receipts r WHERE r.tenant_id=nazo_scim_events.tenant_id AND r.event_id=nazo_scim_events.id)"
                ),
            ),
            ("nazo_vp_transactions", "id", format!("expires_at<={NOW}")),
            ("nazo_vci_offers", "id", format!("expires_at<={NOW}")),
            (
                "nazo_vci_nonces",
                "nonce_hash",
                format!("expires_at<={NOW}"),
            ),
            (
                "nazo_vci_responses",
                "issuance_id",
                format!("expires_at<={NOW}"),
            ),
            ("nazo_vci_deferred", "id", format!("expires_at<={NOW}")),
            (
                "nazo_vci_notifications",
                "notification_id",
                format!("expires_at<={NOW}"),
            ),
            (
                "nazo_vci_access",
                "token_id",
                format!(
                    "expires_at<={NOW}-{} AND NOT EXISTS (SELECT 1 FROM nazo_vci_responses c WHERE c.tenant_id=nazo_vci_access.tenant_id AND c.token_id=nazo_vci_access.token_id) AND NOT EXISTS (SELECT 1 FROM nazo_vci_deferred c WHERE c.tenant_id=nazo_vci_access.tenant_id AND c.token_id=nazo_vci_access.token_id) AND NOT EXISTS (SELECT 1 FROM nazo_vci_notifications c WHERE c.tenant_id=nazo_vci_access.tenant_id AND c.token_id=nazo_vci_access.token_id)",
                    nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS * 1_000_000
                ),
            ),
            (
                "nazo_client_deliveries",
                "user_id,token_hash",
                format!("expires_at<={NOW}"),
            ),
        ];
        for (table, key, condition) in extra {
            statements.push(Statement::new(format!(
                "DELETE FROM {table} WHERE tenant_id=?1 AND ({key}) IN (SELECT {key} FROM {table} WHERE tenant_id=?1 AND {condition} LIMIT ?2) RETURNING 1 AS removed"
            ), params.clone()));
        }
        statements.push(Statement::new(format!(
            "SELECT count(*) AS candidates FROM (SELECT id FROM nazo_refresh_families WHERE tenant_id=?1 AND expires_at<={NOW} ORDER BY expires_at LIMIT ?2)"
        ), params));
        let results = self.database.batch(statements).await?;
        let counts = results[..results.len() - 1]
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
            remembered_mfa_devices: counts[6] as u64,
            logout_deliveries: counts[8] as u64,
            scim_security_events: counts[10] as u64,
            presentations: counts[11] as u64,
            credential_offers: counts[12] as u64,
            credential_nonces: counts[13] as u64,
            credential_responses: counts[14] as u64,
            deferred_credentials: counts[15] as u64,
            credential_notifications: counts[16] as u64,
            credential_access_grants: counts[17] as u64,
            saturated: counts.contains(&limit)
                || results[results.len() - 1].rows[0]["candidates"]
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
