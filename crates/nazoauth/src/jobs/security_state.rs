//! Bounded security-state maintenance scheduling.
//!
//! One process-level worker owns periodic reclamation. Each cycle runs bounded
//! batches (generic cleanup, refresh-token family reclaim and presentation
//! cleanup inside the port) until the batch reports no saturated
//! category, the catch-up budget is exhausted, or a failure occurs; then it
//! rests for the normal interval when drained, or for its elapsed work time
//! when budget-limited. A failure is logged and the next interval runs;
//! there is no fast retry loop and no leader election — PostgreSQL
//! `SKIP LOCKED` plus the shared refresh-family advisory lock coordinate
//! multiple server instances.
use nazo_persistence::SecurityStateMaintenancePort;
use std::{sync::Arc, time::Duration as StdDuration};

const MAINTENANCE_INTERVAL: StdDuration = StdDuration::from_secs(60);
/// Budget for scheduling successive batches. An in-flight bounded batch is
/// allowed to finish. A saturated cycle rests for its actual elapsed time,
/// leaving at least half of sustained catch-up time to request traffic.
const CATCH_UP_BUDGET: StdDuration = StdDuration::from_secs(30);

pub(crate) fn spawn_security_state_maintenance_worker(
    maintenance: Arc<dyn SecurityStateMaintenancePort>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let cycle_started = tokio::time::Instant::now();
            let mut batches = 0_u64;
            let mut rows = 0_u64;
            let mut issuances = 0_u64;
            let (stop_reason, next_delay) = loop {
                let started = tokio::time::Instant::now();
                match maintenance.cleanup_batch().await {
                    Ok(counts) => {
                        batches += 1;
                        rows += counts.issuances
                            + counts.refresh_tokens
                            + counts.spent_refresh_proofs
                            + counts.refresh_contracts
                            + counts.revocations
                            + counts.scim_audit_events
                            + counts.logout_deliveries
                            + counts.scim_security_events
                            + counts.presentations
                            + counts.credential_offers
                            + counts.credential_nonces
                            + counts.credential_access_grants
                            + counts.deferred_credentials
                            + counts.credential_notifications
                            + counts.credential_responses;
                        issuances += counts.issuances;
                        tracing::debug!(
                            issuances = counts.issuances,
                            refresh_tokens = counts.refresh_tokens,
                            spent_refresh_proofs = counts.spent_refresh_proofs,
                            refresh_contracts = counts.refresh_contracts,
                            revocations = counts.revocations,
                            scim_audit_events = counts.scim_audit_events,
                            logout_deliveries = counts.logout_deliveries,
                            scim_security_events = counts.scim_security_events,
                            presentations = counts.presentations,
                            credential_offers = counts.credential_offers,
                            credential_nonces = counts.credential_nonces,
                            credential_access_grants = counts.credential_access_grants,
                            deferred_credentials = counts.deferred_credentials,
                            credential_notifications = counts.credential_notifications,
                            credential_responses = counts.credential_responses,
                            saturated = counts.saturated,
                            batch = batches,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "security-state maintenance batch completed"
                        );
                        if !counts.saturated {
                            break ("drained", MAINTENANCE_INTERVAL);
                        }
                        let elapsed = cycle_started.elapsed();
                        if elapsed >= CATCH_UP_BUDGET {
                            break ("budget_exhausted", elapsed);
                        }
                        // Cooperatively yield between batches so request tasks
                        // interleave; the next batch only runs while a previous
                        // batch hit a row or family budget.
                        tokio::task::yield_now().await;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "security-state maintenance batch failed");
                        break ("error", MAINTENANCE_INTERVAL);
                    }
                }
            };
            tracing::info!(
                stop_reason,
                batches,
                rows,
                issuances,
                elapsed_ms = cycle_started.elapsed().as_millis() as u64,
                next_delay_ms = next_delay.as_millis() as u64,
                "security-state maintenance cycle completed"
            );
            tokio::time::sleep(next_delay).await;
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/jobs/security_state.rs"]
mod tests;
