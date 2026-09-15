//! Bounded security-state maintenance scheduling.
//!
//! One process-level worker owns periodic reclamation. Each cycle performs one
//! bounded batch (generic cleanup, refresh-token leaf reclaim, presentation
//! cleanup inside the port), then waits the fixed interval. A failure is
//! logged and the next interval runs; there is no fast retry loop and no
//! leader election — PostgreSQL `SKIP LOCKED` plus the shared refresh-family
//! advisory lock coordinate multiple server instances.
use nazo_persistence::SecurityStateMaintenancePort;
use std::{sync::Arc, time::Duration as StdDuration};

const MAINTENANCE_INTERVAL: StdDuration = StdDuration::from_secs(60);

pub(crate) fn spawn_security_state_maintenance_worker(
    maintenance: Arc<dyn SecurityStateMaintenancePort>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let started = std::time::Instant::now();
            match maintenance.cleanup_batch().await {
                Ok(counts) => tracing::info!(
                    issuances = counts.issuances,
                    refresh_tokens = counts.refresh_tokens,
                    revocations = counts.revocations,
                    scim_audit_events = counts.scim_audit_events,
                    logout_deliveries = counts.logout_deliveries,
                    scim_security_events = counts.scim_security_events,
                    presentations = counts.presentations,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "security-state maintenance batch completed"
                ),
                Err(error) => {
                    tracing::warn!(%error, "security-state maintenance batch failed");
                }
            }
            tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/jobs/security_state.rs"]
mod tests;
