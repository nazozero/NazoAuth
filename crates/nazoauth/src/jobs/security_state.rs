//! Bounded security-state maintenance scheduling.
//!
//! One process-level worker owns periodic reclamation. Each cycle runs bounded
//! batches (generic cleanup, refresh-token family reclaim and presentation
//! cleanup inside the port) until the batch reports no saturated
//! category, the catch-up budget is exhausted, or a failure occurs; then it
//! waits the fixed interval. A failure is logged and the next interval runs;
//! there is no fast retry loop and no leader election — PostgreSQL
//! `SKIP LOCKED` plus the shared refresh-family advisory lock coordinate
//! multiple server instances.
use nazo_persistence::SecurityStateMaintenancePort;
use std::{sync::Arc, time::Duration as StdDuration};

const MAINTENANCE_INTERVAL: StdDuration = StdDuration::from_secs(60);
/// Wall-clock budget for draining backlog inside one cycle. The worker never
/// spends more than this share of each interval reclaiming expired rows, so
/// catch-up work cannot starve request traffic on the shared pool.
const CATCH_UP_BUDGET: StdDuration = StdDuration::from_secs(30);
/// Belt bound on consecutive batches in one cycle; normally unreachable inside
/// the wall-clock budget and guards against a pathological fast batch loop.
const CATCH_UP_MAX_BATCHES: u32 = 512;

pub(crate) fn spawn_security_state_maintenance_worker(
    maintenance: Arc<dyn SecurityStateMaintenancePort>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let cycle_started = std::time::Instant::now();
            let mut batches = 0_u32;
            loop {
                let started = std::time::Instant::now();
                match maintenance.cleanup_batch().await {
                    Ok(counts) => {
                        batches += 1;
                        tracing::info!(
                            issuances = counts.issuances,
                            refresh_tokens = counts.refresh_tokens,
                            revocations = counts.revocations,
                            scim_audit_events = counts.scim_audit_events,
                            logout_deliveries = counts.logout_deliveries,
                            scim_security_events = counts.scim_security_events,
                            presentations = counts.presentations,
                            sparsified_refresh_members = counts.sparsified_refresh_members,
                            saturated = counts.saturated,
                            batch = batches,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "security-state maintenance batch completed"
                        );
                        if !counts.saturated
                            || batches >= CATCH_UP_MAX_BATCHES
                            || cycle_started.elapsed() >= CATCH_UP_BUDGET
                        {
                            break;
                        }
                        // Cooperatively yield between batches so request tasks
                        // interleave; the next batch only runs while a previous
                        // batch hit a row or family budget.
                        tokio::task::yield_now().await;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "security-state maintenance batch failed");
                        break;
                    }
                }
            }
            tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/jobs/security_state.rs"]
mod tests;
