//! Native back-channel logout delivery scheduling.
use nazo_oauth_server::workers::backchannel_logout::BackchannelLogoutWorker;
use std::{sync::Arc, time::Duration as StdDuration};
pub(crate) fn spawn_backchannel_logout_delivery_worker(
    worker: Arc<BackchannelLogoutWorker>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = worker.process_due_batch().await {
                tracing::warn!(%error, "back-channel logout delivery worker failed");
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/jobs/backchannel_logout.rs"]
mod tests;
