use nazo_oauth_server::workers::ciba_ping::CibaPingDeliveryWorker;
use std::{sync::Arc, time::Duration};
const LOOP_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) fn spawn_ciba_ping_delivery_worker(
    worker: Arc<CibaPingDeliveryWorker>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = worker.process_due_batch().await {
                tracing::warn!(%error, "CIBA ping delivery worker failed");
            }
            tokio::time::sleep(LOOP_INTERVAL).await;
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/jobs/ciba_ping.rs"]
mod tests;
