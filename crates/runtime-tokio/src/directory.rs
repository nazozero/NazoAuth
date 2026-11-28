use std::{sync::Arc, time::Duration};

use nazoauth::runtime::TenantRuntimeRefresher;
use tokio::task::JoinHandle;

pub(crate) fn spawn(refresher: Arc<TenantRuntimeRefresher>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cache = tokio::time::interval(Duration::from_secs(1));
        cache.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut database = tokio::time::interval(Duration::from_secs(5));
        database.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        cache.tick().await;
        database.tick().await;
        loop {
            tokio::select! {
                _ = cache.tick() => {
                    if let Err(error) = refresher.refresh_cache_once().await {
                        tracing::warn!(%error, "tenant directory cache reconciliation incomplete");
                    }
                }
                _ = database.tick() => {
                    if let Err(error) = refresher.reconcile_database_once().await {
                        tracing::warn!(%error, "tenant directory database reconciliation incomplete");
                    }
                }
            }
        }
    })
}
