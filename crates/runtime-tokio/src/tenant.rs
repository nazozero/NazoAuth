use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use nazo_key_management::KeyManager;
use nazo_oauth_server::workers::ciba_ping::CibaPingDeliveryWorker;
use nazoauth::{NazoAuth, runtime::TenantLifecycle};
use tokio::task::JoinHandle;

use crate::{ciba_ping, key_lifecycle::KeyLifecycleTask, runtime_modules};

/// One tenant's task owner, shared by fixed and directory-managed runtimes.
/// Construction is inert; publication starts the tasks after the graph is ready.
pub struct TenantTasks {
    application: Arc<NazoAuth>,
    keys: KeyManager,
    prepublish_window: jiff::SignedDuration,
    ciba: Arc<CibaPingDeliveryWorker>,
    running: Mutex<Option<RunningTasks>>,
}

struct RunningTasks {
    modules: JoinHandle<()>,
    keys: KeyLifecycleTask,
    ciba: JoinHandle<()>,
}

impl Drop for RunningTasks {
    fn drop(&mut self) {
        self.modules.abort();
        self.ciba.abort();
        // The key owner's sender closes on drop. Its active refresh completes
        // before exiting, including when the caller cancels shutdown.
    }
}

impl RunningTasks {
    fn stop(mut self) -> impl std::future::Future<Output = ()> + Send {
        self.modules.abort();
        self.ciba.abort();
        self.keys.request_stop();
        async move {
            tokio::join!(
                self.keys.finish(),
                super::runtime::join_task(&mut self.modules, "tenant runtime modules"),
                super::runtime::join_task(&mut self.ciba, "tenant CIBA ping"),
            );
        }
    }
}

impl TenantTasks {
    pub fn new(
        application: Arc<NazoAuth>,
        keys: KeyManager,
        prepublish_window: jiff::SignedDuration,
        ciba: Arc<CibaPingDeliveryWorker>,
    ) -> Self {
        Self {
            application,
            keys,
            prepublish_window,
            ciba,
            running: Mutex::new(None),
        }
    }

    /// The graph supplied to any fixed-tenant HTTP adapter.
    pub fn application(&self) -> &Arc<NazoAuth> {
        &self.application
    }
}

impl TenantLifecycle for TenantTasks {
    fn start(&self) -> anyhow::Result<()> {
        let mut running = self
            .running
            .lock()
            .expect("tenant tasks mutex is not poisoned");
        if running.is_none() {
            *running = Some(RunningTasks {
                modules: runtime_modules::spawn_reconciler(self.application.clone()),
                keys: KeyLifecycleTask::start(self.keys.clone(), self.prepublish_window),
                ciba: ciba_ping::spawn_ciba_ping_delivery_worker(self.ciba.clone()),
            });
        }
        Ok(())
    }

    fn stop(&self) -> BoxFuture<'_, ()> {
        let running = self
            .running
            .lock()
            .expect("tenant tasks mutex is not poisoned")
            .take();
        let stopping = running.map(RunningTasks::stop);
        // Signals above happen before returning the future. Dropping it still
        // stops all loops and never cancels an in-flight signing-key write.
        Box::pin(async move {
            if let Some(stopping) = stopping {
                stopping.await;
            }
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/tenant.rs"]
mod tests;
