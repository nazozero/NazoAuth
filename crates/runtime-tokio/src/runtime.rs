use std::sync::Arc;

use nazo_identity::TenantDirectorySnapshot;
use nazo_oauth_server::workers::backchannel_logout::BackchannelLogoutWorker;
use nazo_persistence::SecurityStateMaintenancePort;
use nazoauth::runtime::{TenantLifecycle, TenantRuntimeRefresher};
use tokio::task::JoinHandle;

use crate::{TenantTasks, backchannel_logout, directory, security_state};

/// Process-wide work is scheduled once, independently of tenant and HTTP workers.
pub struct ProcessWorkers {
    pub backchannel_logout: Arc<BackchannelLogoutWorker>,
    pub security_state: Arc<dyn SecurityStateMaintenancePort>,
}

enum Tenants {
    Fixed(Arc<TenantTasks>),
    Directory(Arc<TenantRuntimeRefresher>),
}

/// Owns every NazoAuth background task for one embedding instance.
///
/// Keep this owner alive while accepting requests. After stopping the listener,
/// call `shutdown` to wait for active signing-key writes. Dropping the owner
/// withdraws a dynamic directory and signals task termination without aborting
/// those writes. The host owns admission and draining for a fixed tenant.
pub struct Runtime {
    tenants: Tenants,
    directory: Option<OwnedTask>,
    workers: Vec<OwnedTask>,
}

struct OwnedTask(JoinHandle<()>, &'static str);

impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Runtime {
    /// Start the same tenant lifecycle with no directory or request selection.
    pub fn fixed(tenant: Arc<TenantTasks>, workers: ProcessWorkers) -> anyhow::Result<Self> {
        let mut runtime = Self {
            tenants: Tenants::Fixed(tenant.clone()),
            directory: None,
            workers: Vec::new(),
        };
        tenant.start()?;
        runtime.start_process_workers(workers);
        Ok(runtime)
    }

    /// Install an authoritative initial directory and start its shared lifecycle.
    /// The snapshot must come from the configured directory's `load_active` port.
    pub async fn dynamic(
        refresher: Arc<TenantRuntimeRefresher>,
        initial: TenantDirectorySnapshot,
        workers: ProcessWorkers,
    ) -> anyhow::Result<Self> {
        let mut runtime = Self {
            tenants: Tenants::Directory(refresher.clone()),
            directory: None,
            workers: Vec::new(),
        };
        refresher.install_initial(initial).await?;
        runtime.directory = Some(OwnedTask(directory::spawn(refresher), "tenant directory"));
        runtime.start_process_workers(workers);
        Ok(runtime)
    }

    fn start_process_workers(&mut self, workers: ProcessWorkers) {
        self.workers.push(OwnedTask(
            backchannel_logout::spawn_backchannel_logout_delivery_worker(
                workers.backchannel_logout,
            ),
            "back-channel logout",
        ));
        self.workers.push(OwnedTask(
            security_state::spawn_security_state_maintenance_worker(workers.security_state),
            "security-state maintenance",
        ));
    }

    /// Own the application lifetime around a host listener or serving future.
    /// Every completion, including an error result, waits for runtime shutdown.
    /// Cancellation drops this owner and signals all remaining tasks.
    pub async fn run<T>(self, serving: impl std::future::Future<Output = T>) -> T {
        let result = serving.await;
        self.shutdown().await;
        result
    }

    pub async fn shutdown(mut self) {
        if let Some(mut directory) = self.directory.take() {
            directory.0.abort();
            join_task(&mut directory.0, directory.1).await;
        }
        match &self.tenants {
            Tenants::Fixed(tenant) => tenant.stop().await,
            Tenants::Directory(refresher) => refresher.shutdown().await,
        }
        // Signal every remaining loop before joining any one of them so a
        // cancelled shutdown never leaves another process worker running.
        for worker in &self.workers {
            worker.0.abort();
        }
        for worker in &mut self.workers {
            join_task(&mut worker.0, worker.1).await;
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            directory.0.abort();
        }
        match &self.tenants {
            Tenants::Fixed(tenant) => drop(tenant.stop()),
            Tenants::Directory(refresher) => {
                for tenant in refresher.close().by_host.values() {
                    drop(tenant.stop());
                }
            }
        }
    }
}

pub(crate) async fn join_task(task: &mut JoinHandle<()>, name: &'static str) {
    if let Err(error) = task.await
        && !error.is_cancelled()
    {
        tracing::warn!(%error, task = name, "runtime background task stopped unexpectedly");
    }
}

#[cfg(test)]
#[path = "../tests/unit/runtime.rs"]
mod tests;
