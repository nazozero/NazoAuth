use super::*;
use futures_util::future::BoxFuture;
use nazo_identity::{TenantContext, TenantDirectoryBinding, TenantId, ports::RepositoryError};
use nazo_oauth_server::ports::transient_state::{TenantDirectoryCachePort, TransientStateFuture};
use nazoauth::runtime::{
    TenantRuntimeBuildFuture, TenantRuntimeBuildPort, TenantRuntimeRegistry, test_support,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Directory;
impl nazo_persistence::TenantDirectoryStore for Directory {
    fn current_revision(&self) -> BoxFuture<'_, Result<u64, RepositoryError>> {
        Box::pin(async { Ok(1) })
    }
    fn load_active(&self) -> BoxFuture<'_, Result<TenantDirectorySnapshot, RepositoryError>> {
        Box::pin(async { Ok(snapshot()) })
    }
    fn find_active_binding(
        &self,
        _: TenantId,
    ) -> BoxFuture<'_, Result<Option<TenantDirectoryBinding>, RepositoryError>> {
        Box::pin(async { Ok(None) })
    }
}

struct Cache;
impl TenantDirectoryCachePort for Cache {
    fn load(&self) -> TransientStateFuture<'_, Option<Arc<TenantDirectorySnapshot>>> {
        Box::pin(async { Ok(None) })
    }
    fn publish_authoritative<'a>(
        &'a self,
        _: &'a TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }
}

struct Lifecycle {
    stops: AtomicUsize,
    hold_completion: bool,
}
impl TenantLifecycle for Lifecycle {
    fn start(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn stop(&self) -> BoxFuture<'_, ()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.hold_completion {
                std::future::pending::<()>().await;
            }
        })
    }
}

struct Builder(Arc<Lifecycle>);
impl TenantRuntimeBuildPort for Builder {
    fn build(&self, binding: &TenantDirectoryBinding) -> TenantRuntimeBuildFuture<'_> {
        let runtime = test_support::runtime_with_lifecycle(binding.clone(), self.0.clone());
        Box::pin(async move { Ok(runtime) })
    }
}

fn snapshot() -> TenantDirectorySnapshot {
    TenantDirectorySnapshot {
        revision: 1,
        tenants: vec![TenantDirectoryBinding {
            tenant: TenantContext::default_system(),
            issuer: "https://tenant.example".to_owned(),
            external_host: "tenant.example".to_owned(),
            runtime_revision: 1,
        }],
    }
}

async fn owned_loop(live: Arc<AtomicUsize>) -> OwnedTask {
    let entered = Arc::new(tokio::sync::Notify::new());
    let ready = entered.clone();
    let task = tokio::spawn(async move {
        live.fetch_add(1, Ordering::SeqCst);
        let _guard = std::mem::DropGuard::new(live, |live| {
            live.fetch_sub(1, Ordering::SeqCst);
        });
        entered.notify_one();
        std::future::pending::<()>().await;
    });
    ready.notified().await;
    OwnedTask(task, "test-owned loop")
}

struct Fixture {
    runtime: Runtime,
    registry: TenantRuntimeRegistry,
    lifecycle: Arc<Lifecycle>,
    live: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(directory: bool, hold_completion: bool) -> Self {
        let registry = TenantRuntimeRegistry::empty();
        let lifecycle = Arc::new(Lifecycle {
            stops: AtomicUsize::new(0),
            hold_completion,
        });
        let refresher = Arc::new(TenantRuntimeRefresher::new(
            registry.clone(),
            Arc::new(Directory),
            Arc::new(Cache),
            Arc::new(Builder(lifecycle.clone())),
        ));
        refresher.install_initial(snapshot()).await.unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let directory = if directory {
            Some(owned_loop(live.clone()).await)
        } else {
            None
        };
        let workers = vec![
            owned_loop(live.clone()).await,
            owned_loop(live.clone()).await,
        ];
        Self {
            runtime: Runtime {
                tenants: Tenants::Directory(refresher),
                directory,
                workers,
            },
            registry,
            lifecycle,
            live,
        }
    }
}

async fn all_stopped(live: &AtomicUsize) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while live.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every process-owned loop stops");
}

#[tokio::test]
async fn drop_closes_admission_and_stops_workers_even_with_retained_registry_snapshots() {
    let Fixture {
        runtime,
        registry,
        lifecycle,
        live,
    } = Fixture::new(true, false).await;
    let retained = registry.load();
    drop(runtime);
    assert!(registry.load().by_host.is_empty());
    assert_eq!(retained.by_host.len(), 1);
    assert_eq!(lifecycle.stops.load(Ordering::SeqCst), 1);
    all_stopped(&live).await;
}

#[tokio::test]
async fn cancelled_shutdown_while_joining_directory_still_closes_all_owned_work() {
    let Fixture {
        runtime,
        registry,
        lifecycle,
        live,
    } = Fixture::new(true, false).await;
    let mut shutdown = Box::pin(runtime.shutdown());
    assert!(futures_util::poll!(&mut shutdown).is_pending());
    drop(shutdown);
    assert!(registry.load().by_host.is_empty());
    assert_eq!(lifecycle.stops.load(Ordering::SeqCst), 1);
    all_stopped(&live).await;
}

#[tokio::test]
async fn cancelled_shutdown_while_waiting_for_tenant_completion_stops_process_workers() {
    let Fixture {
        runtime,
        registry,
        lifecycle,
        live,
    } = Fixture::new(false, true).await;
    let mut shutdown = Box::pin(runtime.shutdown());
    assert!(futures_util::poll!(&mut shutdown).is_pending());
    assert!(registry.load().by_host.is_empty());
    assert_eq!(lifecycle.stops.load(Ordering::SeqCst), 1);
    drop(shutdown);
    all_stopped(&live).await;
}

#[tokio::test]
async fn serving_error_completes_shutdown_before_returning_the_same_error() {
    let Fixture {
        runtime,
        registry,
        lifecycle,
        live,
    } = Fixture::new(true, false).await;
    let result = runtime.run(async { Err::<(), _>("listener failed") }).await;
    assert_eq!(result, Err("listener failed"));
    assert!(registry.load().by_host.is_empty());
    assert_eq!(lifecycle.stops.load(Ordering::SeqCst), 1);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}
