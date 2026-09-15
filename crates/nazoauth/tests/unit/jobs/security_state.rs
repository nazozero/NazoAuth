use super::*;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{CleanupBatchResult, SecurityStateMaintenanceFuture};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;

const INTERVAL: StdDuration = StdDuration::from_secs(60);

struct Store {
    calls: AtomicUsize,
    active: AtomicUsize,
    release: Semaphore,
}

impl Store {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn cleanup(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _active = Active(&self.active);
        self.release.acquire().await.unwrap().forget();
    }
}

impl SecurityStateMaintenancePort for Store {
    fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
        Box::pin(async move {
            self.cleanup().await;
            Ok(CleanupBatchResult::default())
        })
    }
}

#[tokio::test(start_paused = true)]
async fn first_batch_is_immediate_and_interval_starts_after_completion() {
    let store = Store::new();
    let handle = spawn_security_state_maintenance_worker(store.clone());
    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.active.load(Ordering::SeqCst), 1);
    tokio::time::advance(INTERVAL * 3).await;
    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    store.release.add_permits(1);
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    tokio::time::advance(INTERVAL - std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
    store.release.add_permits(1);
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    tokio::time::advance(INTERVAL * 3).await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn failed_batch_does_not_stop_the_interval() {
    struct Failing {
        calls: AtomicUsize,
    }
    impl SecurityStateMaintenancePort for Failing {
        fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(RepositoryError::Unavailable)
            })
        }
    }
    let failing = Arc::new(Failing {
        calls: AtomicUsize::new(0),
    });
    let handle = spawn_security_state_maintenance_worker(failing.clone());
    tokio::task::yield_now().await;
    assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
    // A failed batch logs and waits one interval before the next attempt; the
    // task stays alive with no tight retry.
    tokio::time::advance(INTERVAL - std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(failing.calls.load(Ordering::SeqCst), 2);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn abort_cancels_inflight_batch_and_await_finishes() {
    let store = Store::new();
    let handle = spawn_security_state_maintenance_worker(store.clone());
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 1);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    tokio::time::advance(INTERVAL * 3).await;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}
