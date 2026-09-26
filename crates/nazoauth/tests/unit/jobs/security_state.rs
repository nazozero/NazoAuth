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

#[tokio::test(start_paused = true)]
async fn saturated_batches_drain_immediately_until_unsaturated() {
    struct Saturating {
        calls: AtomicUsize,
        rounds: usize,
    }
    impl SecurityStateMaintenancePort for Saturating {
        fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
            Box::pin(async move {
                let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(CleanupBatchResult {
                    saturated: !call.is_multiple_of(self.rounds),
                    ..CleanupBatchResult::default()
                })
            })
        }
    }
    let saturating = Arc::new(Saturating {
        calls: AtomicUsize::new(0),
        rounds: 5,
    });
    let handle = spawn_security_state_maintenance_worker(saturating.clone());
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        saturating.calls.load(Ordering::SeqCst),
        5,
        "a saturated batch must be followed by another batch inside the same \
         cycle until the port reports no remaining backlog"
    );
    // After the backlog drains, the worker waits the maintenance interval.
    tokio::time::advance(INTERVAL - std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(saturating.calls.load(Ordering::SeqCst), 5);
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(saturating.calls.load(Ordering::SeqCst), 10);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn saturated_cycle_can_drain_more_than_512_batches() {
    struct LargeBacklog(AtomicUsize);
    impl SecurityStateMaintenancePort for LargeBacklog {
        fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
            Box::pin(async move {
                let call = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(CleanupBatchResult {
                    issuances: 256,
                    saturated: call < 600,
                    ..CleanupBatchResult::default()
                })
            })
        }
    }
    let store = Arc::new(LargeBacklog(AtomicUsize::new(0)));
    let handle = spawn_security_state_maintenance_worker(store.clone());
    for _ in 0..1200 {
        tokio::task::yield_now().await;
    }
    assert_eq!(store.0.load(Ordering::SeqCst), 600);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn budget_exhaustion_rests_for_elapsed_work_before_resuming() {
    struct TimedBacklog(AtomicUsize);
    impl SecurityStateMaintenancePort for TimedBacklog {
        fn cleanup_batch(&self) -> SecurityStateMaintenanceFuture<'_, CleanupBatchResult> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                // A single batch may cross the scheduling budget; it must
                // finish and receive an equally long rest, not be cancelled.
                tokio::time::sleep(CATCH_UP_BUDGET + StdDuration::from_secs(5)).await;
                Ok(CleanupBatchResult {
                    issuances: 256,
                    saturated: true,
                    ..CleanupBatchResult::default()
                })
            })
        }
    }
    let store = Arc::new(TimedBacklog(AtomicUsize::new(0)));
    let handle = spawn_security_state_maintenance_worker(store.clone());
    tokio::task::yield_now().await;
    assert_eq!(store.0.load(Ordering::SeqCst), 1);
    tokio::time::advance(StdDuration::from_secs(35)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(StdDuration::from_secs(35) - StdDuration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.0.load(Ordering::SeqCst), 1);
    tokio::time::advance(StdDuration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.0.load(Ordering::SeqCst), 2);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}
