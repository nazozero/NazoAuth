use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Semaphore;

struct Store {
    claims: AtomicUsize,
    active: AtomicUsize,
    release: Semaphore,
    claimed: Semaphore,
    batch_size: AtomicUsize,
    stale_entries: AtomicUsize,
    claim_fails: AtomicBool,
    finish_fails: AtomicBool,
    finished: AtomicUsize,
}
impl Store {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            claims: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            release: Semaphore::new(0),
            claimed: Semaphore::new(0),
            batch_size: AtomicUsize::new(0),
            stale_entries: AtomicUsize::new(0),
            claim_fails: AtomicBool::new(false),
            finish_fails: AtomicBool::new(false),
            finished: AtomicUsize::new(0),
        })
    }
    async fn claim(&self) {
        self.claims.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        self.claimed.add_permits(1);
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

#[tokio::test(start_paused = true)]
async fn full_batch_continues_immediately_then_empty_or_partial_batch_waits() {
    for tail_size in [0, DELIVERY_BATCH_SIZE - 1] {
        let store = Store::new();
        store
            .batch_size
            .store(DELIVERY_BATCH_SIZE, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let handle = spawn_worker(store.clone());
        store.claimed.acquire().await.unwrap().forget();
        store.release.add_permits(1);
        store.claimed.acquire().await.unwrap().forget();
        assert_eq!(tokio::time::Instant::now(), started);
        assert_eq!(store.finished.load(Ordering::SeqCst), DELIVERY_BATCH_SIZE);
        assert_eq!(store.active.load(Ordering::SeqCst), 1);

        store.batch_size.store(tail_size, Ordering::SeqCst);
        store.release.add_permits(1);
        tokio::task::yield_now().await;
        assert_eq!(store.active.load(Ordering::SeqCst), 0);
        tokio::time::advance(INTERVAL - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.claims.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        store.claimed.acquire().await.unwrap().forget();
        assert_eq!(store.claims.load(Ordering::SeqCst), 3);
        assert_eq!(tokio::time::Instant::now(), started + INTERVAL);
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test(start_paused = true)]
async fn full_scan_with_missing_entries_continues_without_an_idle_delay() {
    for delivery_count in [0, 1] {
        let store = Store::new();
        store.batch_size.store(delivery_count, Ordering::SeqCst);
        store
            .stale_entries
            .store(DELIVERY_BATCH_SIZE - delivery_count, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let handle = spawn_worker(store.clone());
        store.claimed.acquire().await.unwrap().forget();
        store.release.add_permits(1);
        store.claimed.acquire().await.unwrap().forget();
        assert_eq!(tokio::time::Instant::now(), started);
        assert_eq!(store.finished.load(Ordering::SeqCst), delivery_count);

        // A partial scan of stale entries is idle even though its delivery
        // count is indistinguishable from the preceding full stale page.
        store.batch_size.store(0, Ordering::SeqCst);
        store
            .stale_entries
            .store(DELIVERY_BATCH_SIZE - 1, Ordering::SeqCst);
        store.release.add_permits(1);
        tokio::task::yield_now().await;
        tokio::time::advance(INTERVAL - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.claims.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        store.claimed.acquire().await.unwrap().forget();
        assert_eq!(tokio::time::Instant::now(), started + INTERVAL);
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test(start_paused = true)]
async fn claim_and_full_batch_finish_errors_back_off() {
    for fail_claim in [true, false] {
        let store = Store::new();
        store
            .batch_size
            .store(DELIVERY_BATCH_SIZE, Ordering::SeqCst);
        store.claim_fails.store(fail_claim, Ordering::SeqCst);
        store.finish_fails.store(!fail_claim, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let handle = spawn_worker(store.clone());
        store.claimed.acquire().await.unwrap().forget();
        store.release.add_permits(1);
        tokio::task::yield_now().await;
        assert_eq!(store.active.load(Ordering::SeqCst), 0);
        tokio::time::advance(INTERVAL - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(store.claims.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        store.claimed.acquire().await.unwrap().forget();
        assert_eq!(store.claims.load(Ordering::SeqCst), 2);
        assert_eq!(tokio::time::Instant::now(), started + INTERVAL);
        handle.abort();
        assert!(handle.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test(start_paused = true)]
async fn first_batch_is_immediate_and_interval_starts_after_completion() {
    let store = Store::new();
    let handle = spawn_worker(store.clone());
    tokio::task::yield_now().await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 1);
    assert_eq!(store.active.load(Ordering::SeqCst), 1);
    tokio::time::advance(INTERVAL * 3).await;
    tokio::task::yield_now().await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 1);
    store.release.add_permits(1);
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    tokio::time::advance(INTERVAL - std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 1);
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 2);
    store.release.add_permits(1);
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    tokio::time::advance(INTERVAL * 3).await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn abort_cancels_inflight_batch_and_await_finishes() {
    let store = Store::new();
    let handle = spawn_worker(store.clone());
    tokio::task::yield_now().await;
    assert_eq!(store.active.load(Ordering::SeqCst), 1);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert_eq!(store.active.load(Ordering::SeqCst), 0);
    tokio::time::advance(INTERVAL * 3).await;
    assert_eq!(store.claims.load(Ordering::SeqCst), 1);
}

use nazo_oauth_server::ports::transient_state::{
    CibaPingClaimBatch, CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome,
    CibaPingFinishResult, TransientStateError, TransientStateFuture,
};
use nazo_oauth_server::workers::ciba_ping::CibaPingSender;
const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
impl CibaPingDeliveryPort for Store {
    fn claim_due(
        &self,
        _: i64,
        _: i64,
        limit: usize,
    ) -> TransientStateFuture<'_, CibaPingClaimBatch> {
        Box::pin(async move {
            self.claim().await;
            if self.claim_fails.load(Ordering::SeqCst) {
                return Err(TransientStateError::Unavailable);
            }
            let size = self.batch_size.load(Ordering::SeqCst);
            let stale = self.stale_entries.load(Ordering::SeqCst);
            assert!(size + stale <= limit);
            Ok(CibaPingClaimBatch {
                scanned: size + stale,
                deliveries: (0..size)
                    .map(|id| CibaPingDelivery {
                        auth_req_id_hash: id.to_string(),
                        auth_req_id: format!("request-{id}"),
                        endpoint: "https://client.example/ping".to_owned(),
                        client_notification_token: "test-notification-token".to_owned(),
                        attempts: 1,
                        expires_at: chrono::Utc::now().timestamp() + 60,
                    })
                    .collect(),
            })
        })
    }
    fn finish<'a>(
        &'a self,
        _: &'a CibaPingDelivery,
        _: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            if self.finish_fails.load(Ordering::SeqCst) {
                return Err(TransientStateError::Unavailable);
            }
            self.finished.fetch_add(1, Ordering::SeqCst);
            Ok(CibaPingFinishResult::Applied)
        })
    }
}
struct Sender;
impl CibaPingSender for Sender {
    fn send<'a>(
        &'a self,
        _: &'a CibaPingDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    > {
        Box::pin(async { Ok(http::StatusCode::OK) })
    }
}
fn spawn_worker(store: Arc<Store>) -> tokio::task::JoinHandle<()> {
    spawn_ciba_ping_delivery_worker(Arc::new(CibaPingDeliveryWorker::new(
        store,
        Arc::new(Sender),
    )))
}
