use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;

struct Store {
    claims: AtomicUsize,
    active: AtomicUsize,
    release: Semaphore,
}
impl Store {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            claims: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            release: Semaphore::new(0),
        })
    }
    async fn claim(&self) {
        self.claims.fetch_add(1, Ordering::SeqCst);
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
    CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
    TransientStateFuture,
};
use nazo_oauth_server::workers::ciba_ping::CibaPingSender;
const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
impl CibaPingDeliveryPort for Store {
    fn claim_due(
        &self,
        _: i64,
        _: i64,
        _: usize,
    ) -> TransientStateFuture<'_, Vec<CibaPingDelivery>> {
        Box::pin(async move {
            self.claim().await;
            Ok(vec![])
        })
    }
    fn finish<'a>(
        &'a self,
        _: &'a CibaPingDelivery,
        _: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        panic!("empty batch cannot finish a delivery")
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
        panic!("empty batch cannot send a delivery")
    }
}
fn spawn_worker(store: Arc<Store>) -> tokio::task::JoinHandle<()> {
    spawn_ciba_ping_delivery_worker(Arc::new(CibaPingDeliveryWorker::new(
        store,
        Arc::new(Sender),
    )))
}
