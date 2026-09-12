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

use futures_util::future::BoxFuture;
use nazo_auth::BackchannelLogoutDelivery;
use nazo_identity::ports::RepositoryError;
use nazo_oauth_server::workers::backchannel_logout::BackchannelLogoutSender;
use nazo_persistence::BackchannelLogoutDeliveryStore;
const INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
impl BackchannelLogoutDeliveryStore for Store {
    fn claim_due(
        &self,
        _: i64,
        _: i32,
    ) -> BoxFuture<'_, Result<Vec<BackchannelLogoutDelivery>, RepositoryError>> {
        Box::pin(async move {
            self.claim().await;
            Ok(vec![])
        })
    }
    fn complete(&self, _: uuid::Uuid, _: i32) -> BoxFuture<'_, Result<(), RepositoryError>> {
        panic!("empty batch cannot complete a delivery")
    }
    fn fail<'a>(
        &'a self,
        _: uuid::Uuid,
        _: i32,
        _: Option<chrono::DateTime<chrono::Utc>>,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        panic!("empty batch cannot fail a delivery")
    }
}
struct Sender;
impl BackchannelLogoutSender for Sender {
    fn send<'a>(
        &'a self,
        _: &'a BackchannelLogoutDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    > {
        panic!("empty batch cannot send a delivery")
    }
}
fn spawn_worker(store: Arc<Store>) -> tokio::task::JoinHandle<()> {
    spawn_backchannel_logout_delivery_worker(Arc::new(BackchannelLogoutWorker::from_port(
        store,
        Arc::new(Sender),
    )))
}
