use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use nazo_key_management::{
    KeyManager, KeySettings, PersistedSigningKeyset, SigningKeyRepository,
    SigningKeyRepositoryFuture, SigningKeyWrappingKeyRing, SigningKeysetCompareAndSwapResult,
    SigningKeysetCreateResult, test_support::MemorySigningKeyRepository,
};
use tokio::sync::Notify;

use super::{KeyLifecycleTask, managed_refresh_interval, next_failure_backoff, refresh_interval};

fn settings() -> KeySettings {
    KeySettings {
        rotation_interval: chrono::Duration::days(90),
        prepublish_window: chrono::Duration::seconds(20),
        verification_grace: chrono::Duration::minutes(10),
    }
}

#[test]
fn refresh_interval_is_bounded_by_prepublish_window() {
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(86_400)),
        Duration::from_secs(3_600)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(30)),
        Duration::from_secs(15)
    );
    assert_eq!(
        refresh_interval(chrono::Duration::seconds(1)),
        Duration::from_secs(1)
    );
}

#[test]
fn managed_openid4vc_refresh_is_capped_at_thirty_seconds() {
    assert_eq!(
        managed_refresh_interval(chrono::Duration::days(1), true),
        Duration::from_secs(30)
    );
    assert_eq!(
        managed_refresh_interval(chrono::Duration::seconds(20), true),
        Duration::from_secs(10)
    );
    assert_eq!(
        managed_refresh_interval(chrono::Duration::days(1), false),
        Duration::from_secs(3_600)
    );
}

#[test]
fn refresh_failure_backoff_is_bounded() {
    assert_eq!(
        next_failure_backoff(Duration::from_secs(1)),
        Duration::from_secs(2)
    );
    assert_eq!(
        next_failure_backoff(Duration::from_secs(32)),
        Duration::from_secs(60)
    );
    assert_eq!(
        next_failure_backoff(Duration::from_secs(60)),
        Duration::from_secs(60)
    );
}

#[tokio::test]
async fn lifecycle_stops_when_requested() {
    let manager = nazo_key_management::test_support::key_manager(settings())
        .await
        .unwrap();
    let task = KeyLifecycleTask::start(manager, settings().prepublish_window);

    tokio::time::timeout(Duration::from_secs(1), task.stop())
        .await
        .expect("lifecycle should observe shutdown");
}

#[derive(Default)]
struct ControlledRepository {
    inner: MemorySigningKeyRepository,
    loads: AtomicUsize,
    completed_loads: AtomicUsize,
    fail: AtomicBool,
    block: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl SigningKeyRepository for ControlledRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            if self.block.load(Ordering::SeqCst) {
                self.release.notified().await;
            }
            if self.fail.load(Ordering::SeqCst) {
                anyhow::bail!("injected refresh failure");
            }
            let loaded = self.inner.load().await;
            self.completed_loads.fetch_add(1, Ordering::SeqCst);
            loaded
        })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        self.inner.create_if_absent(candidate)
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        self.inner.compare_and_swap(expected_revision, candidate)
    }
}

async fn managed_repository() -> (KeyManager, Arc<ControlledRepository>) {
    let repository = Arc::new(ControlledRepository::default());
    let manager = KeyManager::load_or_create_database(
        settings(),
        None,
        uuid::Uuid::now_v7(),
        repository.clone(),
        SigningKeyWrappingKeyRing::new("test", [0xA5; 32], None).unwrap(),
    )
    .await
    .unwrap();
    // Discard the notification emitted by the initial database load.
    repository.entered.notified().await;
    (manager, repository)
}

#[tokio::test(start_paused = true)]
async fn lifecycle_waits_for_first_interval_and_resets_backoff_after_success() {
    let (manager, repository) = managed_repository().await;
    let baseline = repository.loads.load(Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    repository.fail.store(true, Ordering::SeqCst);
    let task = KeyLifecycleTask::start(manager, settings().prepublish_window);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(repository.loads.load(Ordering::SeqCst), baseline);
    tokio::time::advance(Duration::from_secs(1)).await;
    repository.entered.notified().await;
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(repository.loads.load(Ordering::SeqCst), baseline + 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    repository.entered.notified().await;
    assert_eq!(started.elapsed(), Duration::from_secs(11));
    assert_eq!(repository.loads.load(Ordering::SeqCst), baseline + 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(repository.loads.load(Ordering::SeqCst), baseline + 2);
    repository.fail.store(false, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;
    repository.entered.notified().await;
    let recovered = repository.loads.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(9)).await;
    tokio::task::yield_now().await;
    assert_eq!(repository.loads.load(Ordering::SeqCst), recovered);
    tokio::time::advance(Duration::from_secs(1)).await;
    repository.entered.notified().await;
    assert!(repository.loads.load(Ordering::SeqCst) > recovered);
    repository.fail.store(true, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(10)).await;
    repository.entered.notified().await;
    let failed_again = repository.loads.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;
    repository.entered.notified().await;
    assert_eq!(started.elapsed(), Duration::from_secs(34));
    assert_eq!(repository.loads.load(Ordering::SeqCst), failed_again + 1);
    task.stop().await;
}

#[tokio::test(start_paused = true)]
async fn lifecycle_stop_awaits_in_flight_refresh_without_cancelling_it() {
    let (manager, repository) = managed_repository().await;
    let completed = repository.completed_loads.load(Ordering::SeqCst);
    repository.block.store(true, Ordering::SeqCst);
    let task = KeyLifecycleTask::start(manager, settings().prepublish_window);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(10)).await;
    repository.entered.notified().await;
    let stop = tokio::spawn(task.stop());
    tokio::task::yield_now().await;
    assert!(!stop.is_finished(), "stop must await the active refresh");
    repository.block.store(false, Ordering::SeqCst);
    repository.release.notify_one();
    stop.await.expect("stop task should finish cleanly");
    assert!(repository.completed_loads.load(Ordering::SeqCst) > completed);
}
