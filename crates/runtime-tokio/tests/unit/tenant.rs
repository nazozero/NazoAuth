use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Completion(Arc<AtomicUsize>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn running() -> (RunningTasks, Arc<AtomicUsize>) {
    let stopped = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let worker = || {
        let stopped = stopped.clone();
        let entered = entered.clone();
        tokio::spawn(async move {
            let _completion = Completion(stopped);
            entered.add_permits(1);
            std::future::pending::<()>().await;
        })
    };
    let settings = nazo_key_management::KeySettings {
        rotation_interval: jiff::SignedDuration::from_hours(90 * 24),
        prepublish_window: jiff::SignedDuration::from_hours(24),
        verification_grace: jiff::SignedDuration::from_hours(1),
    };
    let keys = nazo_key_management::test_support::key_manager(settings.clone())
        .await
        .unwrap();
    let running = RunningTasks {
        modules: worker(),
        keys: KeyLifecycleTask::start(keys, settings.prepublish_window),
        ciba: worker(),
    };
    entered.acquire_many(2).await.unwrap().forget();
    (running, stopped)
}

async fn stopped(stopped: &AtomicUsize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while stopped.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both tenant loops stop");
}

#[tokio::test]
async fn retirement_signals_every_loop_before_the_completion_future_is_polled() {
    let (running, count) = running().await;
    let stopping = running.stop();
    stopped(&count).await;
    stopping.await;
}

#[tokio::test]
async fn cancelling_retirement_does_not_detach_an_owned_loop() {
    let (running, count) = running().await;
    drop(running.stop());
    stopped(&count).await;
}

#[tokio::test]
async fn dropping_the_task_owner_stops_every_loop() {
    let (running, count) = running().await;
    drop(running);
    stopped(&count).await;
}

#[tokio::test]
async fn cancelling_polled_retirement_does_not_detach_an_owned_loop() {
    let (running, count) = running().await;
    let mut stopping = Box::pin(running.stop());
    assert!(futures_util::poll!(&mut stopping).is_pending());
    drop(stopping);
    stopped(&count).await;
}
