use std::time::Duration;

use nazo_key_management::KeyManager;
use tokio::{sync::watch, task::JoinHandle};

/// Owns Native scheduling and completion of signing-key refreshes.
pub struct KeyLifecycleTask {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl KeyLifecycleTask {
    #[must_use]
    pub fn start(keyset: KeyManager, prepublish_window: jiff::SignedDuration) -> Self {
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut retry_interval = managed_refresh_interval(
                prepublish_window,
                keyset.openid4vc_public_material().is_some(),
            );
            let mut failure_backoff = MIN_FAILURE_BACKOFF;
            if *receiver.borrow() {
                return;
            }
            loop {
                tokio::select! {
                    _ = receiver.changed() => return,
                    () = tokio::time::sleep(retry_interval) => {}
                }
                // Shutdown interrupts the wait above, never an in-flight refresh.
                match keyset.refresh().await {
                    Ok(()) => {
                        retry_interval = managed_refresh_interval(
                            prepublish_window,
                            keyset.openid4vc_public_material().is_some(),
                        );
                        failure_backoff = MIN_FAILURE_BACKOFF;
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            retry_in_seconds = failure_backoff.as_secs(),
                            "signing key lifecycle refresh failed; retaining the last good generation"
                        );
                        retry_interval = failure_backoff;
                        failure_backoff = next_failure_backoff(failure_backoff);
                    }
                }
            }
        });
        Self { shutdown, task }
    }

    pub(crate) fn request_stop(&self) {
        let _ = self.shutdown.send(true);
    }

    pub(crate) async fn finish(&mut self) {
        if let Err(error) = (&mut self.task).await {
            tracing::error!(error = %error, "signing key lifecycle task failed");
        }
    }
}

const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(60);

fn next_failure_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_FAILURE_BACKOFF)
}

fn refresh_interval(prepublish_window: jiff::SignedDuration) -> Duration {
    let seconds = (prepublish_window.as_secs() / 2).clamp(1, 3_600);
    Duration::from_secs(seconds as u64)
}

fn managed_refresh_interval(
    prepublish_window: jiff::SignedDuration,
    has_openid4vc_material: bool,
) -> Duration {
    let interval = refresh_interval(prepublish_window);
    if has_openid4vc_material {
        interval.min(Duration::from_secs(30))
    } else {
        interval
    }
}

#[cfg(test)]
#[path = "../tests/unit/key_lifecycle.rs"]
mod tests;
