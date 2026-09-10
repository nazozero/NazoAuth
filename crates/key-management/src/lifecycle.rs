use std::time::Duration;

use crate::KeyManager;
use nazo_auth::SigningPurpose;

impl KeyManager {
    pub async fn run_lifecycle(self) {
        let mut normal_interval = managed_refresh_interval(
            self.inner.settings.prepublish_window,
            self.inner
                .generation
                .load()
                .loaded
                .openid4vc_material
                .is_some(),
        );
        let mut retry_interval = normal_interval;
        let mut failure_backoff = MIN_FAILURE_BACKOFF;
        let mut shutdown = self.inner.lifecycle_shutdown.subscribe();
        if *shutdown.borrow() {
            return;
        }
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = tokio::time::sleep(retry_interval) => {}
            }
            match self.refresh().await {
                Ok(()) => {
                    normal_interval = managed_refresh_interval(
                        self.inner.settings.prepublish_window,
                        self.inner
                            .generation
                            .load()
                            .loaded
                            .openid4vc_material
                            .is_some(),
                    );
                    retry_interval = normal_interval;
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
    }
}

const MIN_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(60);
/// A database-backed generation may sign only until this stale-snapshot bound.
pub(crate) const MAX_DATABASE_SNAPSHOT_STALENESS_SECONDS: i64 = 2 * 60 * 60;
pub(crate) const MAX_DATABASE_SNAPSHOT_STALENESS: chrono::Duration =
    chrono::Duration::seconds(MAX_DATABASE_SNAPSHOT_STALENESS_SECONDS);
/// Managed local revocation facts are refreshed on the same cadence as the
/// previous file-backed source. This observation deadline is intentionally
/// shorter than the two-hour signing-generation stale bound.
pub(crate) const OPENID4VC_REVOCATION_MAX_STALE_SECONDS: i64 = 60;

fn next_failure_backoff(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(MAX_FAILURE_BACKOFF)
        .min(MAX_FAILURE_BACKOFF)
}

fn refresh_interval(prepublish_window: chrono::Duration) -> Duration {
    let seconds = (prepublish_window.num_seconds() / 2).clamp(1, 3_600);
    Duration::from_secs(seconds as u64)
}

fn managed_refresh_interval(
    prepublish_window: chrono::Duration,
    has_openid4vc_material: bool,
) -> Duration {
    let interval = refresh_interval(prepublish_window);
    if has_openid4vc_material {
        interval.min(Duration::from_secs(30))
    } else {
        interval
    }
}

pub(crate) fn all_signing_purposes() -> std::collections::BTreeSet<SigningPurpose> {
    [
        SigningPurpose::AccessToken,
        SigningPurpose::IdToken,
        SigningPurpose::Jarm,
        SigningPurpose::Introspection,
        SigningPurpose::LogoutToken,
        SigningPurpose::HttpMessage,
        SigningPurpose::SecurityEvent,
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
#[path = "../tests/unit/lifecycle.rs"]
mod tests;
