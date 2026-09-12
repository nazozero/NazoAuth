//! One batch of back-channel logout deliveries and their retry policy.
use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
use futures_util::{StreamExt as _, stream};
use nazo_auth::{BackchannelLogoutDelivery, MAX_CIBA_LOGOUT_URI_BYTES};
use nazo_persistence::BackchannelLogoutDeliveryStore;
use std::sync::Arc;
use url::Url;
const DELIVERY_BATCH_SIZE: i64 = 20;
const DELIVERY_CONCURRENCY: usize = 8;
const LOCK_TIMEOUT_SECONDS: i32 = 300;
const ERROR_MAX_CHARS: usize = 512;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackchannelResponseAction {
    Delivered,
    Retry,
    TerminalFailure,
}

pub trait BackchannelLogoutSender: Send + Sync {
    fn send<'a>(
        &'a self,
        delivery: &'a BackchannelLogoutDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    >;
}
#[derive(Clone)]
pub struct BackchannelLogoutWorker {
    deliveries: Arc<dyn BackchannelLogoutDeliveryStore>,
    sender: Arc<dyn BackchannelLogoutSender>,
}
impl BackchannelLogoutWorker {
    pub fn from_port(
        deliveries: Arc<dyn BackchannelLogoutDeliveryStore>,
        sender: Arc<dyn BackchannelLogoutSender>,
    ) -> Self {
        Self { deliveries, sender }
    }
    pub async fn process_due_batch(&self) -> anyhow::Result<usize> {
        let deliveries = self
            .deliveries
            .claim_due(DELIVERY_BATCH_SIZE, LOCK_TIMEOUT_SECONDS)
            .await
            .context("failed to claim back-channel logout deliveries")?;
        let processed = deliveries.len();
        let results = stream::iter(deliveries)
            .map(|delivery| async move { self.process_delivery(delivery).await })
            .buffer_unordered(DELIVERY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        if let Some(error) = results.into_iter().find_map(Result::err) {
            return Err(error);
        }
        Ok(processed)
    }

    async fn process_delivery(&self, delivery: BackchannelLogoutDelivery) -> anyhow::Result<()> {
        match self.sender.send(&delivery).await {
            Ok(status)
                if classify_backchannel_status(status.as_u16())
                    == BackchannelResponseAction::Delivered =>
            {
                self.deliveries
                    .complete(delivery.id, delivery.attempts)
                    .await
                    .context("failed to complete back-channel logout delivery")
            }
            outcome => {
                let now = Utc::now();
                let (next_attempt_at, delivery_error) =
                    delivery_failure_state(outcome, delivery.attempts, now, delivery.expires_at);
                let last_error = truncate_error(&delivery_error.to_string());
                tracing::warn!(
                    retry_scheduled = next_attempt_at.is_some(),
                    failure_recorded_at = %now,
                    endpoint_origin = %validate_backchannel_endpoint(&delivery.logout_uri)
                        .map(|endpoint| endpoint.origin().ascii_serialization())
                        .unwrap_or_else(|_| "<invalid>".to_owned()),
                    "back-channel logout delivery failed"
                );
                self.deliveries
                    .fail(delivery.id, delivery.attempts, next_attempt_at, &last_error)
                    .await
                    .context("failed to record back-channel logout delivery failure")
            }
        }
    }
}

fn delivery_failure_state(
    outcome: anyhow::Result<http::StatusCode>,
    attempts: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> (Option<DateTime<Utc>>, anyhow::Error) {
    match outcome {
        Ok(status) => match classify_backchannel_status(status.as_u16()) {
            BackchannelResponseAction::TerminalFailure => (
                None,
                anyhow::anyhow!(
                    "back-channel logout endpoint returned terminal status {}",
                    status.as_u16()
                ),
            ),
            BackchannelResponseAction::Retry => (
                next_retry_at(attempts - 1, now, expires_at),
                anyhow::anyhow!(
                    "back-channel logout endpoint returned retryable status {}",
                    status.as_u16()
                ),
            ),
            BackchannelResponseAction::Delivered => unreachable!(),
        },
        Err(error) => (next_retry_at(attempts - 1, now, expires_at), error),
    }
}
pub fn validate_backchannel_endpoint(raw: &str) -> Result<Url, &'static str> {
    if raw.len() > MAX_CIBA_LOGOUT_URI_BYTES {
        return Err("back-channel logout endpoint exceeds the maximum URI length");
    }
    let endpoint = Url::parse(raw).map_err(|_| "back-channel logout endpoint is not a URI")?;
    let host = endpoint
        .host_str()
        .ok_or("back-channel logout endpoint has no host")?;
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("back-channel logout endpoint contains forbidden URI components");
    }
    match endpoint.scheme() {
        "https" => {}
        "http"
            if matches!(host, "localhost" | "127.0.0.1" | "::1")
                || host.ends_with(".localhost") => {}
        _ => return Err("back-channel logout endpoint must use HTTPS or loopback HTTP"),
    }
    Ok(endpoint)
}

fn classify_backchannel_status(status: u16) -> BackchannelResponseAction {
    match status {
        200 | 204 => BackchannelResponseAction::Delivered,
        408 | 425 | 429 | 500..=599 => BackchannelResponseAction::Retry,
        _ => BackchannelResponseAction::TerminalFailure,
    }
}

fn next_retry_at(
    attempt_index: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let delay_seconds = match attempt_index {
        0 => 5,
        1 => 15,
        2 => 45,
        _ => return None,
    };
    let next_attempt_at = now + Duration::seconds(delay_seconds);
    (next_attempt_at < expires_at).then_some(next_attempt_at)
}

fn truncate_error(error: &str) -> String {
    error.chars().take(ERROR_MAX_CHARS).collect()
}

#[cfg(test)]
#[path = "../../tests/unit/workers/backchannel_logout.rs"]
mod tests;
