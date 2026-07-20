#[cfg(not(test))]
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration as StdDuration};

#[cfg(not(test))]
use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
#[cfg(not(test))]
use futures_util::{StreamExt as _, stream};
#[cfg(not(test))]
use nazo_auth::BackchannelLogoutDelivery;
#[cfg(not(test))]
use nazo_postgres::AuditRepository;
use url::Url;

#[cfg(not(test))]
use super::sector_identifier::is_blocked_ip;

#[cfg(not(test))]
const DELIVERY_BATCH_SIZE: i64 = 20;
#[cfg(not(test))]
const DELIVERY_CONCURRENCY: usize = 8;
#[cfg(not(test))]
const LOCK_TIMEOUT_SECONDS: i32 = 300;
const ERROR_MAX_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackchannelResponseAction {
    Delivered,
    Retry,
    TerminalFailure,
}

#[cfg(not(test))]
enum BackchannelPostOutcome {
    Delivered,
    TerminalFailure(u16),
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct BackchannelLogoutWorker {
    deliveries: AuditRepository,
    private_network_origins: Arc<HashSet<String>>,
}

#[cfg(not(test))]
impl BackchannelLogoutWorker {
    pub(crate) fn new(
        deliveries: AuditRepository,
        private_network_origins: &[String],
    ) -> anyhow::Result<Self> {
        let mut origins = HashSet::new();
        for value in private_network_origins {
            let endpoint = validate_backchannel_endpoint(value)
                .map_err(anyhow::Error::msg)
                .with_context(|| {
                    format!("invalid BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entry {value}")
                })?;
            if endpoint.path() != "/" || endpoint.query().is_some() {
                anyhow::bail!(
                    "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entries must be origins: {value}"
                );
            }
            origins.insert(endpoint.origin().ascii_serialization());
        }
        Ok(Self {
            deliveries,
            private_network_origins: Arc::new(origins),
        })
    }

    pub(crate) async fn process_due_batch(&self) -> anyhow::Result<usize> {
        let deliveries = self
            .deliveries
            .claim_due_backchannel_logout(DELIVERY_BATCH_SIZE, LOCK_TIMEOUT_SECONDS)
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
        match self.post(&delivery).await {
            Ok(BackchannelPostOutcome::Delivered) => self
                .deliveries
                .complete_backchannel_logout(delivery.id, delivery.attempts)
                .await
                .context("failed to complete back-channel logout delivery"),
            outcome => {
                let now = Utc::now();
                let (next_attempt_at, delivery_error) = match outcome {
                    Ok(BackchannelPostOutcome::TerminalFailure(status)) => (
                        None,
                        anyhow::anyhow!(
                            "back-channel logout endpoint returned terminal status {status}"
                        ),
                    ),
                    Err(error) => (
                        next_retry_at(delivery.attempts - 1, now, delivery.expires_at),
                        error,
                    ),
                    Ok(BackchannelPostOutcome::Delivered) => unreachable!(),
                };
                let last_error = truncate_error(&delivery_error.to_string());
                tracing::warn!(
                    error = %last_error,
                    retry_scheduled = next_attempt_at.is_some(),
                    failure_recorded_at = %now,
                    backchannel_logout_uri = %delivery.logout_uri,
                    "back-channel logout delivery failed"
                );
                self.deliveries
                    .fail_backchannel_logout(
                        delivery.id,
                        delivery.attempts,
                        next_attempt_at,
                        &last_error,
                    )
                    .await
                    .context("failed to record back-channel logout delivery failure")
            }
        }
    }

    async fn post(
        &self,
        delivery: &BackchannelLogoutDelivery,
    ) -> anyhow::Result<BackchannelPostOutcome> {
        let endpoint = validate_backchannel_endpoint(&delivery.logout_uri)
            .map_err(anyhow::Error::msg)
            .context("invalid stored back-channel logout endpoint")?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("back-channel logout endpoint has no host"))?;
        let port = endpoint
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("back-channel logout endpoint has no port"))?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .context("back-channel logout DNS resolution failed")?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            anyhow::bail!("back-channel logout DNS returned no addresses");
        }
        let allow_private = self
            .private_network_origins
            .contains(&endpoint.origin().ascii_serialization());
        if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            anyhow::bail!("back-channel logout endpoint resolved to a blocked network");
        }
        let http = reqwest::Client::builder()
            .connect_timeout(StdDuration::from_secs(3))
            .timeout(StdDuration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .context("failed to build back-channel logout HTTP client")?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", &delivery.logout_token)
            .finish();
        let response = http
            .post(&delivery.logout_uri)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .context("back-channel logout request failed")?;
        let status = response.status().as_u16();
        match classify_backchannel_status(status) {
            BackchannelResponseAction::Delivered => Ok(BackchannelPostOutcome::Delivered),
            BackchannelResponseAction::TerminalFailure => {
                Ok(BackchannelPostOutcome::TerminalFailure(status))
            }
            BackchannelResponseAction::Retry => {
                anyhow::bail!("back-channel logout endpoint returned retryable status {status}")
            }
        }
    }
}

fn validate_backchannel_endpoint(raw: &str) -> Result<Url, &'static str> {
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

#[cfg(not(test))]
pub(crate) fn spawn_backchannel_logout_delivery_worker(worker: BackchannelLogoutWorker) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = worker.process_due_batch().await {
                tracing::warn!(%error, "back-channel logout delivery worker failed");
            }
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
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
mod tests {
    use super::*;

    #[test]
    fn retries_are_bounded_and_never_scheduled_after_expiry() {
        let now = Utc::now();
        assert_eq!(
            next_retry_at(0, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(5))
        );
        assert_eq!(
            next_retry_at(1, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(15))
        );
        assert_eq!(
            next_retry_at(2, now, now + Duration::seconds(60)),
            Some(now + Duration::seconds(45))
        );
        assert_eq!(next_retry_at(3, now, now + Duration::seconds(60)), None);
        assert_eq!(next_retry_at(2, now, now + Duration::seconds(45)), None);
    }

    #[test]
    fn persisted_delivery_errors_are_unicode_safe_and_bounded() {
        let error = "失".repeat(ERROR_MAX_CHARS + 10);
        let truncated = truncate_error(&error);
        assert_eq!(truncated.chars().count(), ERROR_MAX_CHARS);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn backchannel_response_classification_retries_only_recoverable_statuses() {
        assert_eq!(
            classify_backchannel_status(200),
            BackchannelResponseAction::Delivered
        );
        assert_eq!(
            classify_backchannel_status(204),
            BackchannelResponseAction::Delivered
        );
        for status in [408, 425, 429, 500, 503, 599] {
            assert_eq!(
                classify_backchannel_status(status),
                BackchannelResponseAction::Retry,
                "status {status}"
            );
        }
        for status in [201, 202, 206, 300, 400, 401, 404, 422] {
            assert_eq!(
                classify_backchannel_status(status),
                BackchannelResponseAction::TerminalFailure,
                "status {status}"
            );
        }
    }

    #[test]
    fn backchannel_endpoint_validation_rejects_unsafe_transport_shapes() {
        assert!(validate_backchannel_endpoint("https://rp.example/logout?tenant=a").is_ok());
        assert!(validate_backchannel_endpoint("http://localhost:8080/logout").is_ok());
        for endpoint in [
            "http://rp.example/logout",
            "file:///tmp/logout",
            "https://user@rp.example/logout",
            "https://rp.example/logout#fragment",
            "not-a-uri",
        ] {
            assert!(
                validate_backchannel_endpoint(endpoint).is_err(),
                "endpoint {endpoint}"
            );
        }
    }
}
