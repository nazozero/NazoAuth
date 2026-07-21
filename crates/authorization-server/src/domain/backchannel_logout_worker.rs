use std::{collections::HashSet, net::SocketAddr, time::Duration as StdDuration};

#[cfg(not(test))]
use std::sync::Arc;

use anyhow::Context as _;
use chrono::{DateTime, Duration, Utc};
#[cfg(not(test))]
use futures_util::{StreamExt as _, stream};
#[cfg(not(test))]
use nazo_auth::BackchannelLogoutDelivery;
#[cfg(not(test))]
use nazo_postgres::AuditRepository;
use url::Url;

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

#[derive(Debug, Eq, PartialEq)]
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
        Ok(Self {
            deliveries,
            private_network_origins: Arc::new(parse_private_network_origins(
                private_network_origins,
            )?),
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
        match post_logout_token(
            &self.private_network_origins,
            &delivery.logout_uri,
            &delivery.logout_token,
        )
        .await
        {
            Ok(BackchannelPostOutcome::Delivered) => self
                .deliveries
                .complete_backchannel_logout(delivery.id, delivery.attempts)
                .await
                .context("failed to complete back-channel logout delivery"),
            outcome => {
                let now = Utc::now();
                let (next_attempt_at, delivery_error) =
                    delivery_failure_state(outcome, delivery.attempts, now, delivery.expires_at);
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
}

fn parse_private_network_origins(values: &[String]) -> anyhow::Result<HashSet<String>> {
    let mut origins = HashSet::new();
    for value in values {
        let endpoint = validate_backchannel_endpoint(value)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("invalid BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entry {value}"))?;
        if endpoint.path() != "/" || endpoint.query().is_some() {
            anyhow::bail!("BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS entries must be origins: {value}");
        }
        origins.insert(endpoint.origin().ascii_serialization());
    }
    Ok(origins)
}

fn delivery_failure_state(
    outcome: anyhow::Result<BackchannelPostOutcome>,
    attempts: i32,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> (Option<DateTime<Utc>>, anyhow::Error) {
    match outcome {
        Ok(BackchannelPostOutcome::TerminalFailure(status)) => (
            None,
            anyhow::anyhow!("back-channel logout endpoint returned terminal status {status}"),
        ),
        Err(error) => (next_retry_at(attempts - 1, now, expires_at), error),
        Ok(BackchannelPostOutcome::Delivered) => unreachable!(),
    }
}

async fn post_logout_token(
    private_network_origins: &HashSet<String>,
    logout_uri: &str,
    logout_token: &str,
) -> anyhow::Result<BackchannelPostOutcome> {
    let endpoint = validate_backchannel_endpoint(logout_uri)
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
    let allow_private = private_network_origins.contains(&endpoint.origin().ascii_serialization());
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
        .append_pair("logout_token", logout_token)
        .finish();
    let response = http
        .post(logout_uri)
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
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    async fn local_status_endpoint(status: u16) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener binds");
        let address = listener
            .local_addr()
            .expect("loopback address is available");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request arrives");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 16];
                let size = stream.read(&mut chunk).await.expect("request is readable");
                assert_ne!(size, 0, "request must contain its declared body");
                request.extend_from_slice(&chunk[..size]);
                let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .and_then(|value| value.parse::<usize>().ok())
                    .expect("request declares content length");
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /logout HTTP/1.1"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-www-form-urlencoded")
            );
            assert!(request.contains("logout_token=logout-token"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nLocation: /followed\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("response is writable");
        });
        (format!("http://{address}/logout"), task)
    }

    async fn post_to_local_status(status: u16) -> anyhow::Result<BackchannelPostOutcome> {
        let (logout_uri, server) = local_status_endpoint(status).await;
        let origin = Url::parse(&logout_uri)
            .expect("local endpoint is a URL")
            .origin()
            .ascii_serialization();
        let result = post_logout_token(&HashSet::from([origin]), &logout_uri, "logout-token").await;
        server.await.expect("local endpoint completes");
        result
    }

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

    #[test]
    fn private_network_origin_configuration_is_exact_and_normalized() {
        let origins = parse_private_network_origins(&[
            "https://rp.example".to_owned(),
            "http://localhost:8080".to_owned(),
        ])
        .expect("valid origins are accepted");
        assert_eq!(
            origins,
            HashSet::from([
                "https://rp.example".to_owned(),
                "http://localhost:8080".to_owned(),
            ])
        );

        for invalid in [
            "https://rp.example/logout",
            "https://rp.example?tenant=a",
            "http://rp.example",
        ] {
            let error = parse_private_network_origins(&[invalid.to_owned()])
                .expect_err("non-origin or unsafe entries are rejected");
            assert!(
                error
                    .to_string()
                    .contains("BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS")
            );
        }
    }

    #[test]
    fn delivery_failure_state_distinguishes_terminal_and_retryable_outcomes() {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(60);
        let (next_attempt_at, terminal) = delivery_failure_state(
            Ok(BackchannelPostOutcome::TerminalFailure(400)),
            1,
            now,
            expires_at,
        );
        assert_eq!(next_attempt_at, None);
        assert!(terminal.to_string().contains("terminal status 400"));

        let (next_attempt_at, retryable) = delivery_failure_state(
            Err(anyhow::anyhow!("network unavailable")),
            2,
            now,
            expires_at,
        );
        assert_eq!(next_attempt_at, Some(now + Duration::seconds(15)));
        assert_eq!(retryable.to_string(), "network unavailable");
    }

    #[tokio::test]
    async fn backchannel_post_enforces_network_and_response_policy() {
        assert_eq!(
            post_to_local_status(204).await.expect("204 is delivered"),
            BackchannelPostOutcome::Delivered
        );
        assert_eq!(
            post_to_local_status(400)
                .await
                .expect("400 is a terminal response"),
            BackchannelPostOutcome::TerminalFailure(400)
        );
        assert_eq!(
            post_to_local_status(302)
                .await
                .expect("redirects are terminal and are not followed"),
            BackchannelPostOutcome::TerminalFailure(302)
        );
        let retry = post_to_local_status(503)
            .await
            .expect_err("503 remains retryable");
        assert!(retry.to_string().contains("retryable status 503"));

        let blocked =
            post_logout_token(&HashSet::new(), "http://127.0.0.1:9/logout", "logout-token")
                .await
                .expect_err("private networks require an exact-origin allowlist");
        assert!(blocked.to_string().contains("blocked network"));
    }
}
