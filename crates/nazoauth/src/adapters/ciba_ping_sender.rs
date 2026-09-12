use super::{ciba_ping_tls::apply_ciba_ping_tls_policy, sector_identifier::is_blocked_ip};
use anyhow::Context as _;
use nazo_auth::validate_ciba_notification_endpoint;
use nazo_oauth_server::{
    ports::transient_state::CibaPingDelivery, workers::ciba_ping::CibaPingSender,
};
use reqwest::header;
use serde_json::json;
use std::{collections::HashSet, net::SocketAddr, time::Duration};

pub(crate) struct CibaPingHttpSender {
    private_network_origins: HashSet<String>,
}
impl CibaPingHttpSender {
    pub(crate) fn new(private_network_origins: &[String]) -> anyhow::Result<Self> {
        let mut origins = HashSet::new();
        for value in private_network_origins {
            let parsed = validate_ciba_notification_endpoint(value)
                .map_err(anyhow::Error::msg)
                .with_context(|| {
                    format!("invalid CIBA_NOTIFICATION_PRIVATE_ORIGINS entry {value}")
                })?;
            if parsed.path() != "/" || parsed.query().is_some() {
                anyhow::bail!(
                    "CIBA_NOTIFICATION_PRIVATE_ORIGINS entries must be HTTPS origins: {value}"
                );
            }
            origins.insert(parsed.origin().ascii_serialization());
        }
        Ok(Self {
            private_network_origins: origins,
        })
    }

    async fn post(&self, delivery: &CibaPingDelivery) -> anyhow::Result<http::StatusCode> {
        let endpoint =
            validate_ciba_notification_endpoint(&delivery.endpoint).map_err(anyhow::Error::msg)?;
        let host = endpoint
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("CIBA ping endpoint has no host"))?;
        let port = endpoint.port_or_known_default().unwrap_or(443);
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .context("CIBA ping DNS resolution failed")?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            anyhow::bail!("CIBA ping DNS returned no addresses");
        }
        let allow_private = self
            .private_network_origins
            .contains(&endpoint.origin().ascii_serialization());
        if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            anyhow::bail!("CIBA ping endpoint resolved to a blocked network");
        }
        let client = apply_ciba_ping_tls_policy(reqwest::Client::builder().no_proxy())?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .context("failed to build CIBA ping HTTP client")?;
        let response = client
            .post(endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::HeaderName::from_static("idempotency-key"),
                ciba_ping_idempotency_key(&delivery.auth_req_id_hash),
            )
            .bearer_auth(&delivery.client_notification_token)
            .json(&json!({"auth_req_id": delivery.auth_req_id}))
            .send()
            .await
            .context("CIBA ping request failed")?;
        Ok(response.status())
    }
}
fn ciba_ping_idempotency_key(auth_req_id_hash: &str) -> String {
    format!("nazo-ciba-ping-{auth_req_id_hash}")
}

impl CibaPingSender for CibaPingHttpSender {
    fn send<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    > {
        Box::pin(self.post(delivery))
    }
}
#[cfg(test)]
#[path = "../../tests/unit/domain/ciba_ping_delivery.rs"]
mod tests;
