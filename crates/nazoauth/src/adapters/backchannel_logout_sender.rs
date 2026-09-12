//! Native DNS and HTTP delivery for back-channel logout.
use crate::adapters::sector_identifier::is_blocked_ip;
use anyhow::Context as _;
use nazo_auth::BackchannelLogoutDelivery;
use nazo_oauth_server::workers::backchannel_logout::{
    BackchannelLogoutSender, validate_backchannel_endpoint,
};
use std::{collections::HashSet, net::SocketAddr, time::Duration as StdDuration};

pub(crate) struct NativeBackchannelLogoutSender {
    private_network_origins: HashSet<String>,
}
impl NativeBackchannelLogoutSender {
    pub(crate) fn new(private_network_origins: &[String]) -> anyhow::Result<Self> {
        Ok(Self {
            private_network_origins: parse_private_network_origins(private_network_origins)?,
        })
    }
}
impl BackchannelLogoutSender for NativeBackchannelLogoutSender {
    fn send<'a>(
        &'a self,
        delivery: &'a BackchannelLogoutDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    > {
        Box::pin(post_logout_token(
            &self.private_network_origins,
            &delivery.logout_uri,
            &delivery.logout_token,
        ))
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

async fn post_logout_token(
    private_network_origins: &HashSet<String>,
    logout_uri: &str,
    logout_token: &str,
) -> anyhow::Result<http::StatusCode> {
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
        .no_proxy()
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
        .header(
            reqwest::header::HeaderName::from_static("idempotency-key"),
            backchannel_idempotency_key(logout_token),
        )
        .body(body)
        .send()
        .await
        .context("back-channel logout request failed")?;
    Ok(response.status())
}

fn backchannel_idempotency_key(logout_token: &str) -> String {
    format!(
        "nazo-backchannel-logout-{}",
        blake3::hash(logout_token.as_bytes()).to_hex()
    )
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/backchannel_logout_sender.rs"]
mod tests;
