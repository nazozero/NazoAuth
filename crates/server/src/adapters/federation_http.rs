//! Native outbound exchanges for configured identity providers.
use bytes::{Bytes, BytesMut};
use nazoauth::capabilities::FederationHttpClient;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{net::IpAddr, time::Duration};

const DEADLINE: Duration = Duration::from_secs(10);

fn federation_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
}

pub(crate) struct FederationClient {
    configured: reqwest::Client,
    discovered: reqwest::Client,
}

// The connector consumes these exact answers. Checking here preserves pooling
// without a separate DNS preflight or a second, unchecked resolution.
struct PublicFederationDns;

impl Resolve for PublicFederationDns {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .collect::<Vec<_>>();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| super::sector_identifier::is_blocked_ip(address.ip()))
            {
                return Err("discovered endpoint resolved to a blocked network".into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

impl FederationClient {
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self {
            configured: federation_client().build()?,
            discovered: federation_client()
                .https_only(true)
                .dns_resolver(PublicFederationDns)
                .build()?,
        })
    }
}

impl FederationHttpClient for FederationClient {
    fn send(
        &self,
        request: http::Request<Bytes>,
        max_response_bytes: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::Response<Bytes>>> + Send + '_>,
    > {
        Box::pin(async move {
            exchange(&self.configured, request.try_into()?, max_response_bytes).await
        })
    }

    fn send_discovered(
        &self,
        request: http::Request<Bytes>,
        max_response_bytes: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::Response<Bytes>>> + Send + '_>,
    > {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request)?;
            // Literal IPs bypass reqwest's DNS resolver, including normalized
            // spellings such as 2130706433 and IPv4-mapped IPv6 addresses.
            let ip = match request.url().host() {
                Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
                Some(url::Host::Domain(_)) => None,
                None => anyhow::bail!("missing issuer host"),
            };
            anyhow::ensure!(
                ip.is_none_or(|ip| !super::sector_identifier::is_blocked_ip(ip)),
                "discovered endpoint resolved to a blocked network"
            );
            exchange(&self.discovered, request, max_response_bytes).await
        })
    }
}

async fn exchange(
    client: &reqwest::Client,
    request: reqwest::Request,
    max_response_bytes: usize,
) -> anyhow::Result<http::Response<Bytes>> {
    let mut response = client.execute(request).await?;
    anyhow::ensure!(
        response.status().is_success(),
        "federation provider returned a non-success status"
    );
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        anyhow::bail!("federation provider response is too large");
    }
    let mut output = http::Response::new(Bytes::new());
    *output.status_mut() = response.status();
    *output.headers_mut() = std::mem::take(response.headers_mut());
    let mut body = Bytes::new();
    let mut buffer: Option<BytesMut> = None;
    while let Some(chunk) = response.chunk().await? {
        let length = buffer.as_ref().map_or(body.len(), BytesMut::len);
        if chunk.len() > max_response_bytes - length {
            anyhow::bail!("federation provider response is too large");
        }
        if chunk.is_empty() {
            continue;
        }
        if let Some(buffer) = buffer.as_mut() {
            buffer.extend_from_slice(&chunk);
        } else if body.is_empty() {
            body = chunk;
        } else {
            let mut combined = BytesMut::with_capacity(body.len() + chunk.len());
            combined.extend_from_slice(&body);
            combined.extend_from_slice(&chunk);
            buffer = Some(combined);
        }
    }
    *output.body_mut() = buffer.map_or(body, BytesMut::freeze);
    Ok(output)
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/federation_http.rs"]
mod tests;
