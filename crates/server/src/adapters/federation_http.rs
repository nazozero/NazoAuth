//! Native outbound exchanges for configured identity providers.
use bytes::{Bytes, BytesMut};
use nazoauth::capabilities::FederationHttpClient;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(10);

fn federation_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
}

pub(crate) struct FederationClient(reqwest::Client);

impl FederationClient {
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self(federation_client().build()?))
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
        Box::pin(exchange(&self.0, request, max_response_bytes))
    }

    fn send_discovered(
        &self,
        request: http::Request<Bytes>,
        max_response_bytes: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::Response<Bytes>>> + Send + '_>,
    > {
        Box::pin(async move {
            tokio::time::timeout(DEADLINE, async {
                // Resolve the same normalized host reqwest will connect to.
                let url = reqwest::Url::parse(&request.uri().to_string())?;
                anyhow::ensure!(url.scheme() == "https", "discovery requires HTTPS");
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("missing issuer host"))?
                    .trim_matches(['[', ']']);
                let addresses = tokio::net::lookup_host((host, url.port().unwrap_or(443)))
                    .await?
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    !addresses.is_empty()
                        && !addresses
                            .iter()
                            .any(|addr| { super::sector_identifier::is_blocked_ip(addr.ip()) }),
                    "discovered endpoint resolved to a blocked network"
                );
                let client = federation_client()
                    .resolve_to_addrs(host, &addresses)
                    .build()?;
                exchange(&client, request, max_response_bytes).await
            })
            .await?
        })
    }
}

async fn exchange(
    client: &reqwest::Client,
    request: http::Request<Bytes>,
    max_response_bytes: usize,
) -> anyhow::Result<http::Response<Bytes>> {
    let (parts, body) = request.into_parts();
    let mut response = client
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await?;
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
