//! Native outbound exchanges for configured identity providers.
use bytes::{Bytes, BytesMut};
use nazoauth::capabilities::FederationHttpClient;

pub(crate) struct FederationClient(reqwest::Client);

impl FederationClient {
    pub(crate) fn new() -> anyhow::Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        ))
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
            let (parts, body) = request.into_parts();
            let mut response = self
                .0
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await?
                .error_for_status()?;
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
        })
    }
}
