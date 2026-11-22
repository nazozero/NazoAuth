//! Bounded Workers fetch adapters. Operators admit exact HTTPS origins; there
//! is no arbitrary redirect, ambient credential forwarding, or native socket.
use std::{collections::BTreeSet, sync::Arc, time::Duration};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use nazo_digital_credentials::{CredentialFormat, CredentialTrustError};
use nazo_oauth_server::{
    ports::transient_state::CibaPingDelivery,
    workers::{backchannel_logout::BackchannelLogoutSender, ciba_ping::CibaPingSender},
};

#[derive(Clone)]
pub(crate) struct Outbound {
    origins: Arc<BTreeSet<String>>,
}

impl Outbound {
    pub(crate) fn new(origins: &[String]) -> anyhow::Result<Self> {
        let mut admitted = BTreeSet::new();
        for origin in origins {
            let url = https_url(origin, false)?;
            ensure!(
                url.path() == "/" && url.query().is_none(),
                "outbound entries must be HTTPS origins"
            );
            admitted.insert(url.origin().ascii_serialization());
        }
        Ok(Self {
            origins: Arc::new(admitted),
        })
    }

    fn admit(&self, raw: &str, allow_fragment: bool) -> anyhow::Result<url::Url> {
        let mut url = https_url(raw, allow_fragment)?;
        ensure!(
            self.origins.contains(&url.origin().ascii_serialization()),
            "outbound origin is not admitted"
        );
        url.set_fragment(None);
        Ok(url)
    }

    pub(crate) async fn send(
        &self,
        request: Request<Bytes>,
        limit: usize,
        timeout: Duration,
    ) -> anyhow::Result<Response<Bytes>> {
        self.admit(&request.uri().to_string(), false)?;
        transport(request, limit, timeout).await
    }

    async fn document(&self, uri: &str, media: &[&str], fragment: bool) -> anyhow::Result<Bytes> {
        let url = self.admit(uri, fragment)?;
        let request = Request::builder()
            .uri(url.as_str())
            .header(header::ACCEPT, media.join(", "))
            .body(Bytes::new())?;
        let response = transport(request, 128 * 1024, Duration::from_secs(10)).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "remote document returned a non-success status"
        );
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        ensure!(
            media
                .iter()
                .any(|accepted| content_type.eq_ignore_ascii_case(accepted)),
            "remote document content type is unsupported"
        );
        Ok(response.into_body())
    }
}

fn https_url(raw: &str, allow_fragment: bool) -> anyhow::Result<url::Url> {
    ensure!(raw.len() <= 8192, "outbound URL is too long");
    let url = url::Url::parse(raw).context("invalid outbound URL")?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && (allow_fragment || url.fragment().is_none()),
        "outbound URL must use HTTPS without credentials or fragment"
    );
    let host = url
        .host_str()
        .context("outbound URL has no host")?
        .trim_matches(['[', ']']);
    // Exact origin admission is the authority on Workers. Unlike native DNS
    // resolution, fetch does not expose IP pinning. Never infer an allowlist
    // from user-controlled client metadata or an unpinned DNS preflight.
    ensure!(
        !host.eq_ignore_ascii_case("localhost")
            && !host.ends_with(".localhost")
            && !host.ends_with(".local")
            && host.parse::<std::net::IpAddr>().is_err()
            && host.contains('.'),
        "outbound URL must use an admitted public DNS name"
    );
    Ok(url)
}

#[cfg(target_arch = "wasm32")]
async fn transport(
    request: Request<Bytes>,
    limit: usize,
    timeout: Duration,
) -> anyhow::Result<Response<Bytes>> {
    use futures_util::{
        StreamExt as _,
        future::{Either, select},
    };
    worker::send::SendFuture::new(async move {
        let abort = worker::AbortController::default();
        let signal = abort.signal();
        let exchange = async {
            let (parts, body) = request.into_parts();
            let headers = worker::Headers::new();
            for (name, value) in &parts.headers {
                headers.append(name.as_str(), value.to_str()?)?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::from(parts.method.as_str().to_owned()))
                .with_headers(headers)
                .with_redirect(worker::RequestRedirect::Manual)
                .with_cache(worker::CacheMode::NoStore);
            if !body.is_empty() {
                init.with_body(Some(worker::js_sys::Uint8Array::from(body.as_ref()).into()));
            }
            let request = worker::Request::new_with_init(&parts.uri.to_string(), &init)?;
            let mut response = worker::Fetch::Request(request)
                .send_with_signal(&signal)
                .await
                .map_err(|_| anyhow::anyhow!("outbound request failed"))?;
            let mut output = Response::builder().status(response.status_code());
            for (name, value) in response.headers().entries() {
                output = output.header(name, value);
            }
            let mut bytes = Vec::new();
            if limit > 0 {
                if let Some(length) = response
                    .headers()
                    .get("content-length")?
                    .and_then(|value| value.parse::<usize>().ok())
                {
                    ensure!(length <= limit, "outbound response exceeds its size limit");
                }
                let mut stream = response.stream()?;
                while let Some(chunk) = stream.next().await {
                    let chunk =
                        chunk.map_err(|_| anyhow::anyhow!("outbound response read failed"))?;
                    ensure!(
                        chunk.len() <= limit.saturating_sub(bytes.len()),
                        "outbound response exceeds its size limit"
                    );
                    bytes.extend_from_slice(&chunk);
                }
            }
            Ok(output.body(Bytes::from(bytes))?)
        };
        let result = match select(Box::pin(exchange), Box::pin(worker::Delay::from(timeout))).await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(anyhow::anyhow!("outbound request timed out")),
        };
        abort.abort();
        result
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
async fn transport(_: Request<Bytes>, _: usize, _: Duration) -> anyhow::Result<Response<Bytes>> {
    anyhow::bail!("Workers fetch requires the Workers runtime")
}

impl nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
    for Outbound
{
    fn resolve<'a>(
        &'a self,
        uri: &'a str,
        _: Option<&'a str>,
    ) -> nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksFuture<'a> {
        Box::pin(async move {
            // No pending fetch or stale JWKS is shared between request contexts.
            let document: serde_json::Value = serde_json::from_slice(
                &self
                    .document(
                        uri,
                        &["application/json", "application/jwk-set+json"],
                        false,
                    )
                    .await
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|_| "remote JWKS is not valid JSON".to_owned())?;
            if !document
                .get("keys")
                .is_some_and(serde_json::Value::is_array)
            {
                return Err("remote JWKS must contain a keys array".into());
            }
            Ok(Arc::new(document))
        })
    }
}

impl nazo_auth::SectorIdentifierResolverPort for Outbound {
    fn resolve<'a>(&'a self, uri: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async move {
            let values: Vec<String> = serde_json::from_slice(
                &self
                    .document(uri, &["application/json"], false)
                    .await
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|_| "sector identifier document is not a JSON URI array".to_owned())?;
            for value in &values {
                url::Url::parse(value)
                    .map_err(|_| "sector identifier entry is not a URI".to_owned())?;
            }
            Ok(values)
        })
    }
}

impl nazo_oauth_server::ports::remote_request_object::RemoteRequestObjectResolverPort for Outbound {
    fn resolve_request_object<'a>(
        &'a self,
        uri: &'a str,
    ) -> nazo_oauth_server::ports::remote_request_object::RequestObjectFuture<'a> {
        Box::pin(async move {
            let bytes = self
                .document(
                    uri,
                    &["application/jwt", "application/oauth-authz-req+jwt"],
                    true,
                )
                .await
                .map_err(|error| error.to_string())?;
            let jwt = std::str::from_utf8(&bytes)
                .map_err(|_| "remote request object must be UTF-8".to_owned())?
                .trim();
            if jwt.is_empty() {
                return Err("remote request object is empty".into());
            }
            Ok(jwt.to_owned())
        })
    }
}

impl nazo_oauth_server::ports::credential_status::CredentialStatusResolver for Outbound {
    fn fetch<'a>(
        &'a self,
        uri: &'a str,
        format: CredentialFormat,
    ) -> nazo_digital_credentials::CredentialFuture<'a, Result<Vec<u8>, CredentialTrustError>> {
        Box::pin(async move {
            let media = match format {
                CredentialFormat::SdJwtVc => "application/statuslist+jwt",
                CredentialFormat::MsoMdoc => "application/statuslist+cwt",
            };
            self.document(uri, &[media], false)
                .await
                .map(Vec::from)
                .map_err(|_| CredentialTrustError::Unavailable)
        })
    }
}

impl nazoauth::capabilities::FederationHttpClient for Outbound {
    fn send(
        &self,
        request: Request<Bytes>,
        max_response_bytes: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Response<Bytes>>> + Send + '_>,
    > {
        Box::pin(async move {
            let response = self
                .send(request, max_response_bytes, Duration::from_secs(10))
                .await?;
            ensure!(
                response.status().is_success(),
                "federation provider returned a non-success status"
            );
            Ok(response)
        })
    }

    fn send_discovered(
        &self,
        request: Request<Bytes>,
        max_response_bytes: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Response<Bytes>>> + Send + '_>,
    > {
        nazoauth::capabilities::FederationHttpClient::send(self, request, max_response_bytes)
    }
}

impl CibaPingSender for Outbound {
    fn send<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<StatusCode>> + Send + 'a>>
    {
        Box::pin(async move {
            nazo_auth::validate_ciba_notification_endpoint(&delivery.endpoint)
                .map_err(anyhow::Error::msg)?;
            let request = Request::builder()
                .method("POST")
                .uri(&delivery.endpoint)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", delivery.client_notification_token),
                )
                .header(
                    "idempotency-key",
                    format!("nazo-ciba-ping-{}", delivery.auth_req_id_hash),
                )
                .body(Bytes::from(serde_json::to_vec(
                    &serde_json::json!({"auth_req_id": delivery.auth_req_id}),
                )?))?;
            Ok(self
                .send(request, 0, Duration::from_secs(5))
                .await?
                .status())
        })
    }
}

impl BackchannelLogoutSender for Outbound {
    fn send<'a>(
        &'a self,
        delivery: &'a nazo_auth::BackchannelLogoutDelivery,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<StatusCode>> + Send + 'a>>
    {
        Box::pin(async move {
            nazo_oauth_server::workers::backchannel_logout::validate_backchannel_endpoint(
                &delivery.logout_uri,
            )
            .map_err(anyhow::Error::msg)?;
            let body = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("logout_token", &delivery.logout_token)
                .finish();
            let request = Request::builder()
                .method("POST")
                .uri(&delivery.logout_uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Bytes::from(body))?;
            Ok(self
                .send(request, 0, Duration::from_secs(5))
                .await?
                .status())
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/outbound.rs"]
mod tests;
