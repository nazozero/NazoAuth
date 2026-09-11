use std::{collections::HashSet, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use super::jwks_cache::{JwksCache, Lookup};
use futures_util::StreamExt;
use reqwest::{StatusCode, header};
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};
use url::Url;

use super::sector_identifier::{
    MAX_RESPONSE_BYTES, is_blocked_host, is_blocked_ip, parse_sector_identifier_document,
};

const JWKS_CACHE_TTL: Duration = Duration::from_secs(30);
const JWKS_CACHE_CAPACITY: usize = 256;
const REMOTE_DOCUMENT_DEADLINE: Duration = Duration::from_secs(10);
const REMOTE_FETCH_CONCURRENCY: usize = 16;

#[derive(Clone)]
pub(crate) struct RemoteClientDocumentResolver {
    private_network_origins: Arc<HashSet<String>>,
    jwks_cache: Arc<JwksCache>,
    cache_epoch: Instant,
    fetch_slots: Arc<Semaphore>,
    root_certificates: Arc<Vec<reqwest::Certificate>>,
}

impl RemoteClientDocumentResolver {
    pub(crate) fn new(private_network_origins: &[String]) -> Result<Self, String> {
        Self::new_with_root_certificates(private_network_origins, Vec::new())
    }

    pub(crate) fn new_with_root_certificates(
        private_network_origins: &[String],
        root_certificates: Vec<reqwest::Certificate>,
    ) -> Result<Self, String> {
        let mut origins = HashSet::new();
        for value in private_network_origins {
            let parsed = validate_https_url(value, false)?;
            if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(format!(
                    "REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS entry must be an HTTPS origin: {value}"
                ));
            }
            origins.insert(parsed.origin().ascii_serialization());
        }
        Ok(Self {
            private_network_origins: Arc::new(origins),
            jwks_cache: Arc::new(JwksCache::new(
                NonZeroUsize::new(JWKS_CACHE_CAPACITY).expect("nonzero JWKS capacity"),
                JWKS_CACHE_TTL,
            )),
            cache_epoch: Instant::now(),
            fetch_slots: Arc::new(Semaphore::new(REMOTE_FETCH_CONCURRENCY)),
            root_certificates: Arc::new(root_certificates),
        })
    }

    /// An unknown key can force one refresh per cached URI entry, including
    /// failed attempts. Once that budget is spent, signature verification
    /// rejects missing keys from the cached document. A refresh failure itself
    /// is returned directly and never falls back to stale cached material.
    pub(crate) async fn jwks_for_kid(
        &self,
        uri: &str,
        expected_kid: Option<&str>,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + REMOTE_DOCUMENT_DEADLINE;
        let cache_key = canonical_cache_key(uri)?;
        let cached = self.jwks_cache.get(&cache_key, self.cache_epoch.elapsed());
        if let Some(document) = &cached
            && jwks_contains_kid(document, expected_kid)
        {
            return Ok(document.as_ref().clone());
        }
        let document =
            match self
                .jwks_cache
                .begin(cache_key, cached.as_ref(), self.cache_epoch.elapsed())
            {
                Lookup::Ready(document) => document,
                Lookup::Wait(pending) => timeout_at(deadline, pending)
                    .await
                    .map_err(|_| "remote document request timed out".to_owned())??,
                Lookup::Fetch(guard) => {
                    let result = timeout_at(deadline, self.fetch_jwks(uri, deadline))
                        .await
                        .map_err(|_| "remote document request timed out".to_owned())
                        .and_then(|result| result);
                    guard.finish(result, self.cache_epoch.elapsed())?
                }
            };
        Ok(document.as_ref().clone())
    }

    async fn fetch_jwks(&self, uri: &str, deadline: Instant) -> Result<Value, String> {
        let fetched = self.fetch(uri, RemoteDocumentKind::Jwks, deadline).await?;
        let document: Value = serde_json::from_slice(&fetched.body)
            .map_err(|_| "remote JWKS is not valid JSON".to_owned())?;
        if !document.is_object() || !document.get("keys").is_some_and(Value::is_array) {
            return Err("remote JWKS must be an object containing a keys array".to_owned());
        }
        Ok(document)
    }

    pub(crate) async fn sector_identifier_uris(&self, uri: &str) -> Result<Vec<String>, String> {
        let deadline = Instant::now() + REMOTE_DOCUMENT_DEADLINE;
        let fetched = self
            .fetch(uri, RemoteDocumentKind::SectorIdentifier, deadline)
            .await?;
        parse_sector_identifier_document(&fetched.content_type, &fetched.body)
            .map_err(|error| format!("{error:?}"))
    }

    pub(crate) async fn request_object(&self, uri: &str) -> Result<String, String> {
        let deadline = Instant::now() + REMOTE_DOCUMENT_DEADLINE;
        let fetched = self
            .fetch(uri, RemoteDocumentKind::RequestObject, deadline)
            .await?;
        let jwt = String::from_utf8(fetched.body)
            .map_err(|_| "remote request object must be UTF-8".to_owned())?;
        let jwt = jwt.trim();
        if jwt.is_empty() || jwt.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("remote request object is empty or oversized".to_owned());
        }
        Ok(jwt.to_owned())
    }

    async fn fetch(
        &self,
        uri: &str,
        kind: RemoteDocumentKind,
        deadline: Instant,
    ) -> Result<RemoteDocument, String> {
        let parsed = validate_https_url(uri, kind == RemoteDocumentKind::RequestObject)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "remote document URI has no host".to_owned())?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let allow_private = kind != RemoteDocumentKind::SectorIdentifier
            && self
                .private_network_origins
                .contains(&parsed.origin().ascii_serialization());
        if kind == RemoteDocumentKind::SectorIdentifier && is_blocked_host(host) {
            return Err("sector identifier URI resolves to a blocked network".to_owned());
        }
        let _permit = self
            .fetch_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "remote document concurrency limit reached".to_owned())?;
        let addresses = timeout_at(deadline, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| "remote document DNS resolution timed out".to_owned())?
            .map_err(|_| "remote document DNS resolution failed".to_owned())?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            return Err("remote document DNS returned no addresses".to_owned());
        }
        if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            return Err("remote document resolved to a blocked network".to_owned());
        }

        let mut client_builder = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        for certificate in self.root_certificates.iter() {
            client_builder = client_builder.add_root_certificate(certificate.clone());
        }
        let client = client_builder
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| "remote document HTTP client could not be built".to_owned())?;
        let response = timeout_at(deadline, client.get(parsed).send())
            .await
            .map_err(|_| "remote document request timed out".to_owned())?
            .map_err(|error| {
                if error.is_timeout() {
                    "remote document request timed out".to_owned()
                } else {
                    "remote document request failed".to_owned()
                }
            })?;
        if response.status() != StatusCode::OK {
            return Err("remote document returned a non-success status".to_owned());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err("remote document is oversized".to_owned());
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !kind.accepts_content_type(&content_type) {
            return Err("remote document has an unsupported content type".to_owned());
        }
        let body = timeout_at(deadline, async move {
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|_| "remote document body could not be read".to_owned())?;
                if body.len().saturating_add(chunk.len()) as u64 > MAX_RESPONSE_BYTES {
                    return Err("remote document is oversized".to_owned());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        })
        .await
        .map_err(|_| "remote document body timed out".to_owned())??;
        Ok(RemoteDocument { content_type, body })
    }
}

struct RemoteDocument {
    content_type: String,
    body: Vec<u8>,
}

fn canonical_cache_key(uri: &str) -> Result<String, String> {
    let parsed = validate_https_url(uri, true)?;
    Ok(parsed.to_string())
}

fn jwks_contains_kid(document: &Value, expected_kid: Option<&str>) -> bool {
    let Some(expected_kid) = expected_kid else {
        return true;
    };
    document
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key.get("kid").and_then(Value::as_str) == Some(expected_kid))
        })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RemoteDocumentKind {
    Jwks,
    RequestObject,
    SectorIdentifier,
}

impl RemoteDocumentKind {
    fn accepts_content_type(self, content_type: &str) -> bool {
        let media_type = content_type.split(';').next().unwrap_or_default().trim();
        match self {
            Self::Jwks => {
                matches!(media_type, "application/json" | "application/jwk-set+json")
            }
            Self::RequestObject => matches!(
                media_type,
                "application/jwt" | "application/oauth-authz-req+jwt"
            ),
            Self::SectorIdentifier => media_type == "application/json",
        }
    }
}

fn validate_https_url(value: &str, allow_fragment: bool) -> Result<Url, String> {
    let parsed = Url::parse(value).map_err(|_| "remote document URI is invalid".to_owned())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (!allow_fragment && parsed.fragment().is_some())
    {
        return Err(
            "remote document URI must be an absolute HTTPS URI without userinfo".to_owned(),
        );
    }
    Ok(parsed)
}

impl nazo_http_actix::RemoteJwksResolverPort for RemoteClientDocumentResolver {
    fn resolve<'a>(
        &'a self,
        uri: &'a str,
        expected_kid: Option<&'a str>,
    ) -> nazo_http_actix::RemoteJwksFuture<'a> {
        Box::pin(async move { self.jwks_for_kid(uri, expected_kid).await })
    }
}

impl nazo_auth::SectorIdentifierResolverPort for RemoteClientDocumentResolver {
    fn resolve<'a>(&'a self, uri: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async move { self.sector_identifier_uris(uri).await })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/remote_client_documents.rs"]
pub(crate) mod tests;
