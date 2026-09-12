//! mTLS client certificate binding helpers.
//!
//! The application accepts certificate identity only from the direct TLS
//! connection or the standardized RFC 9440 `Client-Cert` field supplied by a
//! configured trusted proxy.

use actix_web::http::header::HeaderMap;
use actix_web::{HttpMessage, HttpRequest, dev::Extensions, web::Data};
use base64::{Engine, engine::general_purpose::STANDARD};
use nazo_http_actix::{IpCidr, mtls::MtlsThumbprintExtractor, request_from_trusted_proxy_cidrs};
use nazo_oauth_server::{
    contracts::token_client_auth::ClientCertificateFacts,
    security::mtls::{certificate_chain_verified, certificate_der_identity},
};
use std::{any::Any, sync::Arc};
const RFC9440_CLIENT_CERT_HEADER: &str = "client-cert";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectTlsServerName(String);

impl DirectTlsServerName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn capture_direct_tls_client_certificate(
    io: &dyn Any,
    extensions: &mut Extensions,
    deployment_verifier: Option<&dyn rustls::server::danger::ClientCertVerifier>,
) {
    let Some(stream) = io
        .downcast_ref::<actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>>()
    else {
        return;
    };
    if let Some(server_name) = stream.get_ref().1.server_name()
        && let Ok(server_name) = nazo_identity::canonical_tenant_host(server_name)
    {
        extensions.insert(DirectTlsServerName(server_name));
    }
    let Some(chain) = stream.get_ref().1.peer_certificates() else {
        return;
    };
    let Some((certificate, intermediates)) = chain.split_first() else {
        return;
    };
    if let Some(mut identity) = certificate_der_identity(certificate.as_ref()) {
        identity.certificate_chain_der = chain.iter().map(|der| der.as_ref().to_vec()).collect();
        identity.deployment_trusted_chain = deployment_verifier.is_some_and(|verifier| {
            verifier
                .verify_client_cert(
                    certificate,
                    intermediates,
                    rustls::pki_types::UnixTime::now(),
                )
                .is_ok()
        });
        extensions.insert(identity);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MtlsCertificateSourceMode {
    Disabled,
    DirectTls,
    Rfc9440,
}

impl MtlsCertificateSourceMode {
    pub(crate) fn from_config(value: Option<&str>) -> anyhow::Result<Self> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Disabled),
            Some("disabled") => Ok(Self::Disabled),
            Some("direct-tls") => Ok(Self::DirectTls),
            Some("rfc9440") => Ok(Self::Rfc9440),
            Some(value) => anyhow::bail!(
                "MTLS_CERTIFICATE_SOURCE must be disabled, direct-tls, or rfc9440; got {value}"
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MtlsCertificateSource {
    mode: MtlsCertificateSourceMode,
}

#[derive(Clone)]
struct ForwardedClientCertificate(Option<ClientCertificateFacts>);

impl MtlsCertificateSource {
    pub(crate) fn new(mode: MtlsCertificateSourceMode) -> Self {
        Self { mode }
    }
}

pub(crate) fn request_mtls_thumbprint(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<String> {
    request_mtls_client_certificate_from_configured_source(req, trusted_proxy_cidrs)?.thumbprint
}

pub(crate) fn request_mtls_client_certificate(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<ClientCertificateFacts> {
    request_mtls_client_certificate_from_configured_source(req, trusted_proxy_cidrs)
}

fn request_mtls_client_certificate_from_configured_source(
    req: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<ClientCertificateFacts> {
    let mode = req
        .app_data::<Data<MtlsCertificateSource>>()
        .map(|source| source.mode)
        .unwrap_or(MtlsCertificateSourceMode::Disabled);
    match mode {
        MtlsCertificateSourceMode::Disabled => None,
        MtlsCertificateSourceMode::DirectTls => req.conn_data::<ClientCertificateFacts>().cloned(),
        MtlsCertificateSourceMode::Rfc9440
            if request_from_trusted_proxy_cidrs(req, trusted_proxy_cidrs) =>
        {
            if let Some(cached) = req.extensions().get::<ForwardedClientCertificate>() {
                return cached.0.clone();
            }
            let certificate = request_mtls_client_certificate_from_rfc9440(req.headers()).map(
                |mut certificate| {
                    certificate.deployment_trusted_chain = req
                        .app_data::<Data<dyn rustls::server::danger::ClientCertVerifier>>()
                        .is_some_and(|verifier| {
                            certificate_chain_verified(&certificate, verifier.get_ref())
                        });
                    certificate
                },
            );
            // These transport facts are immutable for this request. Tenant
            // trust decisions remain with the caller's current tenant binding.
            req.extensions_mut()
                .insert(ForwardedClientCertificate(certificate.clone()));
            certificate
        }
        MtlsCertificateSourceMode::Rfc9440 => None,
    }
}

pub(crate) fn request_mtls_client_certificate_from_rfc9440(
    headers: &HeaderMap,
) -> Option<ClientCertificateFacts> {
    let mut values = headers.get_all(RFC9440_CLIENT_CERT_HEADER);
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || value.len() < 3 {
        return None;
    }
    let der = decode_forwarded_certificate(value)?;
    let mut certificate = certificate_der_identity(&der)?;
    let mut chains = headers.get_all("client-cert-chain");
    if let Some(chain) = chains.next() {
        if chains.next().is_some() {
            return None;
        }
        for value in chain.to_str().ok()?.split(',') {
            certificate
                .certificate_chain_der
                .push(decode_forwarded_certificate(value.trim())?);
        }
    }
    Some(certificate)
}

fn decode_forwarded_certificate(value: &str) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix(':')?.strip_suffix(':')?;
    if encoded.is_empty() || encoded.chars().any(char::is_whitespace) {
        return None;
    }
    STANDARD.decode(encoded).ok()
}

pub(crate) struct ServerMtlsThumbprintExtractor {
    trusted_proxy_cidrs: Arc<[IpCidr]>,
}

impl ServerMtlsThumbprintExtractor {
    pub(crate) fn new(trusted_proxy_cidrs: Vec<IpCidr>) -> Self {
        Self {
            trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
        }
    }
}

impl MtlsThumbprintExtractor for ServerMtlsThumbprintExtractor {
    fn resolve(&self, request: &HttpRequest) -> Option<String> {
        request_mtls_thumbprint(request, &self.trusted_proxy_cidrs)
    }
}
#[cfg(test)]
#[path = "../../tests/unit/http/mtls.rs"]
mod tests;
