//! Request certificate facts, selected lazily from direct TLS or a trusted RFC 9440 peer.

use std::sync::{Arc, OnceLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use http::HeaderMap;
use nazo_crypto::certificate::CertificateDer;
use nazo_oauth_server::{
    contracts::token_client_auth::ClientCertificateFacts,
    security::mtls::certificate_chain_identity,
};

use crate::http::{
    IpCidr, Request, mtls::MtlsThumbprintExtractor, request_from_trusted_proxy_cidrs,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MtlsCertificateSourceMode {
    #[default]
    Disabled,
    DirectTls,
    Rfc9440,
}

/// Verifies the presented chain against the deployment's configured CA material.
/// Registered-client and token-binding decisions remain in the application.
pub trait CertificateChainVerifier: Send + Sync {
    fn verify(&self, chain: &[CertificateDer<'static>]) -> bool;
}

pub struct MtlsCertificateSource {
    pub mode: MtlsCertificateSourceMode,
    pub trusted_proxy_cidrs: Box<[IpCidr]>,
    pub verifier: Option<Arc<dyn CertificateChainVerifier>>,
}

#[derive(Clone, Default)]
pub struct ForwardedClientCertificate(pub OnceLock<Option<ClientCertificateFacts>>);

impl MtlsCertificateSource {
    pub fn new(
        mode: MtlsCertificateSourceMode,
        trusted_proxy_cidrs: &[IpCidr],
        verifier: Option<Arc<dyn CertificateChainVerifier>>,
    ) -> Self {
        Self {
            mode,
            trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
            verifier,
        }
    }

    /// Installs request-local state without parsing certificates or accepting a peer.
    pub fn prepare_request(self: &Arc<Self>, request: &mut Request) {
        if self.mode == MtlsCertificateSourceMode::Disabled {
            return;
        }
        request.extensions_mut().insert(Arc::clone(self));
        if self.mode == MtlsCertificateSourceMode::Rfc9440 {
            request
                .extensions_mut()
                .insert(ForwardedClientCertificate::default());
        }
    }
}

pub fn request_mtls_thumbprint(request: &Request) -> Option<String> {
    with_request_mtls_client_certificate(request, |certificate| {
        certificate.and_then(|certificate| certificate.thumbprint.clone())
    })
}

pub fn request_mtls_client_certificate(request: &Request) -> Option<ClientCertificateFacts> {
    with_request_mtls_client_certificate(request, |certificate| certificate.cloned())
}

pub fn with_request_mtls_client_certificate<'a, R>(
    request: &'a Request,
    project: impl FnOnce(Option<&'a ClientCertificateFacts>) -> R,
) -> R {
    let Some(source) = request.extensions().get::<Arc<MtlsCertificateSource>>() else {
        return project(None);
    };
    match source.mode {
        MtlsCertificateSourceMode::Disabled => project(None),
        MtlsCertificateSourceMode::DirectTls => project(
            request
                .extensions()
                .get::<crate::ConnectionFacts>()
                .and_then(|connection| connection.client_certificate.as_deref()),
        ),
        MtlsCertificateSourceMode::Rfc9440 => {
            let cached = request
                .extensions()
                .get::<ForwardedClientCertificate>()
                .expect("facade prepares the RFC 9440 request cache");
            let certificate = cached.0.get_or_init(|| {
                if !request_from_trusted_proxy_cidrs(request, &source.trusted_proxy_cidrs) {
                    return None;
                }
                let mut certificate =
                    request_mtls_client_certificate_from_rfc9440(request.headers())?;
                certificate.deployment_trusted_chain = source
                    .verifier
                    .as_ref()
                    .is_some_and(|verifier| verifier.verify(&certificate.certificate_chain_der));
                Some(certificate)
            });
            project(certificate.as_ref())
        }
    }
}

pub fn request_mtls_client_certificate_from_rfc9440(
    headers: &HeaderMap,
) -> Option<ClientCertificateFacts> {
    let mut values = headers.get_all("client-cert").iter();
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || value.len() < 3 {
        return None;
    }
    let der = decode_forwarded_certificate(value)?;
    let mut certificates = vec![der.into()];
    let mut chains = headers.get_all("client-cert-chain").iter();
    if let Some(chain) = chains.next() {
        if chains.next().is_some() {
            return None;
        }
        for value in chain.to_str().ok()?.split(',') {
            certificates.push(decode_forwarded_certificate(value.trim())?.into());
        }
    }
    certificate_chain_identity(certificates.into())
}

pub fn decode_forwarded_certificate(value: &str) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix(':')?.strip_suffix(':')?;
    if encoded.is_empty() || encoded.chars().any(char::is_whitespace) {
        return None;
    }
    STANDARD.decode(encoded).ok()
}

pub struct ServerMtlsThumbprintExtractor;

impl MtlsThumbprintExtractor for ServerMtlsThumbprintExtractor {
    fn resolve(&self, request: &Request) -> Option<String> {
        request_mtls_thumbprint(request)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/endpoints/mtls.rs"]
mod tests;
