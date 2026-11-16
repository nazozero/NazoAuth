//! Focused tests use the production transport conversion and certificate policy.
use actix_web::{HttpRequest, web::Data};
use bytes::Bytes;
use nazoauth::test_support::{
    endpoints::mtls::{MtlsCertificateSource, MtlsCertificateSourceMode},
    http::{ClientIpConfig, IpCidr, Request},
};
use std::sync::Arc;

pub(crate) fn request(request: &HttpRequest, settings: &crate::settings::Settings) -> Request {
    request_with_policy(
        request,
        &settings.endpoint.trusted_proxy_cidrs,
        settings.endpoint.mtls_certificate_source,
    )
}

pub(crate) fn request_with_client_ip(request: &HttpRequest, config: &ClientIpConfig) -> Request {
    request_with_policy(
        request,
        config.trusted_proxy_cidrs(),
        MtlsCertificateSourceMode::Disabled,
    )
}

pub(crate) fn request_head(request: &HttpRequest) -> Request {
    request_with_policy(request, &[], MtlsCertificateSourceMode::Disabled)
}

pub(crate) fn request_with_policy(
    request: &HttpRequest,
    trusted_proxies: &[IpCidr],
    default_mode: MtlsCertificateSourceMode,
) -> Request {
    let mut forwarded = nazo_http_actix::forward_request(request, Bytes::new());
    let mode = request
        .app_data::<Data<MtlsCertificateSourceMode>>()
        .map(|mode| *mode.get_ref())
        .unwrap_or(default_mode);
    let verifier = request
        .app_data::<Data<dyn rustls::server::danger::ClientCertVerifier>>()
        .map(|verifier| {
            Arc::new(crate::adapters::transport_facts::RustlsCertificateVerifier(
                verifier.clone().into_inner(),
            )) as Arc<dyn nazoauth::capabilities::CertificateChainVerifier>
        });
    Arc::new(MtlsCertificateSource::new(mode, trusted_proxies, verifier))
        .prepare_request(&mut forwarded);
    forwarded
}

// Match the production collector's owned response without a test-only error box.
#[allow(clippy::result_large_err)]
pub(crate) async fn ciba_body<S, E>(
    source: S,
) -> Result<Bytes, nazoauth::test_support::http::Response>
where
    S: futures_util::Stream<Item = Result<Bytes, E>>,
{
    use futures_util::TryStreamExt;
    let method = nazoauth::test_support::resolve(&http::Method::POST, "/bc-authorize")
        .expect("CIBA POST route")
        .method;
    nazoauth::test_support::http::collect_route_body(
        method,
        source.map_err(|_| std::io::Error::other("fixture payload failure")),
    )
    .await
}

pub(crate) fn headers(source: &actix_web::http::header::HeaderMap) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in source {
        headers.append(
            http::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    headers
}
