// Native regression module: reexports the actual neutral implementation.
pub(crate) use nazoauth::test_support::endpoints::mtls::*;
#[path = "../../unit/http/mtls.rs"]
pub(crate) mod tests;

pub(crate) fn request_mtls_thumbprint(
    request: &actix_web::HttpRequest,
    trusted_proxies: &[nazoauth::test_support::http::IpCidr],
) -> Option<String> {
    nazoauth::test_support::endpoints::mtls::request_mtls_thumbprint(
        &crate::test_support::transport::request_with_policy(
            request,
            trusted_proxies,
            MtlsCertificateSourceMode::Disabled,
        ),
    )
}

pub(crate) fn request_mtls_client_certificate_from_rfc9440(
    headers: &actix_web::http::header::HeaderMap,
) -> Option<nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts> {
    nazoauth::test_support::endpoints::mtls::request_mtls_client_certificate_from_rfc9440(
        &crate::test_support::transport::headers(headers),
    )
}
