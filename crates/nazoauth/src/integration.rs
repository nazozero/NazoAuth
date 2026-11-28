//! HTTP transport facts and the endpoint registration contract.
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, OnceLock},
};

/// Decode RFC 9440 certificate fields supplied by an independently authenticated
/// ingress. Calling this does not establish deployment CA trust.
pub use crate::endpoints::mtls::request_mtls_client_certificate_from_rfc9440 as client_certificate_from_rfc9440;
use crate::http::apply_security_headers;
pub use crate::routes::{BodyMode, Endpoint, Route, RouteMethod, route_for_path, routes};
pub(crate) use crate::routes::{RouteGuard, guard_precedes_cors, match_path, unmatched_policy};
pub use nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts;

mod mount;
pub use mount::Mount;

#[cfg(feature = "conformance")]
pub mod conformance;

/// Facts obtained from the connection or an authenticated host ingress, before
/// NazoAuth applies proxy, token-binding and certificate policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionFacts {
    pub peer_addr: Option<SocketAddr>,
    /// Original client address authenticated by the host's ingress boundary.
    /// This is distinct from the socket peer and never establishes proxy or TLS
    /// certificate trust. Ordinary forwarding headers cannot populate it.
    pub authenticated_client_ip: Option<IpAddr>,
    /// TLS server name supplied by the host's trusted connection boundary.
    /// Shared tenant selection normalizes case and trailing-dot aliases.
    pub server_name: Option<Arc<str>>,
    pub client_certificate: Option<Arc<ClientCertificateFacts>>,
}

/// Borrow the request's actual authority without consulting forwarding headers.
/// HTTP/1 absolute-form uses the target authority. HTTP/2 requires `:authority`
/// and a consistent optional Host; HTTP/3 also permits Host-only requests.
/// Duplicate or invalid Host fields cannot choose a tenant or proof URL.
/// HTTP listeners remain responsible for their wire-level header requirements.
pub fn request_authority<B>(request: &http::Request<B>) -> Option<&str> {
    let mut hosts = request.headers().get_all(http::header::HOST).iter();
    let host = hosts.next().map(|value| value.to_str()).transpose().ok()?;
    if hosts.next().is_some() {
        return None;
    }
    if request.version() >= http::Version::HTTP_2 {
        return multiplexed_authority(
            request.version(),
            request.uri().scheme_str(),
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str()),
            host,
        );
    }
    if let Some(authority) = request.uri().authority() {
        return Some(authority.as_str());
    }
    host
}

/// Shared HTTP/2 and HTTP/3 authority admission for transport libraries using
/// different HTTP types. Callers first reject duplicate or non-UTF-8 Host fields.
/// The returned authority borrows the original input; URI normalization is used
/// only to compare uncommon HTTP/2 aliases, never to rewrite the request target.
pub fn multiplexed_authority<'a>(
    version: http::Version,
    scheme: Option<&str>,
    authority: Option<&'a str>,
    host: Option<&'a str>,
) -> Option<&'a str> {
    let selected = match version {
        http::Version::HTTP_2 => authority?,
        http::Version::HTTP_3 => authority.or(host)?,
        _ => return None,
    };
    if selected.is_empty() || selected.starts_with(':') || !valid_host_header(selected) {
        return None;
    }
    let Some(host) = host.filter(|_| authority.is_some()) else {
        return Some(selected);
    };
    if version == http::Version::HTTP_3 {
        // RFC 9114 section 4.3.1 requires the same value when both are present.
        return (selected == host).then_some(selected);
    }
    if selected.eq_ignore_ascii_case(host) {
        return Some(selected);
    }
    if host.is_empty() || !valid_host_header(host) {
        return None;
    }
    // RFC 9113 section 8.3.1 compares entities after URI normalization. Exact
    // and case-only matches above avoid allocations on ordinary HTTP/2 traffic.
    let scheme = scheme?;
    let selected_origin = url::Url::parse(&format!("{scheme}://{selected}")).ok()?;
    let host_origin = url::Url::parse(&format!("{scheme}://{host}")).ok()?;
    (selected_origin.origin() == host_origin.origin()).then_some(selected)
}

/// Validate the RFC 9110 Host field grammar without allocating a URI. Header
/// cardinality and HTTP/1.1 presence are the transport's responsibility. An
/// empty value is legal when the request target has no authority; it cannot
/// select a tenant. Registered names are URI syntax, not DNS admission policy.
pub fn valid_host_header(value: &str) -> bool {
    let (host, port) = if let Some(literal) = value.strip_prefix('[') {
        let Some((address, suffix)) = literal.split_once(']') else {
            return false;
        };
        let valid_address = if let Some(future) = address
            .strip_prefix('v')
            .or_else(|| address.strip_prefix('V'))
        {
            future.split_once('.').is_some_and(|(version, address)| {
                !version.is_empty()
                    && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !address.is_empty()
                    && address
                        .bytes()
                        .all(|byte| reg_name_byte(byte) || byte == b':')
            })
        } else {
            address.parse::<std::net::Ipv6Addr>().is_ok()
        };
        return valid_address
            && (suffix.is_empty()
                || suffix
                    .strip_prefix(':')
                    .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit())));
    } else {
        value
            .split_once(':')
            .map_or((value, None), |(host, port)| (host, Some(port)))
    };
    if port.is_some_and(|port| !port.bytes().all(|byte| byte.is_ascii_digit())) {
        return false;
    }
    let mut bytes = host.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !reg_name_byte(byte) {
            return false;
        }
    }
    true
}

fn reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)
}

/// The product's security headers for host-owned responses, including static UI
/// and listener rejections. Adapters add only headers absent from the response.
pub fn security_headers(path: &str) -> &'static http::HeaderMap {
    static POLICIES: OnceLock<[http::HeaderMap; 2]> = OnceLock::new();
    let policies = POLICIES.get_or_init(|| {
        [false, true].map(|iframe| {
            let mut headers = http::HeaderMap::new();
            apply_security_headers(&mut headers, iframe);
            headers
        })
    });
    &policies[usize::from(path == "/check_session")]
}

#[cfg(test)]
#[path = "../tests/unit/integration.rs"]
mod tests;
