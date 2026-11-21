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
pub(crate) use crate::routes::{
    RouteGuard, guard_precedes_cors, match_path, routing_path, unmatched_policy,
};
pub use nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts;

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
    pub server_name: Option<Arc<str>>,
    pub client_certificate: Option<Arc<ClientCertificateFacts>>,
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
