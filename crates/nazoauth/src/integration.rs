//! HTTP transport facts and the endpoint registration contract.
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

pub use crate::http::CorsPolicy;
use crate::http::apply_security_headers;
pub use crate::routes::{BodyMode, Endpoint, Route, RouteGuard, RouteMethod, routes};
pub(crate) use crate::routes::{guard_precedes_cors, match_path, routing_path, unmatched_policy};
pub use nazo_oauth_server::contracts::token_client_auth::ClientCertificateFacts;

#[cfg(feature = "conformance")]
pub mod conformance;

/// Facts obtained from the actual connection, before NazoAuth applies trust policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConnectionFacts {
    pub peer_addr: Option<SocketAddr>,
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
