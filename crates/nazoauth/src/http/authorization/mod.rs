//! Authorization HTTP parsing, cookie facts, and presentation.
mod config;
pub(crate) mod consent;
pub(crate) mod par;
pub(crate) mod presentation;
pub(crate) mod request;
use crate::http::sessions::SessionHttpConfig;
pub(crate) use config::authorization_config;
use nazo_http_actix::ClientIpConfig;
use nazo_oauth_server::authorization::AuthorizationApplication;
use std::sync::Arc;
pub(crate) struct AuthorizationEndpoint {
    application: Arc<AuthorizationApplication>,
    client_ip: ClientIpConfig,
    session_http: SessionHttpConfig,
}
impl AuthorizationEndpoint {
    pub(crate) fn new(
        application: Arc<AuthorizationApplication>,
        client_ip: ClientIpConfig,
        session_http: SessionHttpConfig,
    ) -> Self {
        Self {
            application,
            client_ip,
            session_http,
        }
    }
}
#[cfg(test)]
#[path = "../../../tests/unit/http/authorization/boundary.rs"]
mod boundary_tests;
#[cfg(test)]
#[path = "../../../tests/support/http/authorization.rs"]
pub(crate) mod test_support;
