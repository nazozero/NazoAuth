//! Authorization HTTP parsing, cookie facts, and presentation.

pub mod consent;
pub mod par;
pub mod presentation;
pub mod request;
use crate::endpoints::sessions::SessionHttpConfig;

use crate::http::ClientIpConfig;
use nazo_oauth_server::authorization::AuthorizationApplication;
use std::sync::Arc;
pub struct AuthorizationEndpoint {
    pub application: Arc<AuthorizationApplication>,
    pub client_ip: ClientIpConfig,
    pub session_http: SessionHttpConfig,
    pub client_attestation: Option<Arc<nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator>>,
}
impl AuthorizationEndpoint {
    pub fn new(
        application: Arc<AuthorizationApplication>,
        client_ip: ClientIpConfig,
        session_http: SessionHttpConfig,
    ) -> Self {
        Self {
            application,
            client_ip,
            session_http,
            client_attestation: None,
        }
    }
    pub fn with_client_attestation(
        mut self,
        validator: Option<Arc<nazo_oauth_server::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator>>,
    ) -> Self {
        self.client_attestation = validator;
        self
    }
}

pub mod config;
pub use config::authorization_config;
