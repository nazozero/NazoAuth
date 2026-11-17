use super::ip::ClientIpConfig;
use nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationApplication;
use std::sync::Arc;

#[derive(Clone)]
pub struct DynamicRegistrationEndpoint {
    pub(super) application: Arc<DynamicRegistrationApplication>,
    pub(super) client_ip: ClientIpConfig,
}

impl DynamicRegistrationEndpoint {
    pub fn new(
        application: Arc<DynamicRegistrationApplication>,
        client_ip: ClientIpConfig,
    ) -> Self {
        Self {
            application,
            client_ip,
        }
    }
}
