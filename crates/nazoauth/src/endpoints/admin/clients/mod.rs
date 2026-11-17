//! 管理端 OAuth 客户端 transport adapter。
pub mod create;
pub mod detail;
pub mod list;
pub mod templates;
pub mod update;

use crate::config::Configuration;
use nazo_auth::AdminClientPolicy;
use std::sync::Arc;

pub use nazo_key_management::ClientRegistrationCrypto as ServerAdminClientCrypto;

pub type ServerAdminClientService = nazo_auth::AdminClientService<
    Arc<dyn nazo_auth::AdminClientRepositoryPort>,
    Arc<dyn nazo_auth::SectorIdentifierResolverPort>,
    ServerAdminClientCrypto,
>;

#[derive(Clone)]
pub struct AdminClientConfig {
    pub client_ip: crate::http::ClientIpConfig,
}

impl AdminClientConfig {
    pub fn from_settings(settings: &Configuration) -> Self {
        Self {
            client_ip: crate::http::ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        }
    }

    pub fn client_ip(&self) -> &crate::http::ClientIpConfig {
        &self.client_ip
    }
}

pub fn admin_client_policy(settings: &Configuration) -> AdminClientPolicy {
    AdminClientPolicy {
        tenant: settings.tenant.context,
        pairwise_subject_secret: settings.protocol.pairwise_subject_secret.clone(),
        client_secret_pepper: settings.protocol.client_secret_pepper.clone(),
    }
}
