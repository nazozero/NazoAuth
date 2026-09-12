//! 管理端 OAuth 客户端 transport adapter。
pub(crate) mod create;
pub(crate) mod detail;
pub(crate) mod list;
pub(crate) mod templates;
pub(crate) mod update;

use crate::adapters::remote_client_documents::RemoteClientDocumentResolver;
use crate::settings::Settings;
use nazo_auth::AdminClientPolicy;
use std::sync::Arc;

pub(crate) use nazo_key_management::ClientRegistrationCrypto as ServerAdminClientCrypto;

pub(crate) type ServerAdminClientService = nazo_auth::AdminClientService<
    Arc<dyn nazo_auth::AdminClientRepositoryPort>,
    RemoteClientDocumentResolver,
    ServerAdminClientCrypto,
>;

#[derive(Clone)]
pub(crate) struct AdminClientConfig {
    client_ip: nazo_http_actix::ClientIpConfig,
}

impl AdminClientConfig {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        Self {
            client_ip: nazo_http_actix::ClientIpConfig::new(
                &settings.endpoint.trusted_proxy_cidrs,
                settings.endpoint.client_ip_header_mode,
            ),
        }
    }

    pub(crate) fn client_ip(&self) -> &nazo_http_actix::ClientIpConfig {
        &self.client_ip
    }
}

pub(crate) fn admin_client_policy(settings: &Settings) -> AdminClientPolicy {
    AdminClientPolicy {
        tenant: settings.tenant.context,
        pairwise_subject_secret: settings.protocol.pairwise_subject_secret.clone(),
        client_secret_pepper: settings.protocol.client_secret_pepper.clone(),
    }
}

#[cfg(test)]
#[path = "../../../../tests/support/http/admin/clients.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../../../tests/unit/http/admin/clients/boundary.rs"]
mod boundary_tests;
