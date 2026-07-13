#[cfg(not(test))]
use std::sync::Arc;

#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::{DpopNoncePolicy, Settings};
use crate::support::client_ip::IpCidr;

#[derive(Clone)]
pub(crate) struct ResourceServerConfig {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) default_audience: String,
    pub(crate) protected_resource_identifier: String,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) fapi_http_signature_max_age_seconds: i64,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for ResourceServerConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            default_audience: protocol.default_audience.to_owned(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            dpop_nonce_policy: protocol.dpop_nonce_policy,
            fapi_http_signature_max_age_seconds: protocol.fapi_http_signature_max_age_seconds,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ResourceServerHandles {
    pub(crate) config: ResourceServerConfig,
    pub(crate) keyset: nazo_key_management::KeyManager,
    pub(crate) tokens: nazo_postgres::TokenRepository,
    pub(crate) clients: nazo_postgres::OAuthClientRepository,
    pub(crate) replay: nazo_valkey::ReplayStore,
    #[cfg(not(test))]
    pub(crate) runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    #[cfg(test)]
    pub(crate) http_message_signatures_enabled: bool,
}

impl ResourceServerHandles {
    #[cfg(not(test))]
    pub(crate) fn accepts_http_message_signatures(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::HttpMessageSignatures,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    #[cfg(test)]
    pub(crate) fn accepts_http_message_signatures(&self) -> bool {
        self.http_message_signatures_enabled
    }
}
