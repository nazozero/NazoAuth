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
    #[cfg(test)]
    pub(crate) fn from_app_state(state: &super::AppState) -> Self {
        let connection = state.valkey_connection();
        Self {
            config: ResourceServerConfig::from(state.settings.as_ref()),
            keyset: state.keyset.clone(),
            tokens: nazo_postgres::TokenRepository::new(state.diesel_db.clone()),
            clients: nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            replay: nazo_valkey::ReplayStore::new(&connection),
            http_message_signatures_enabled: state.settings.modules.enable_fapi_http_signatures,
        }
    }

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
