#[cfg(not(test))]
use std::sync::Arc;

#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;
use crate::support::{client_ip::ClientIpHeaderMode, client_ip::IpCidr};

#[derive(Clone)]
pub(crate) struct DynamicRegistrationConfig {
    pub(crate) issuer: String,
    pub(crate) default_audience: String,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) client_secret_pepper: String,
    pub(crate) initial_access_token: Option<String>,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) rate_limit_max_requests: u64,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for DynamicRegistrationConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let identity = &settings.identity;
        let modules = &settings.modules;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            default_audience: protocol.default_audience.to_owned(),
            pairwise_subject_secret: protocol
                .pairwise_subject_secret
                .as_deref()
                .map(ToOwned::to_owned),
            client_secret_pepper: protocol.client_secret_pepper.to_owned(),
            initial_access_token: modules
                .dynamic_client_registration_initial_access_token
                .as_deref()
                .map(ToOwned::to_owned),
            rate_limit_window_seconds: identity.rate_limit.window_seconds,
            rate_limit_max_requests: identity.rate_limit.token_management_max_requests,
            client_ip_header_mode: endpoint.client_ip_header_mode,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DynamicRegistrationHandles {
    pub(crate) config: DynamicRegistrationConfig,
    pub(crate) clients: nazo_postgres::OAuthClientRepository,
    pub(crate) rate_limits: nazo_valkey::RateLimitStore,
    pub(crate) keyset: nazo_key_management::KeyManager,
    #[cfg(not(test))]
    pub(crate) runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    #[cfg(test)]
    pub(crate) enabled: bool,
}

impl DynamicRegistrationHandles {
    #[cfg(not(test))]
    pub(crate) fn accepts_new_requests(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::DynamicClientRegistration,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    #[cfg(test)]
    pub(crate) fn accepts_new_requests(&self) -> bool {
        self.enabled
    }

    #[cfg(test)]
    pub(crate) fn from_app_state(state: &super::AppState) -> Self {
        Self {
            config: DynamicRegistrationConfig::from(state.settings.as_ref()),
            clients: nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            rate_limits: nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            keyset: state.keyset.clone(),
            enabled: state.settings.modules.enable_dynamic_client_registration,
        }
    }
}
