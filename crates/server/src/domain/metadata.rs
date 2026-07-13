use std::sync::Arc;

use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::{AuthorizationServerProfile, CibaSecurityProfile, Settings, SubjectType};

#[derive(Clone)]
pub(crate) struct MetadataConfig {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) mtls_enabled: bool,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
    pub(crate) ciba_security_profile: CibaSecurityProfile,
    pub(crate) subject_type: SubjectType,
    pub(crate) pairwise_subject_enabled: bool,
    pub(crate) protected_resource_identifier: String,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) request_uri_parameter_enabled: bool,
}

impl From<&Settings> for MetadataConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let protocol = &settings.protocol;
        let modules = &settings.modules;
        Self {
            issuer: endpoint.issuer.clone(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.clone(),
            mtls_enabled: !endpoint.trusted_proxy_cidrs.is_empty(),
            authorization_server_profile: protocol.authorization_server_profile,
            ciba_security_profile: protocol.ciba_security_profile,
            subject_type: protocol.subject_type,
            pairwise_subject_enabled: protocol.pairwise_subject_secret.is_some(),
            protected_resource_identifier: protocol.protected_resource_identifier.to_owned(),
            require_pushed_authorization_requests: protocol.require_pushed_authorization_requests
                || protocol
                    .authorization_server_profile
                    .requires_fapi2_security(),
            request_uri_parameter_enabled: modules.enable_request_uri_parameter,
        }
    }
}

#[derive(Clone)]
pub(crate) struct MetadataHandles {
    pub(crate) config: MetadataConfig,
    pub(crate) keyset: nazo_key_management::KeyManager,
    pub(crate) runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}
