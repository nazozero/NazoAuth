use crate::config::Configuration;
use crate::http::{ClientIpHeaderMode, IpCidr};
use nazo_oauth_server::token::device_config::DeviceConfig;
#[derive(Clone)]
pub struct DeviceHttpConfig {
    pub frontend_base_url: Box<str>,
    pub trusted_proxy_cidrs: Box<[IpCidr]>,
    pub client_ip_header_mode: ClientIpHeaderMode,
}
impl From<&Configuration> for DeviceHttpConfig {
    fn from(settings: &Configuration) -> Self {
        Self {
            frontend_base_url: settings.endpoint.frontend_base_url.as_str().into(),
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone().into(),
            client_ip_header_mode: settings.endpoint.client_ip_header_mode,
        }
    }
}
pub fn device_config_from_settings(settings: &Configuration) -> DeviceConfig {
    DeviceConfig {
        profile: settings.protocol.authorization_server_profile,
        issuer: settings.endpoint.issuer.as_str().into(),
        mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
        frontend_base_url: settings.endpoint.frontend_base_url.as_str().into(),
        client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
        default_audience: settings.protocol.default_audience.as_str().into(),
        ttl_seconds: settings.device.device_authorization_ttl_seconds,
        poll_interval_seconds: settings.device.device_authorization_poll_interval_seconds,
        pairwise_subject_secret: settings
            .protocol
            .pairwise_subject_secret
            .as_deref()
            .map(Into::into),
    }
}
