use crate::settings::Settings;
use nazo_oauth_server::token::ciba::state::CibaConfig;

pub(crate) fn ciba_config(settings: &Settings) -> CibaConfig {
    CibaConfig {
        issuer: settings.endpoint.issuer.as_str().into(),
        mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
        frontend_base_url: settings.endpoint.frontend_base_url.as_str().into(),
        client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
        default_audience: settings.protocol.default_audience.as_str().into(),
        tenant_id: settings.tenant.context.tenant_id.as_uuid(),
        auth_req_id_ttl_seconds: settings.ciba.ciba_auth_req_id_ttl_seconds,
        poll_interval_seconds: settings.ciba.ciba_poll_interval_seconds,
        ciba_fapi_profile: settings.protocol.ciba_security_profile.requires_fapi_ciba(),
        ciba_fapi2_hardening: settings
            .protocol
            .ciba_security_profile
            .requires_fapi2_hardening(),
    }
}
