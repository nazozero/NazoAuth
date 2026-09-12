use crate::settings::Settings;
use nazo_oauth_server::authorization::config::AuthorizationConfig;

pub(crate) fn authorization_config(settings: &Settings) -> AuthorizationConfig {
    let protocol = &settings.protocol;
    let endpoint = &settings.endpoint;
    let rate_limit = &settings.identity.rate_limit;
    AuthorizationConfig {
        issuer: endpoint.issuer.as_str().into(),
        mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.as_str().into(),
        frontend_base_url: endpoint.frontend_base_url.as_str().into(),
        profile: protocol.authorization_server_profile,
        dpop_nonce_policy: protocol.dpop_nonce_policy,
        request_object_jti_policy: protocol.request_object_jti_policy,
        auth_code_ttl_seconds: protocol.auth_code_ttl_seconds,
        par_ttl_seconds: protocol.par_ttl_seconds,
        require_pushed_authorization_requests: protocol.require_pushed_authorization_requests,
        client_secret_pepper: protocol.client_secret_pepper.as_str().into(),
        rate_limit_window_seconds: rate_limit.window_seconds,
        token_management_max_requests: rate_limit.token_management_max_requests,
    }
}
