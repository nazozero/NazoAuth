//! Product configuration for token issuance.
use crate::config::Configuration;
use nazo_oauth_server::token::issue::TokenIssuanceConfig;
use std::collections::BTreeSet;
pub fn token_issuance_config(settings: &Configuration) -> TokenIssuanceConfig {
    TokenIssuanceConfig {
        deployment_profile: settings.protocol.deployment_profile,
        profile: settings.protocol.authorization_server_profile,
        issuer: settings.endpoint.issuer.as_str().into(),
        mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
        dpop_nonce_policy: settings.protocol.dpop_nonce_policy,
        default_audience: settings.protocol.default_audience.as_str().into(),
        openid4vci_enabled: settings.modules.enable_openid4vci_issuer,
        openid4vci_credential_scopes: settings
            .openid4vc
            .credential_configurations
            .values()
            .filter_map(|configuration| configuration.scope.as_deref())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        pairwise_subject_secret: settings
            .protocol
            .pairwise_subject_secret
            .as_deref()
            .map(Into::into),
        client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
        rate_limit_window_seconds: settings.identity.rate_limit.window_seconds,
        token_rate_limit_max_requests: settings.identity.rate_limit.token_max_requests,
        auth_code_ttl_seconds: settings.protocol.auth_code_ttl_seconds,
        audit_client_credentials_issuance: settings.protocol.audit_client_credentials_issuance,
        access_token_ttl_seconds: settings.protocol.access_token_ttl_seconds,
        id_token_ttl_seconds: settings.protocol.id_token_ttl_seconds,
        refresh_token_ttl_seconds: settings.protocol.refresh_token_ttl_seconds,
    }
}
