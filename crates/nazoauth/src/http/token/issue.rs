//! Native configuration assembly and request idempotency extraction.
use crate::settings::Settings;
use nazo_oauth_server::{crypto::blake3_hex, token::issue::TokenIssuanceConfig};
use std::collections::BTreeSet;
pub(crate) fn token_issuance_config(settings: &Settings) -> TokenIssuanceConfig {
    TokenIssuanceConfig {
        issuer: settings.endpoint.issuer.as_str().into(),
        mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
        dpop_nonce_policy: settings.protocol.dpop_nonce_policy,
        default_audience: settings.protocol.default_audience.as_str().into(),
        openid4vci_enabled: settings.modules.enable_openid4vci_issuer,
        openid4vci_credential_scopes: settings
            .openid4vc
            .credential_configurations
            .values()
            .filter_map(|configuration| configuration.scope.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
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
        access_token_ttl_seconds: settings.protocol.access_token_ttl_seconds,
        id_token_ttl_seconds: settings.protocol.id_token_ttl_seconds,
        refresh_token_ttl_seconds: settings.protocol.refresh_token_ttl_seconds,
    }
}

pub(crate) fn request_idempotency_key(req: &actix_web::HttpRequest) -> Option<String> {
    let value = req.headers().get("idempotency-key")?.to_str().ok()?.trim();
    if value.is_empty() || value.len() > 256 {
        return None;
    }
    Some(format!("idempotency:{}", blake3_hex(value)))
}

#[cfg(test)]
#[path = "../../../tests/support/http/token/issue.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../../tests/unit/http/token/issue.rs"]
pub(crate) mod tests;
