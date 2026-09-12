use crate::contracts::oauth_error::OAuthEndpointError;
use crate::services::ServerAuthorizationService;
use crate::token::issue::TokenIssuanceConfig;
use http::StatusCode;

pub(super) async fn enforce_token_rate_limit(
    service: &ServerAuthorizationService,
    config: &TokenIssuanceConfig,
    source_ip: &str,
) -> Result<(), OAuthEndpointError> {
    let count = service
        .increment_token_rate(source_ip, config.rate_limit_window_seconds())
        .await
        .map_err(|error| {
            tracing::warn!(%error, "token rate limit increment failed");
            OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
                false,
            )
        })?;
    if count > config.token_rate_limit_max_requests() {
        return Err(OAuthEndpointError::RateLimited {
            retry_after_seconds: config.rate_limit_window_seconds(),
        });
    }
    Ok(())
}
