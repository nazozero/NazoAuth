//! 基于 Valkey 的固定窗口限流。
//! 限流主体默认取连接来源地址，不信任可伪造的转发头。

use super::prelude::*;
use super::{authorization_error_response, blake3_hex, client_ip, oauth_error, valkey_set_ex_nx};

#[derive(Clone, Copy)]
pub(crate) enum RateLimitPolicy {
    Auth,
    Token,
    TokenManagement,
}

impl RateLimitPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Token => "token",
            Self::TokenManagement => "token_management",
        }
    }

    fn max_requests(self, settings: &Settings) -> u64 {
        match self {
            Self::Auth => settings.rate_limit.auth_max_requests,
            Self::Token => settings.rate_limit.token_max_requests,
            Self::TokenManagement => settings.rate_limit.token_management_max_requests,
        }
    }
}

pub(crate) async fn enforce_rate_limit(
    state: &AppState,
    req: &HttpRequest,
    policy: RateLimitPolicy,
) -> Result<(), HttpResponse> {
    let settings = &state.settings.rate_limit;
    let window_seconds = settings.window_seconds;
    let max_requests = policy.max_requests(&state.settings);
    let key = rate_limit_key(policy, &rate_limit_subject(req, &state.settings));

    valkey_set_ex_nx(&state.valkey, key.clone(), "0", window_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "rate limit window creation failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;
    let count = state.valkey.incr::<i64, _>(key).await.map_err(|error| {
        tracing::warn!(%error, "rate limit increment failed");
        oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )
    })?;

    if count as u64 > max_requests {
        return Err(rate_limited_response(window_seconds));
    }
    Ok(())
}

fn rate_limit_subject(req: &HttpRequest, settings: &Settings) -> String {
    client_ip(req, settings)
}

fn rate_limit_key(policy: RateLimitPolicy, subject: &str) -> String {
    format!(
        "oauth:rate:{}:{}",
        policy.name(),
        blake3_hex(subject.trim())
    )
}

fn rate_limited_response(retry_after_seconds: u64) -> HttpResponse {
    let mut response = authorization_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        "请求过于频繁，请稍后重试.",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/rate_limit.rs"]
mod tests;
