//! 基于 Valkey 的固定窗口限流。
//! 限流主体默认取连接来源地址，不信任可伪造的转发头。

use super::prelude::*;
use super::{authorization_error_response, blake3_hex, client_ip, oauth_error, valkey_eval_string};

const INCREMENT_RATE_LIMIT_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  redis.call('SET', KEYS[1], '1', 'EX', ARGV[1])
  return '1'
end

local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) == -1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return tostring(count)
"#;

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

    let count = increment_rate_limit_counter(state, key, window_seconds)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "rate limit increment failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;

    if count > max_requests {
        return Err(rate_limited_response(window_seconds));
    }
    Ok(())
}

async fn increment_rate_limit_counter(
    state: &AppState,
    key: String,
    window_seconds: u64,
) -> anyhow::Result<u64> {
    let count = valkey_eval_string(
        &state.valkey,
        INCREMENT_RATE_LIMIT_SCRIPT,
        vec![key],
        vec![window_seconds.to_string()],
    )
    .await?;
    count
        .parse::<u64>()
        .map_err(|error| anyhow::anyhow!("invalid rate limit counter: {error}"))
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
