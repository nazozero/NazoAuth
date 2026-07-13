//! 基于 Valkey 的固定窗口限流。
//! 限流主体默认取连接来源地址，不信任可伪造的转发头。

#[cfg(test)]
use super::blake3_hex;
use super::{
    ClientIpHeaderMode, IpCidr, authorization_error_response, client_ip,
    client_ip::client_ip_with_context, oauth_error,
};
use crate::domain::AppState;
use crate::settings::{RateLimitSettings, Settings};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::{HttpRequest, HttpResponse};

#[derive(Clone, Copy)]
pub(crate) enum RateLimitPolicy {
    Auth,
    Token,
    TokenManagement,
}

impl RateLimitPolicy {
    #[cfg(test)]
    fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Token => "token",
            Self::TokenManagement => "token_management",
        }
    }

    fn dimension(self) -> nazo_valkey::RateDimension {
        match self {
            Self::Auth => nazo_valkey::RateDimension::Auth,
            Self::Token => nazo_valkey::RateDimension::Token,
            Self::TokenManagement => nazo_valkey::RateDimension::TokenManagement,
        }
    }

    fn max_requests(self, settings: &RateLimitSettings) -> u64 {
        match self {
            Self::Auth => settings.auth_max_requests,
            Self::Token => settings.token_max_requests,
            Self::TokenManagement => settings.token_management_max_requests,
        }
    }
}

pub(crate) async fn enforce_rate_limit(
    state: &AppState,
    req: &HttpRequest,
    policy: RateLimitPolicy,
) -> Result<(), HttpResponse> {
    let identity = state.settings.identity();
    let settings = identity.rate_limit;
    let endpoint = state.settings.endpoint();
    enforce_rate_limit_with_store(
        &nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
        req,
        policy,
        settings.window_seconds,
        policy.max_requests(settings),
        endpoint.client_ip_header_mode,
        endpoint.trusted_proxy_cidrs,
    )
    .await
}

pub(crate) async fn enforce_rate_limit_with_store(
    store: &nazo_valkey::RateLimitStore,
    req: &HttpRequest,
    policy: RateLimitPolicy,
    window_seconds: u64,
    max_requests: u64,
    client_ip_header_mode: ClientIpHeaderMode,
    trusted_proxy_cidrs: &[IpCidr],
) -> Result<(), HttpResponse> {
    let count = store
        .increment(
            policy.dimension(),
            &client_ip_with_context(req, client_ip_header_mode, trusted_proxy_cidrs),
            window_seconds,
        )
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

pub(crate) async fn enforce_login_failure_throttle(
    state: &AppState,
    req: &HttpRequest,
    normalized_email: &str,
) -> Result<(), HttpResponse> {
    let identity = state.settings.identity();
    let settings = identity.rate_limit;
    let subjects = login_failure_subjects(req, &state.settings, normalized_email);
    let email_count = login_failure_count(
        state,
        nazo_valkey::LoginFailureDimension::Email,
        &subjects.email_subject,
    )
    .await?;
    let ip_email_count = login_failure_count(
        state,
        nazo_valkey::LoginFailureDimension::IpEmail,
        &subjects.ip_email_subject,
    )
    .await?;

    if email_count >= settings.login_failure_email_max_attempts
        || ip_email_count >= settings.login_failure_ip_email_max_attempts
    {
        return Err(login_failure_rate_limited_response(
            settings.login_failure_window_seconds,
        ));
    }
    Ok(())
}

pub(crate) async fn record_login_failure(
    state: &AppState,
    req: &HttpRequest,
    normalized_email: &str,
) -> Result<(), HttpResponse> {
    let identity = state.settings.identity();
    let settings = identity.rate_limit;
    let subjects = login_failure_subjects(req, &state.settings, normalized_email);
    for (dimension, subject) in [
        (
            nazo_valkey::LoginFailureDimension::Email,
            &subjects.email_subject,
        ),
        (
            nazo_valkey::LoginFailureDimension::IpEmail,
            &subjects.ip_email_subject,
        ),
    ] {
        nazo_valkey::RateLimitStore::new(&state.valkey_connection())
            .increment_login_failure(dimension, subject, settings.login_failure_window_seconds)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "login failure throttle increment failed");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "登录失败次数记录失败.",
                )
            })?;
    }
    Ok(())
}

pub(crate) async fn clear_login_failures(
    state: &AppState,
    req: &HttpRequest,
    normalized_email: &str,
) {
    let subjects = login_failure_subjects(req, &state.settings, normalized_email);
    for (dimension, subject) in [
        (
            nazo_valkey::LoginFailureDimension::Email,
            &subjects.email_subject,
        ),
        (
            nazo_valkey::LoginFailureDimension::IpEmail,
            &subjects.ip_email_subject,
        ),
    ] {
        if let Err(error) = nazo_valkey::RateLimitStore::new(&state.valkey_connection())
            .clear_login_failure(dimension, subject)
            .await
        {
            tracing::warn!(%error, "failed to clear login failure throttle state");
        }
    }
}

async fn login_failure_count(
    state: &AppState,
    dimension: nazo_valkey::LoginFailureDimension,
    subject: &str,
) -> Result<u64, HttpResponse> {
    nazo_valkey::RateLimitStore::new(&state.valkey_connection())
        .login_failure_count(dimension, subject)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "login failure throttle lookup failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "登录失败次数校验失败.",
            )
        })
}

#[cfg(test)]
fn rate_limit_subject(req: &HttpRequest, settings: &Settings) -> String {
    client_ip(req, settings)
}

#[cfg(test)]
fn rate_limit_key(policy: RateLimitPolicy, subject: &str) -> String {
    format!(
        "oauth:rate:{}:{}",
        policy.name(),
        blake3_hex(subject.trim())
    )
}

struct LoginFailureSubjects {
    email_subject: String,
    ip_email_subject: String,
}

fn login_failure_subjects(
    req: &HttpRequest,
    settings: &Settings,
    normalized_email: &str,
) -> LoginFailureSubjects {
    let email = normalized_email.trim();
    let source_ip = client_ip(req, settings);
    LoginFailureSubjects {
        email_subject: email.to_owned(),
        ip_email_subject: format!("{source_ip}:{email}"),
    }
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

fn login_failure_rate_limited_response(retry_after_seconds: u64) -> HttpResponse {
    let mut response = authorization_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        "登录失败次数过多，请稍后重试.",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/rate_limit.rs"]
mod tests;
