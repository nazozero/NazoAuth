//! 用户密码登录端点。

use actix_web::http::{StatusCode, header};
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use nazo_http_actix::{
    authorization_error_response, cookie_value, json_response, make_cookie, oauth_error,
    with_cookie_headers,
};
use nazo_identity::{AuthenticatePasswordError, AuthenticatePasswordInput, RememberedMfaProof};
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::LocalAuthenticationService;
use crate::support::client_ip::{ClientIpConfig, client_ip_with_config};
use crate::support::{AuthRequestLimiter, MFA_REMEMBERED_COOKIE_NAME, blake3_hex};

#[derive(Clone)]
pub(crate) struct LoginHttpConfig {
    issuer: String,
    frontend_base_url: String,
    session_cookie_name: String,
    csrf_cookie_name: String,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl LoginHttpConfig {
    pub(crate) fn new(
        issuer: impl Into<String>,
        frontend_base_url: impl Into<String>,
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            frontend_base_url: frontend_base_url.into(),
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    email: String,
    password: String,
    next: Option<String>,
}

#[derive(Clone, Copy)]
enum LoginResponseMode {
    Json,
    Form,
}

pub(crate) async fn login(
    rate_limiter: Data<AuthRequestLimiter>,
    client_ip_config: Data<ClientIpConfig>,
    authentication: Data<LocalAuthenticationService>,
    http_config: Data<LoginHttpConfig>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (payload, response_mode) = match parse_login_request(&req, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if matches!(response_mode, LoginResponseMode::Form)
        && !form_login_origin_is_allowed(http_config.get_ref(), &req)
    {
        return oauth_error(StatusCode::FORBIDDEN, "access_denied", "登录来源无效.");
    }
    if let Err(response) = rate_limiter.enforce(&req).await {
        return response;
    }

    let email = payload.email.trim().to_lowercase();
    let result = authentication
        .authenticate_password(AuthenticatePasswordInput {
            email,
            password: payload.password,
            source_ip: client_ip_with_config(&req, client_ip_config.get_ref()),
            remembered_mfa: remembered_mfa_proof(&req),
            now: Utc::now(),
        })
        .await;
    let success = match result {
        Ok(success) => success,
        Err(error) => return authentication_error_response(error),
    };
    let cookies = [
        make_cookie(
            &http_config.session_cookie_name,
            &success.session_id,
            true,
            http_config.session_ttl_seconds,
            http_config.cookie_secure,
        ),
        make_cookie(
            &http_config.csrf_cookie_name,
            &success.csrf_token,
            false,
            http_config.session_ttl_seconds,
            http_config.cookie_secure,
        ),
    ];
    if matches!(response_mode, LoginResponseMode::Form) {
        let location = safe_form_login_next(http_config.get_ref(), &req, payload.next.as_deref());
        let mut response = HttpResponse::SeeOther();
        if let Ok(value) = header::HeaderValue::from_str(&location) {
            response.insert_header((header::LOCATION, value));
        }
        return with_cookie_headers(response.finish(), &cookies);
    }
    let response = json!({
        "expires_in": http_config.session_ttl_seconds,
        "csrf_token": success.csrf_token,
        "mfa_required": success.session.pending_mfa(),
    });
    with_cookie_headers(json_response(response), &cookies)
}

fn authentication_error_response(error: AuthenticatePasswordError) -> HttpResponse {
    match error {
        AuthenticatePasswordError::ThrottleUnavailable(error) => {
            tracing::warn!(%error, "login failure throttle lookup failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "登录失败次数校验失败.",
            )
        }
        AuthenticatePasswordError::Throttled {
            retry_after_seconds,
        } => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "登录失败次数过多，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        AuthenticatePasswordError::AccountLookup(error) => {
            tracing::warn!(%error, "failed to query user for login");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户查询失败.",
            )
        }
        AuthenticatePasswordError::SecretBusy => {
            let mut response = oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "登录服务繁忙，请稍后重试.",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
            response
        }
        AuthenticatePasswordError::SecretUnavailable => {
            tracing::warn!("password verification worker failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "密码校验失败.",
            )
        }
        AuthenticatePasswordError::FailureRecord(error) => {
            tracing::warn!(%error, "login failure throttle increment failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "登录失败次数记录失败.",
            )
        }
        AuthenticatePasswordError::InvalidCredentials => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.")
        }
        AuthenticatePasswordError::InactiveAccount => {
            oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "当前账号已停用.")
        }
        AuthenticatePasswordError::RememberedMfa(error) => {
            tracing::warn!(%error, "failed to check remembered MFA device");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 状态查询失败.",
            )
        }
        AuthenticatePasswordError::Session(error) => {
            tracing::warn!(%error, "failed to store login session");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            )
        }
        AuthenticatePasswordError::SessionCollision => {
            tracing::warn!("generated login session identifier collided");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            )
        }
    }
}

fn remembered_mfa_proof(req: &HttpRequest) -> Option<RememberedMfaProof> {
    let token = cookie_value(req, MFA_REMEMBERED_COOKIE_NAME)?;
    let user_agent_hash = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(blake3_hex);
    Some(RememberedMfaProof {
        token_hash: blake3_hex(token.trim()),
        user_agent_hash,
    })
}

fn parse_login_request(
    req: &HttpRequest,
    body: &Bytes,
) -> Result<(LoginRequest, LoginResponseMode), HttpResponse> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if content_type.eq_ignore_ascii_case("application/json") {
        let payload = serde_json::from_slice::<LoginRequest>(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login request body must be valid JSON.",
            )
        })?;
        return Ok((payload, LoginResponseMode::Json));
    }
    if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        let raw = std::str::from_utf8(body).map_err(|_| {
            oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "login form body must be valid UTF-8.",
            )
        })?;
        return parse_login_form(raw).map(|payload| (payload, LoginResponseMode::Form));
    }
    Err(oauth_error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "invalid_request",
        "login request must use JSON or form encoding.",
    ))
}

fn parse_login_form(raw: &str) -> Result<LoginRequest, HttpResponse> {
    let mut email = None;
    let mut password = None;
    let mut next = None;
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match key.as_ref() {
            "email" => assign_once(&mut email, value.into_owned())?,
            "password" => assign_once(&mut password, value.into_owned())?,
            "next" => assign_once(&mut next, value.into_owned())?,
            _ => {}
        }
    }
    let Some(email) = email else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "email is required.",
        ));
    };
    let Some(password) = password else {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "password is required.",
        ));
    };
    Ok(LoginRequest {
        email,
        password,
        next,
    })
}

fn assign_once(slot: &mut Option<String>, value: String) -> Result<(), HttpResponse> {
    if slot.is_some() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "duplicate login form parameter.",
        ));
    }
    *slot = Some(value);
    Ok(())
}

fn form_login_origin_is_allowed(config: &LoginHttpConfig, req: &HttpRequest) -> bool {
    let mut origin_headers = req.headers().get_all(header::ORIGIN);
    let Some(origin_header) = origin_headers.next() else {
        return false;
    };
    if origin_headers.next().is_some() {
        return false;
    }
    let Ok(origin_header) = origin_header.to_str() else {
        return false;
    };
    let Some(request_origin) = strict_request_origin(origin_header) else {
        return false;
    };
    [&config.issuer, &config.frontend_base_url]
        .into_iter()
        .filter_map(|trusted_url| normalized_url_origin(trusted_url))
        .any(|trusted_origin| trusted_origin == request_origin)
}

fn strict_request_origin(value: &str) -> Option<String> {
    if value == "null" || value != value.trim() {
        return None;
    }
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn normalized_url_origin(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn safe_form_login_next(
    config: &LoginHttpConfig,
    req: &HttpRequest,
    submitted: Option<&str>,
) -> String {
    let default_next = format!("{}/profile", config.frontend_base_url.trim_end_matches('/'));
    submitted
        .and_then(safe_relative_next)
        .or_else(|| referer_login_next(req))
        .unwrap_or(default_next)
}

fn safe_relative_next(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return None;
    }
    let path = trimmed
        .split_once(['?', '#'])
        .map(|(path, _)| path)
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if path == "/authorize" {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

fn referer_login_next(req: &HttpRequest) -> Option<String> {
    let header = req.headers().get(header::REFERER)?.to_str().ok()?;
    let referer = url::Url::parse(header).ok()?;
    let next = referer.query_pairs().find_map(|(key, value)| {
        if key == "next" {
            Some(value.into_owned())
        } else {
            None
        }
    })?;
    safe_relative_next(&next)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/login.rs"]
mod tests;
