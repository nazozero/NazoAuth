use crate::http::{Request, Response};
use http::{StatusCode, header};
use nazo_oauth_server::contracts::mfa_profile::{
    MfaChallengeCommand, MfaCodeCommand, MfaProfileError, MfaProfileErrorKind,
    MfaProfileOperations, MfaRequestContext, MfaSessionRotation,
};

use std::sync::Arc;

use jiff::Timestamp;
use nazo_identity::mfa::{MFA_TOTP_DIGITS, MFA_TOTP_PERIOD_SECONDS};
use serde::Deserialize;
use serde_json::json;

use crate::http::{
    ClientIpConfig, authorization_error_response, clear_cookie, client_ip_with_config,
    cookie_value, has_valid_csrf_token_for_cookies, json_response_no_store, make_cookie,
    with_cookie_headers,
};

#[derive(Clone)]
pub struct MfaProfileConfig {
    session_cookie_name: String,
    csrf_cookie_name: String,
    remembered_mfa_cookie_name: String,
    session_ttl_seconds: u64,
    remembered_mfa_ttl_seconds: u64,
    cookie_secure: bool,
}

impl MfaProfileConfig {
    #[must_use]
    pub fn new(
        session_cookie_name: impl Into<String>,
        csrf_cookie_name: impl Into<String>,
        remembered_mfa_cookie_name: impl Into<String>,
        session_ttl_seconds: u64,
        remembered_mfa_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            remembered_mfa_cookie_name: remembered_mfa_cookie_name.into(),
            session_ttl_seconds,
            remembered_mfa_ttl_seconds,
            cookie_secure,
        }
    }
}

#[derive(Clone)]
pub struct MfaProfileEndpoint {
    operations: Arc<dyn MfaProfileOperations>,
    client_ip: ClientIpConfig,
    config: MfaProfileConfig,
}

impl MfaProfileEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn MfaProfileOperations>,
        client_ip: ClientIpConfig,
        config: MfaProfileConfig,
    ) -> Self {
        Self {
            operations,
            client_ip,
            config,
        }
    }
}

#[derive(Deserialize)]
pub struct ConfirmTotpRequest {
    code: String,
}

#[derive(Deserialize)]
pub struct MfaChallengeRequest {
    code: String,
    remember_device: Option<bool>,
}

#[derive(Deserialize)]
pub struct MfaProtectedRequest {
    code: String,
}

pub async fn mfa_totp_begin(endpoint: &MfaProfileEndpoint, request: &Request) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint.operations.begin_totp(context).await {
        Ok(enrollment) => json_response_no_store(json!({
            "secret_base32": enrollment.secret_base32,
            "otpauth_uri": enrollment.otpauth_uri,
            "period": MFA_TOTP_PERIOD_SECONDS,
            "digits": MFA_TOTP_DIGITS,
        })),
        Err(error) => error_response(endpoint, error),
    }
}

pub async fn mfa_totp_confirm(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
    payload: ConfirmTotpRequest,
) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .confirm_totp(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            endpoint,
            json_response_no_store(json!({
                "mfa_enabled": true,
                "backup_codes": success.backup_codes,
            })),
            &success.rotation,
        ),
        Err(error) => error_response(endpoint, error),
    }
}

pub async fn mfa_verify(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
    payload: MfaChallengeRequest,
) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let remember_device = payload.remember_device.unwrap_or(false);
    let user_agent_hash = if remember_device {
        request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| blake3::hash(value.as_bytes()).to_hex().to_string())
    } else {
        None
    };
    match endpoint
        .operations
        .verify_challenge(MfaChallengeCommand {
            context,
            code: payload.code,
            remember_device,
            user_agent_hash,
        })
        .await
    {
        Ok(success) => {
            let mut cookies = Vec::from(rotation_cookies(endpoint, &success.rotation));
            if let Some(token) = success.remembered_device_token {
                cookies.push(make_cookie(
                    &endpoint.config.remembered_mfa_cookie_name,
                    &token,
                    true,
                    endpoint.config.remembered_mfa_ttl_seconds,
                    endpoint.config.cookie_secure,
                ));
            }
            with_cookie_headers(
                json_response_no_store(json!({
                    "success": true,
                    "method": success.method,
                })),
                &cookies,
            )
        }
        Err(error) => error_response(endpoint, error),
    }
}

pub async fn mfa_step_up(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
    payload: MfaProtectedRequest,
) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .step_up(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            endpoint,
            json_response_no_store(json!({
                "success": true,
                "method": success.method,
            })),
            &success.rotation,
        ),
        Err(error) => error_response(endpoint, error),
    }
}

pub async fn mfa_backup_codes_regenerate(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
    payload: MfaProtectedRequest,
) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .regenerate_backup_codes(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(success) => with_rotation(
            endpoint,
            json_response_no_store(json!({"backup_codes": success.backup_codes})),
            &success.rotation,
        ),
        Err(error) => error_response(endpoint, error),
    }
}

pub async fn mfa_disable(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
    payload: MfaProtectedRequest,
) -> Response {
    let context = match request_context(endpoint, request) {
        Ok(context) => context,
        Err(response) => return response,
    };
    match endpoint
        .operations
        .disable(MfaCodeCommand {
            context,
            code: payload.code,
        })
        .await
    {
        Ok(changed) if changed => with_cookie_headers(
            json_response_no_store(json!({"mfa_enabled": false})),
            &[clear_cookie(
                &endpoint.config.remembered_mfa_cookie_name,
                endpoint.config.cookie_secure,
            )],
        ),
        Ok(_) => json_response_no_store(json!({"mfa_enabled": false})),
        Err(error) => error_response(endpoint, error),
    }
}

fn request_context(
    endpoint: &MfaProfileEndpoint,
    request: &Request,
) -> Result<MfaRequestContext, Response> {
    if !has_valid_csrf_token_for_cookies(
        request,
        None,
        &endpoint.config.session_cookie_name,
        &endpoint.config.csrf_cookie_name,
    ) {
        return Err(crate::http::csrf_error());
    }
    let Some(session_id) = cookie_value(request, &endpoint.config.session_cookie_name) else {
        return Err(clear_session_cookies(
            endpoint,
            authorization_error_response(StatusCode::UNAUTHORIZED, "login_required", "请求失败."),
        ));
    };
    Ok(MfaRequestContext {
        session_id,
        source_ip: client_ip_with_config(request, &endpoint.client_ip),
        now: Timestamp::now().as_second(),
    })
}

fn error_response(endpoint: &MfaProfileEndpoint, error: MfaProfileError) -> Response {
    let mut response = match error.kind {
        MfaProfileErrorKind::SessionMissing => clear_session_cookies(
            endpoint,
            authorization_error_response(StatusCode::UNAUTHORIZED, "login_required", "请求失败."),
        ),
        MfaProfileErrorKind::ChallengeMissing => {
            authorization_error_response(StatusCode::UNAUTHORIZED, "login_required", "请求失败.")
        }
        MfaProfileErrorKind::SessionUnavailable
        | MfaProfileErrorKind::RateLimitUnavailable
        | MfaProfileErrorKind::CredentialUnavailable
        | MfaProfileErrorKind::HashUnavailable
        | MfaProfileErrorKind::SessionWriteFailed
        | MfaProfileErrorKind::RememberDeviceFailed
        | MfaProfileErrorKind::BackupCodesFailed
        | MfaProfileErrorKind::DisableFailed
        | MfaProfileErrorKind::AuditUnavailable => authorization_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求失败.",
        ),
        MfaProfileErrorKind::RateLimited => {
            authorization_error_response(StatusCode::TOO_MANY_REQUESTS, "slow_down", "请求失败.")
        }
        MfaProfileErrorKind::AlreadyEnabled => {
            authorization_error_response(StatusCode::CONFLICT, "invalid_request", "请求失败.")
        }
        MfaProfileErrorKind::EnrollmentMissing | MfaProfileErrorKind::MfaDisabled => {
            authorization_error_response(StatusCode::BAD_REQUEST, "invalid_request", "请求失败.")
        }
        MfaProfileErrorKind::InvalidCode => {
            authorization_error_response(StatusCode::BAD_REQUEST, "invalid_grant", "请求失败.")
        }
    };
    if let Some(retry_after_seconds) = error.retry_after_seconds
        && let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    if error.clear_session_cookies {
        response = clear_session_cookies(endpoint, response);
    }
    response
}

fn with_rotation(
    endpoint: &MfaProfileEndpoint,
    response: Response,
    rotation: &MfaSessionRotation,
) -> Response {
    with_cookie_headers(response, &rotation_cookies(endpoint, rotation))
}

fn rotation_cookies(
    endpoint: &MfaProfileEndpoint,
    rotation: &MfaSessionRotation,
) -> [cookie::Cookie<'static>; 2] {
    [
        make_cookie(
            &endpoint.config.session_cookie_name,
            &rotation.session_id,
            true,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
        make_cookie(
            &endpoint.config.csrf_cookie_name,
            &rotation.csrf_token,
            false,
            endpoint.config.session_ttl_seconds,
            endpoint.config.cookie_secure,
        ),
    ]
}

fn clear_session_cookies(endpoint: &MfaProfileEndpoint, response: Response) -> Response {
    with_cookie_headers(
        response,
        &[
            clear_cookie(
                &endpoint.config.session_cookie_name,
                endpoint.config.cookie_secure,
            ),
            clear_cookie(
                &endpoint.config.csrf_cookie_name,
                endpoint.config.cookie_secure,
            ),
        ],
    )
}
