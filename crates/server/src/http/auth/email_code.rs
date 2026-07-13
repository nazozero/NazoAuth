//! 邮箱验证码发送端点。

use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{json_response, oauth_error};
use nazo_identity::{SendVerificationCodeError, SendVerificationCodeOutcome};
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::LocalRegistrationService;
use crate::support::{email::normalize_email_address, rate_limit::AuthRequestLimiter};

#[derive(Clone, Copy)]
pub(crate) struct EmailCodeHttpConfig {
    dev_response_enabled: bool,
}

impl EmailCodeHttpConfig {
    pub(crate) fn new(dev_response_enabled: bool) -> Self {
        Self {
            dev_response_enabled,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct SendCodeRequest {
    email: String,
}

/// 生成并保存注册邮箱验证码。
pub(crate) async fn send_code(
    rate_limiter: Data<AuthRequestLimiter>,
    registration: Data<LocalRegistrationService>,
    http_config: Data<EmailCodeHttpConfig>,
    req: HttpRequest,
    Json(payload): Json<SendCodeRequest>,
) -> HttpResponse {
    if let Err(response) = rate_limiter.enforce(&req).await {
        return response;
    }

    send_code_after_rate_limit(registration, http_config, req, payload).await
}

pub(crate) async fn send_code_after_rate_limit(
    registration: Data<LocalRegistrationService>,
    http_config: Data<EmailCodeHttpConfig>,
    req: HttpRequest,
    payload: SendCodeRequest,
) -> HttpResponse {
    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let peer_subject = email_code_peer_subject(&req);
    match registration
        .send_verification_code(&email, &peer_subject)
        .await
    {
        Ok(SendVerificationCodeOutcome::Suppressed) => {
            send_code_success_response(http_config.dev_response_enabled, None)
        }
        Ok(SendVerificationCodeOutcome::Sent { code }) => {
            send_code_success_response(http_config.dev_response_enabled, Some(&code))
        }
        Err(SendVerificationCodeError::DeliveryNotConfigured) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "邮件发送未配置.",
        ),
        Err(SendVerificationCodeError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(
            SendVerificationCodeError::Reservation(_) | SendVerificationCodeError::CodeStore(_),
        ) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::CodeHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::Delivery(error)) => {
            tracing::warn!(%error, "failed to send verification email");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "验证码发送失败.",
            )
        }
    }
}

#[cfg(test)]
fn email_code_peer_cooldown_key(req: &HttpRequest) -> String {
    format!(
        "oauth:email_verify:peer_send:{}",
        crate::support::security::blake3_hex(&email_code_peer_subject(req))
    )
}

fn email_code_peer_subject(req: &HttpRequest) -> String {
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn send_code_success_response(dev_response_enabled: bool, code: Option<&str>) -> HttpResponse {
    let mut body = json!({"success": true, "message": "如果邮箱尚未注册，验证码将会发送。"});
    if cfg!(debug_assertions)
        && dev_response_enabled
        && let Some(code) = code
    {
        body["verification_code"] = json!(code);
    }
    json_response(body)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/email_code.rs"]
mod tests;
