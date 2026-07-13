//! 用户注册端点。

use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{json_response_status, oauth_error};
use nazo_identity::{PublicAccount, RegisterLocalAccountError, RegisterLocalAccountInput};
use serde::Deserialize;
use serde_json::json;

use crate::bootstrap::LocalRegistrationService;
use crate::support::client_ip::ClientIpConfig;
use crate::support::{AuthRateLimitConfig, enforce_auth_rate_limit, normalize_email_address};

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    email: String,
    verification_code: String,
    password: String,
}

/// 使用邮箱验证码创建本地用户。
pub(crate) async fn register(
    rate_limits: Data<nazo_valkey::RateLimitStore>,
    rate_limit_config: Data<AuthRateLimitConfig>,
    client_ip_config: Data<ClientIpConfig>,
    registration: Data<LocalRegistrationService>,
    req: HttpRequest,
    Json(payload): Json<RegisterRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_auth_rate_limit(
        rate_limits.get_ref(),
        &req,
        *rate_limit_config.get_ref(),
        client_ip_config.get_ref(),
    )
    .await
    {
        return response;
    }

    register_after_rate_limit(registration, payload).await
}

pub(crate) async fn register_after_rate_limit(
    registration: Data<LocalRegistrationService>,
    payload: RegisterRequest,
) -> HttpResponse {
    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let input = RegisterLocalAccountInput {
        email,
        verification_code: verification_code_for_lookup(&payload),
        password: payload.password,
    };
    match registration.register_local_account(input).await {
        Ok(account) => register_success_response(account),
        Err(RegisterLocalAccountError::InvalidVerificationCode) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "验证码错误或已过期.",
        ),
        Err(RegisterLocalAccountError::VerificationUnavailable(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码校验失败.",
        ),
        Err(RegisterLocalAccountError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(RegisterLocalAccountError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.")
        }
        Err(RegisterLocalAccountError::PasswordHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "密码哈希失败.",
        ),
        Err(RegisterLocalAccountError::Create(error)) => {
            tracing::warn!(%error, "failed to create user");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户创建失败.",
            )
        }
        Err(RegisterLocalAccountError::Consistency) => {
            tracing::warn!("created user returned outside the default tenant context");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户创建失败.",
            )
        }
    }
}

fn verification_code_for_lookup(payload: &RegisterRequest) -> String {
    payload.verification_code.trim().to_owned()
}

fn register_success_response(user: PublicAccount) -> HttpResponse {
    json_response_status(
        StatusCode::CREATED,
        json!({"id": user.id(), "email": user.account.email}),
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/register.rs"]
mod tests;
