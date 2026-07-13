//! 邮箱验证码发送端点。
use nazo_http_actix::{json_response, oauth_error};

use crate::domain::AppState;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::blake3_hex;
use crate::support::{
    DEFAULT_TENANT_ID, RateLimitPolicy, email_delivery_configured, enforce_rate_limit,
    hash_password, parse_email_recipient, random_numeric_code, send_verification_email,
};
#[cfg(test)]
use crate::support::{default_tenant_context, normalize_email_address, valkey_get, valkey_set_ex};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use diesel_async::RunQueryDsl;
#[cfg(test)]
use nazo_postgres::get_conn;
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
#[derive(Deserialize)]
pub(crate) struct SendCodeRequest {
    email: String,
}

/// 生成并保存注册邮箱验证码。
pub(crate) async fn send_code(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<SendCodeRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }

    send_code_after_rate_limit(state, req, payload).await
}

pub(crate) async fn send_code_after_rate_limit(
    state: Data<AppState>,
    req: HttpRequest,
    payload: SendCodeRequest,
) -> HttpResponse {
    let Ok(recipient) = parse_email_recipient(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let email = recipient.normalized.clone();
    if !email_delivery_configured(&state.settings) {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "邮件发送未配置.",
        );
    }
    let identity = state.settings.identity();
    let dev_response_enabled = identity.email_code_dev_response_enabled;
    match nazo_postgres::UserRepository::new(state.diesel_db.clone())
        .public_account_by_email(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).expect("default tenant ID is non-nil"),
            &email,
        )
        .await
    {
        Ok(Some(_)) => return send_code_success_response(dev_response_enabled, None),
        Ok(None) => {}
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "数据库连接失败.",
            );
        }
    }

    let peer_subject = email_code_peer_subject(&req);
    let store = nazo_valkey::AuthenticationStore::new(&state.valkey_connection());
    match store
        .reserve_email_peer_send(&peer_subject, identity.email.send_peer_cooldown_seconds)
        .await
    {
        Ok(true) => {}
        Ok(false) => return send_code_success_response(dev_response_enabled, None),
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "验证码生成失败.",
            );
        }
    }

    match store
        .reserve_email_send(&email, identity.email.send_cooldown_seconds)
        .await
    {
        Ok(true) => {}
        Ok(false) => return send_code_success_response(dev_response_enabled, None),
        Err(_) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "验证码生成失败.",
            );
        }
    }

    let code = random_numeric_code();
    let Ok(code_hash) = hash_password(&code) else {
        let _ = store.delete_email_peer_send(&peer_subject).await;
        let _ = store.delete_email_send(&email).await;
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        );
    };
    if store
        .store_email_code(&email, &code_hash, identity.email.code_ttl_seconds)
        .await
        .is_err()
    {
        let _ = store.delete_email_peer_send(&peer_subject).await;
        let _ = store.delete_email_send(&email).await;
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        );
    }

    if let Err(error) = send_verification_email(&state.settings, recipient.mailbox, &code).await {
        let _ = store.delete_email_code(&email).await;
        let _ = store.delete_email_peer_send(&peer_subject).await;
        let _ = store.delete_email_send(&email).await;
        tracing::warn!(%error, "failed to send verification email");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码发送失败.",
        );
    }

    send_code_success_response(dev_response_enabled, Some(&code))
}

#[cfg(test)]
fn email_code_peer_cooldown_key(req: &HttpRequest) -> String {
    format!(
        "oauth:email_verify:peer_send:{}",
        blake3_hex(&email_code_peer_subject(req))
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
