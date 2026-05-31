//! 邮箱验证码发送端点。
use crate::http::prelude::*;

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
    let dev_response_enabled = state.settings.email_code_dev_response_enabled;
    match find_user_by_email(&state.diesel_db, &email).await {
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

    let peer_cooldown_key = email_code_peer_cooldown_key(&req);
    match valkey_set_ex_nx(
        &state.valkey,
        &peer_cooldown_key,
        "1",
        state.settings.email.send_peer_cooldown_seconds,
    )
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

    let cooldown_key = format!("oauth:email_verify:send:{email}");
    match valkey_set_ex_nx(
        &state.valkey,
        &cooldown_key,
        "1",
        state.settings.email.send_cooldown_seconds,
    )
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
        let _ = valkey_del(&state.valkey, &peer_cooldown_key).await;
        let _ = valkey_del(&state.valkey, &cooldown_key).await;
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        );
    };
    let key = format!("oauth:email_verify:code:{email}");
    if valkey_set_ex(
        &state.valkey,
        &key,
        code_hash,
        state.settings.email.code_ttl_seconds,
    )
    .await
    .is_err()
    {
        let _ = valkey_del(&state.valkey, &peer_cooldown_key).await;
        let _ = valkey_del(&state.valkey, &cooldown_key).await;
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        );
    }

    if let Err(error) = send_verification_email(&state.settings, recipient.mailbox, &code).await {
        let _ = valkey_del(&state.valkey, &key).await;
        let _ = valkey_del(&state.valkey, &peer_cooldown_key).await;
        let _ = valkey_del(&state.valkey, &cooldown_key).await;
        tracing::warn!(%error, "failed to send verification email");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码发送失败.",
        );
    }

    send_code_success_response(dev_response_enabled, Some(&code))
}

fn email_code_peer_cooldown_key(req: &HttpRequest) -> String {
    let subject = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    format!("oauth:email_verify:peer_send:{}", blake3_hex(&subject))
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
