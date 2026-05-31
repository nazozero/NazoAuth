//! 用户登录端点。
// 登录成功后同时写入服务端会话和双 cookie，其中 CSRF cookie 允许前端读取。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    email: String,
    password: String,
}

/// 校验邮箱密码并创建会话。
pub(crate) async fn login(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<LoginRequest>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }

    let email = payload.email.trim().to_lowercase();
    let Some(user) = find_user_by_email(&state.diesel_db, &email)
        .await
        .ok()
        .flatten()
    else {
        return oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.");
    };
    if !user.is_active || !verify_password(&payload.password, &user.password_hash) {
        return oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.");
    }

    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let key = format!("oauth:session:{session_id}");
    if valkey_set_ex(
        &state.valkey,
        key,
        user.id.to_string(),
        state.settings.session_ttl_seconds,
    )
    .await
    .is_err()
    {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "会话写入失败.",
        );
    }

    let body = json!({
        "session_id": session_id,
        "expires_in": state.settings.session_ttl_seconds,
        "csrf_token": csrf_token
    });
    with_cookie_headers(
        json_response(body),
        &[
            make_cookie(
                &state.settings.session_cookie_name,
                &session_id,
                true,
                state.settings.session_ttl_seconds,
                state.settings.cookie_secure,
            ),
            make_cookie(
                &state.settings.csrf_cookie_name,
                &csrf_token,
                false,
                state.settings.session_ttl_seconds,
                state.settings.cookie_secure,
            ),
        ],
    )
}
