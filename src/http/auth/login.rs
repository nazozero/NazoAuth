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
    let user = match find_user_by_email(&state.diesel_db, &email).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            audit_event(
                "login_failure",
                audit_fields(&[
                    ("email_hash", json!(blake3_hex(&email))),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip(&req, &state.settings))),
                    ),
                ]),
            );
            return oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query user for login");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "用户查询失败.",
            );
        }
    };
    if !user.is_active || !verify_password(&payload.password, &user.password_hash) {
        audit_event(
            "login_failure",
            audit_fields(&[
                ("user_id", json!(user.id)),
                ("email_hash", json!(blake3_hex(&email))),
                (
                    "source_ip_hash",
                    json!(blake3_hex(&client_ip(&req, &state.settings))),
                ),
            ]),
        );
        return oauth_error(StatusCode::UNAUTHORIZED, "access_denied", "邮箱或密码错误.");
    }

    let session_id = random_urlsafe_token();
    let csrf_token = random_urlsafe_token();
    let key = format!("oauth:session:{session_id}");
    let session = SessionPayload {
        user_id: user.id,
        auth_time: Utc::now().timestamp(),
        amr: vec!["password".to_owned()],
    };
    let session_body = match serde_json::to_string(&session) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    if valkey_set_ex(
        &state.valkey,
        key,
        session_body,
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

    audit_event(
        "login_success",
        audit_fields(&[
            ("user_id", json!(user.id)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
            ("amr", json!(session.amr)),
        ]),
    );

    let body = json!({
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
