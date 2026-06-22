//! 用户登录端点。
// 登录成功后同时写入服务端会话和双 cookie，其中 CSRF cookie 允许前端读取。
use crate::http::prelude::*;

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

/// 校验邮箱密码并创建会话。
pub(crate) async fn login(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    let (payload, response_mode) = match parse_login_request(&req, &body) {
        Ok(value) => value,
        Err(response) => return response,
    };

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
    let remembered_mfa = if user.mfa_enabled {
        match remembered_mfa_device_valid(&state, &req, &user).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to check remembered MFA device");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 状态查询失败.",
                );
            }
        }
    } else {
        false
    };
    let mut amr = vec!["password".to_owned()];
    if remembered_mfa {
        amr.push("remembered_mfa".to_owned());
        amr.push("mfa".to_owned());
    }
    let session = SessionPayload {
        user_id: user.id,
        auth_time: Utc::now().timestamp(),
        amr,
        pending_mfa: user.mfa_enabled && !remembered_mfa,
        oidc_sid: Some(random_urlsafe_token()),
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

    let cookies = [
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
    ];

    if matches!(response_mode, LoginResponseMode::Form) {
        let location = safe_form_login_next(&state, &req, payload.next.as_deref());
        let mut response = HttpResponse::SeeOther();
        if let Ok(value) = HeaderValue::from_str(&location) {
            response.insert_header((header::LOCATION, value));
        }
        return with_cookie_headers(response.finish(), &cookies);
    }

    let response_body = json!({
        "expires_in": state.settings.session_ttl_seconds,
        "csrf_token": csrf_token,
        "mfa_required": session.pending_mfa
    });
    with_cookie_headers(json_response(response_body), &cookies)
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
    let mut email: Option<String> = None;
    let mut password: Option<String> = None;
    let mut next: Option<String> = None;

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

fn safe_form_login_next(state: &AppState, req: &HttpRequest, submitted: Option<&str>) -> String {
    submitted
        .and_then(safe_relative_next)
        .or_else(|| referer_login_next(req))
        .unwrap_or_else(|| {
            format!(
                "{}/profile",
                state.settings.frontend_base_url.trim_end_matches('/')
            )
        })
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
    if path != "/authorize" {
        return None;
    }
    Some(trimmed.to_owned())
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
