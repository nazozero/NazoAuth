//! MFA enrollment, challenge, and step-up endpoints.
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct ConfirmTotpRequest {
    code: String,
}

#[derive(Deserialize)]
pub(crate) struct MfaChallengeRequest {
    code: String,
    remember_device: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct MfaProtectedRequest {
    code: String,
}

pub(crate) async fn mfa_totp_begin(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    no_store(mfa_totp_begin_inner(state, req).await)
}

async fn mfa_totp_begin_inner(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let repository = nazo_postgres::MfaRepository::new(state.diesel_db.clone());
    let existing = match repository
        .totp_enrollment(user.tenant().tenant_id, user.user_id())
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to load TOTP credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 凭据查询失败.",
            );
        }
    };
    if existing
        .as_ref()
        .is_some_and(|credential| credential.confirmed)
    {
        return oauth_error(StatusCode::CONFLICT, "invalid_request", "TOTP MFA 已启用.");
    }

    let secret = nazo_identity::mfa::generate_totp_secret_base32();
    let label = format!("{} ({})", user.account.email, state.settings.issuer);
    let result = repository
        .begin_totp_enrollment(
            user.tenant().tenant_id,
            user.user_id(),
            secret.clone(),
            label,
        )
        .await;
    if let Err(error) = result {
        tracing::warn!(%error, "failed to store TOTP enrollment secret");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA 凭据写入失败.",
        );
    }

    json_response(json!({
        "secret_base32": secret,
        "otpauth_uri": nazo_identity::mfa::otpauth_uri(
            &state.settings.issuer,
            &user.account.email,
            &secret,
        ),
        "period": MFA_TOTP_PERIOD_SECONDS,
        "digits": MFA_TOTP_DIGITS
    }))
}

pub(crate) async fn mfa_totp_confirm(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    no_store(mfa_totp_confirm_inner(state, req, Json(payload)).await)
}

async fn mfa_totp_confirm_inner(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let repository = nazo_postgres::MfaRepository::new(state.diesel_db.clone());
    match repository
        .totp_enrollment(user.tenant().tenant_id, user.user_id())
        .await
    {
        Ok(Some(credential)) if !credential.confirmed => {}
        Ok(Some(_)) => {
            return oauth_error(StatusCode::CONFLICT, "invalid_request", "TOTP MFA 已启用.");
        }
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "请先开始 TOTP MFA 注册.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load TOTP credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 凭据查询失败.",
            );
        }
    };
    let (backup_codes, hashes) = match generate_backup_codes_and_hashes() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to generate backup codes");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "备份码生成失败.",
            );
        }
    };
    match repository
        .verify_and_confirm_totp(
            user.tenant().tenant_id,
            user.user_id(),
            &payload.code,
            Utc::now().timestamp(),
            hashes,
        )
        .await
    {
        Ok(nazo_identity::ports::TotpVerificationOutcome::Accepted) => {}
        Ok(
            nazo_identity::ports::TotpVerificationOutcome::Invalid
            | nazo_identity::ports::TotpVerificationOutcome::Replay,
        ) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to confirm TOTP credential");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 启用失败.",
            );
        }
    };
    let rotation =
        match step_up_current_session(&state, &req, MfaVerificationMethod::Totp.amr()).await {
            Ok(Some(rotation)) => rotation,
            Ok(None) => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "login_required",
                    "当前会话已过期.",
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to step up current session after TOTP enrollment");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "会话写入失败.",
                );
            }
        };
    audit_event(
        "mfa_totp_enabled",
        audit_fields(&[("user_id", json!(user.id())), ("method", json!("totp"))]),
    );
    with_cookie_headers(
        json_response(json!({
            "mfa_enabled": true,
            "backup_codes": backup_codes
        })),
        &rotated_session_cookies(&state, &rotation),
    )
}

pub(crate) async fn mfa_verify(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    no_store(mfa_verify_inner(state, req, Json(payload)).await)
}

async fn mfa_verify_inner(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let session = match current_pending_mfa_session(&state, &req).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "没有待完成的 MFA 登录挑战.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve pending MFA session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    let method = match verify_user_mfa_code(&state.diesel_db, &session.user, &payload.code).await {
        Ok(Some(method)) => method,
        Ok(None) => {
            audit_event(
                "mfa_challenge_failure",
                audit_fields(&[("user_id", json!(session.user.id()))]),
            );
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA challenge");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    };
    let mut cookies = Vec::new();
    if payload.remember_device.unwrap_or(false) {
        match remember_mfa_device(&state, &req, &session.user).await {
            Ok(token) => cookies.push(make_cookie(
                MFA_REMEMBERED_COOKIE_NAME,
                &token,
                true,
                MFA_REMEMBERED_TTL_SECONDS,
                state.settings.cookie_secure,
            )),
            Err(error) => {
                tracing::warn!(%error, "failed to remember MFA device");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 设备记住失败.",
                );
            }
        }
    }
    let rotation = match complete_mfa_session(&state, &req, method.amr()).await {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "MFA 登录挑战已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to complete MFA session");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    cookies.extend(rotated_session_cookies(&state, &rotation));
    audit_event(
        "mfa_challenge_success",
        audit_fields(&[
            ("user_id", json!(session.user.id())),
            ("method", json!(method.amr())),
        ]),
    );
    with_cookie_headers(
        json_response(json!({
            "success": true,
            "method": method.amr()
        })),
        &cookies,
    )
}

pub(crate) async fn mfa_backup_codes_regenerate(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    no_store(mfa_backup_codes_regenerate_inner(state, req, Json(payload)).await)
}

async fn mfa_backup_codes_regenerate_inner(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    if !user.account.mfa_enabled {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "MFA 未启用.");
    }
    let method = match verify_user_mfa_code(&state.diesel_db, &user, &payload.code).await {
        Ok(Some(method)) => method,
        Ok(None) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA for backup code regeneration");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    };
    let rotation = match step_up_current_session(&state, &req, method.amr()).await {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "当前会话已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to step up session before backup code regeneration");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    let backup_codes = match replace_backup_codes(&state.diesel_db, &user).await {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to regenerate backup codes");
            return with_rotated_session_cookies(
                &state,
                &rotation,
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "备份码生成失败.",
                ),
            );
        }
    };
    audit_event(
        "mfa_backup_codes_regenerated",
        audit_fields(&[
            ("user_id", json!(user.id())),
            ("method", json!(method.amr())),
        ]),
    );
    with_cookie_headers(
        json_response(json!({ "backup_codes": backup_codes })),
        &rotated_session_cookies(&state, &rotation),
    )
}

fn rotated_session_cookies(
    state: &AppState,
    rotation: &SessionRotation,
) -> [actix_web::cookie::Cookie<'static>; 2] {
    [
        make_cookie(
            &state.settings.session_cookie_name,
            &rotation.session_id,
            true,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
        make_cookie(
            &state.settings.csrf_cookie_name,
            &rotation.csrf_token,
            false,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        ),
    ]
}

fn with_rotated_session_cookies(
    state: &AppState,
    rotation: &SessionRotation,
    response: HttpResponse,
) -> HttpResponse {
    with_cookie_headers(response, &rotated_session_cookies(state, rotation))
}

pub(crate) async fn mfa_disable(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    no_store(mfa_disable_inner(state, req, Json(payload)).await)
}

async fn mfa_disable_inner(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    let user = match current_user_or_login_required(&state, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth).await {
        return response;
    }
    if !user.account.mfa_enabled {
        return json_response(json!({ "mfa_enabled": false }));
    }
    match verify_user_mfa_code(&state.diesel_db, &user, &payload.code).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
        }
        Err(error) => {
            tracing::warn!(%error, "failed to verify MFA for disable");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
    }
    if let Err(error) = clear_user_mfa_state(&state.diesel_db, &user).await {
        tracing::warn!(%error, "failed to disable MFA");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "MFA 禁用失败.",
        );
    }
    audit_event(
        "mfa_disabled",
        audit_fields(&[("user_id", json!(user.id()))]),
    );
    with_cookie_headers(
        json_response(json!({ "mfa_enabled": false })),
        &[clear_cookie(
            MFA_REMEMBERED_COOKIE_NAME,
            state.settings.cookie_secure,
        )],
    )
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        actix_web::http::header::PRAGMA,
        actix_web::http::header::HeaderValue::from_static("no-cache"),
    );
    response
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/mfa.rs"]
mod tests;
