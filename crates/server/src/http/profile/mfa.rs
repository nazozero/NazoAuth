//! MFA enrollment, challenge, and step-up endpoints.
use nazo_http_actix::{
    clear_cookie, csrf_error, has_valid_csrf_token_for_cookies, json_response, make_cookie,
    oauth_error, with_cookie_headers,
};

#[cfg(test)]
use crate::domain::DatabaseUserFixture;
use crate::domain::MfaProfileHandles;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::MFA_BACKUP_CODE_COUNT;
#[cfg(test)]
use crate::support::{
    DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, SessionPayload,
    remembered_mfa_device_valid, valkey_get, valkey_set_ex,
};
use crate::support::{
    MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS, MFA_TOTP_DIGITS,
    MFA_TOTP_PERIOD_SECONDS, MfaVerificationMethod, RateLimitPolicy, SessionRotation, audit_event,
    audit_fields, clear_user_mfa_state_with_repository, enforce_rate_limit_with_store,
    generate_backup_codes_and_hashes, remember_mfa_device_with_repository,
    replace_backup_codes_with_repository, verify_user_mfa_code_with_repository,
};
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::DateTime;
use chrono::Utc;
use nazo_identity::PublicAccount;
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
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

pub(crate) async fn mfa_totp_begin(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
) -> HttpResponse {
    no_store(mfa_totp_begin_inner(handles, req).await)
}

async fn mfa_totp_begin_inner(handles: Data<MfaProfileHandles>, req: HttpRequest) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let user = match current_mfa_user_or_login_required(&handles, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let existing = match handles
        .mfa
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
    let label = format!("{} ({})", user.account.email, handles.config.issuer);
    let result = handles
        .mfa
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
            &handles.config.issuer,
            &user.account.email,
            &secret,
        ),
        "period": MFA_TOTP_PERIOD_SECONDS,
        "digits": MFA_TOTP_DIGITS
    }))
}

pub(crate) async fn mfa_totp_confirm(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    no_store(mfa_totp_confirm_inner(handles, req, Json(payload)).await)
}

async fn mfa_totp_confirm_inner(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<ConfirmTotpRequest>,
) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let user = match current_mfa_user_or_login_required(&handles, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_mfa_rate_limit(&handles, &req).await {
        return response;
    }
    let credential = match handles
        .mfa
        .totp_enrollment(user.tenant().tenant_id, user.user_id())
        .await
    {
        Ok(Some(credential)) if !credential.confirmed => credential,
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
    if nazo_identity::mfa::verified_totp_step(
        &credential.secret_base32,
        &payload.code,
        Utc::now().timestamp(),
        credential.last_used_step,
    )
    .is_none()
    {
        if let Err(error) = handles
            .mfa
            .record_invalid_totp_attempt(user.tenant().tenant_id, user.user_id())
            .await
        {
            tracing::warn!(%error, "failed to persist invalid TOTP enrollment audit");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "MFA 验证失败.",
            );
        }
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
    }
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
    let rotation = match handles
        .sessions
        .step_up_current_session(
            &req,
            MfaVerificationMethod::Totp.amr(),
            handles.config.session_ttl_seconds,
        )
        .await
    {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "当前会话已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to step up current session before TOTP enrollment");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    match handles
        .mfa
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
            return with_rotated_session_cookies(
                &handles,
                &rotation,
                oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效."),
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to confirm TOTP credential");
            return with_rotated_session_cookies(
                &handles,
                &rotation,
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 启用失败.",
                ),
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
        &rotated_session_cookies(&handles, &rotation),
    )
}

pub(crate) async fn mfa_verify(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    no_store(mfa_verify_inner(handles, req, Json(payload)).await)
}

async fn mfa_verify_inner(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaChallengeRequest>,
) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let session = match handles.sessions.current_pending_mfa_session(&req).await {
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
    if let Err(response) = enforce_mfa_rate_limit(&handles, &req).await {
        return response;
    }
    let method = match verify_user_mfa_code_with_repository(
        &handles.mfa,
        &session.user,
        &payload.code,
    )
    .await
    {
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
        match remember_mfa_device_with_repository(&handles.mfa, &req, &session.user).await {
            Ok(token) => cookies.push(make_cookie(
                MFA_REMEMBERED_COOKIE_NAME,
                &token,
                true,
                MFA_REMEMBERED_TTL_SECONDS,
                handles.sessions.http_config().cookie_secure(),
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
    let rotation = match handles
        .sessions
        .complete_mfa_session(&req, method.amr(), handles.config.session_ttl_seconds)
        .await
    {
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
    cookies.extend(rotated_session_cookies(&handles, &rotation));
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
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    no_store(mfa_backup_codes_regenerate_inner(handles, req, Json(payload)).await)
}

pub(crate) async fn mfa_step_up(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    no_store(mfa_step_up_inner(handles, req, Json(payload)).await)
}

async fn mfa_step_up_inner(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let user = match current_mfa_user_or_login_required(&handles, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_mfa_rate_limit(&handles, &req).await {
        return response;
    }
    if !user.account.mfa_enabled {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "MFA 未启用.");
    }
    let method =
        match verify_user_mfa_code_with_repository(&handles.mfa, &user, &payload.code).await {
            Ok(Some(method)) => method,
            Ok(None) => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效.");
            }
            Err(error) => {
                tracing::warn!(%error, "failed to verify MFA for session step-up");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "MFA 验证失败.",
                );
            }
        };

    // Factor consumption deliberately precedes privilege elevation. PostgreSQL and Valkey do not
    // share a transaction; a rotation failure may consume a one-time factor, but can never produce
    // an elevated session without a successful, replay-safe verification.
    let rotation = match handles
        .sessions
        .step_up_current_session(&req, method.amr(), handles.config.session_ttl_seconds)
        .await
    {
        Ok(Some(rotation)) => rotation,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "login_required",
                "当前会话已过期或已被替换.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to rotate session after MFA step-up");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话写入失败.",
            );
        }
    };
    audit_event(
        "mfa_step_up_success",
        audit_fields(&[
            ("user_id", json!(user.id())),
            ("method", json!(method.amr())),
        ]),
    );
    with_cookie_headers(
        json_response(json!({
            "success": true,
            "method": method.amr()
        })),
        &rotated_session_cookies(&handles, &rotation),
    )
}

async fn mfa_backup_codes_regenerate_inner(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let user = match current_mfa_user_or_login_required(&handles, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_mfa_rate_limit(&handles, &req).await {
        return response;
    }
    if !user.account.mfa_enabled {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "MFA 未启用.");
    }
    let method =
        match verify_user_mfa_code_with_repository(&handles.mfa, &user, &payload.code).await {
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
    let rotation = match handles
        .sessions
        .step_up_current_session(&req, method.amr(), handles.config.session_ttl_seconds)
        .await
    {
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
    let backup_codes = match replace_backup_codes_with_repository(&handles.mfa, &user).await {
        Ok(codes) => codes,
        Err(error) => {
            tracing::warn!(%error, "failed to regenerate backup codes");
            return with_rotated_session_cookies(
                &handles,
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
        &rotated_session_cookies(&handles, &rotation),
    )
}

fn rotated_session_cookies(
    handles: &MfaProfileHandles,
    rotation: &SessionRotation,
) -> [actix_web::cookie::Cookie<'static>; 2] {
    [
        make_cookie(
            handles.sessions.http_config().session_cookie_name(),
            &rotation.session_id,
            true,
            handles.config.session_ttl_seconds,
            handles.sessions.http_config().cookie_secure(),
        ),
        make_cookie(
            handles.sessions.http_config().csrf_cookie_name(),
            &rotation.csrf_token,
            false,
            handles.config.session_ttl_seconds,
            handles.sessions.http_config().cookie_secure(),
        ),
    ]
}

fn with_rotated_session_cookies(
    handles: &MfaProfileHandles,
    rotation: &SessionRotation,
    response: HttpResponse,
) -> HttpResponse {
    with_cookie_headers(response, &rotated_session_cookies(handles, rotation))
}

pub(crate) async fn mfa_disable(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    no_store(mfa_disable_inner(handles, req, Json(payload)).await)
}

async fn mfa_disable_inner(
    handles: Data<MfaProfileHandles>,
    req: HttpRequest,
    Json(payload): Json<MfaProtectedRequest>,
) -> HttpResponse {
    if !has_valid_mfa_csrf_token(&handles, &req) {
        return csrf_error();
    }
    let user = match current_mfa_user_or_login_required(&handles, &req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = enforce_mfa_rate_limit(&handles, &req).await {
        return response;
    }
    if !user.account.mfa_enabled {
        return json_response(json!({ "mfa_enabled": false }));
    }
    match verify_user_mfa_code_with_repository(&handles.mfa, &user, &payload.code).await {
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
    if let Err(error) = clear_user_mfa_state_with_repository(&handles.mfa, &user).await {
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
            handles.sessions.http_config().cookie_secure(),
        )],
    )
}

fn has_valid_mfa_csrf_token(handles: &MfaProfileHandles, req: &HttpRequest) -> bool {
    let http = handles.sessions.http_config();
    has_valid_csrf_token_for_cookies(
        req,
        None,
        http.session_cookie_name(),
        http.csrf_cookie_name(),
    )
}

async fn current_mfa_user_or_login_required(
    handles: &MfaProfileHandles,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match handles.sessions.current_session(req).await {
        Ok(Some(session)) => Ok(session.user),
        Ok(None) => {
            let http = handles.sessions.http_config();
            Err(with_cookie_headers(
                oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "login_required",
                    "会话不存在或已过期,请重新登录.",
                ),
                &[
                    clear_cookie(http.session_cookie_name(), http.cookie_secure()),
                    clear_cookie(http.csrf_cookie_name(), http.cookie_secure()),
                ],
            ))
        }
        Err(error) => {
            tracing::warn!(%error, "failed to resolve current MFA session user");
            Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            ))
        }
    }
}

async fn enforce_mfa_rate_limit(
    handles: &MfaProfileHandles,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    enforce_rate_limit_with_store(
        &handles.rate_limits,
        req,
        RateLimitPolicy::Auth,
        handles.config.rate_limit_window_seconds,
        handles.config.rate_limit_max_requests,
        handles.config.client_ip_header_mode,
        &handles.config.trusted_proxy_cidrs,
    )
    .await
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
