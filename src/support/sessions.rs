//! 会话用户与权限解析。
// 只处理从请求 Cookie 到当前用户/管理员身份的解析。

use super::{login_required_response, oauth_error, prelude::*, valkey_del, valkey_set_ex};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct SessionPayload {
    pub(crate) user_id: Uuid,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    #[serde(default)]
    pub(crate) pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oidc_sid: Option<String>,
}

pub(crate) struct CurrentSession {
    pub(crate) user: UserRow,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    pub(crate) oidc_sid: String,
}

pub(crate) async fn current_user(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<UserRow>> {
    Ok(current_session(state, req)
        .await?
        .map(|session| session.user))
}

pub(crate) async fn current_session(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, &state.settings.session_cookie_name) else {
        return Ok(None);
    };
    let session_key = format!("oauth:session:{sid}");
    let Some(raw) = valkey_get(&state.valkey, &session_key).await? else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = match serde_json::from_str::<SessionPayload>(&raw) {
        Ok(payload) if valid_session_payload(&payload, now) => payload,
        Ok(_) => {
            tracing::warn!("session payload contains invalid authentication metadata");
            let _ = valkey_del(&state.valkey, session_key).await;
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!(%error, "session payload is malformed");
            let _ = valkey_del(&state.valkey, session_key).await;
            return Ok(None);
        }
    };
    if payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(state, session_key, payload).await
}

pub(crate) async fn current_pending_mfa_session(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, &state.settings.session_cookie_name) else {
        return Ok(None);
    };
    let session_key = format!("oauth:session:{sid}");
    let Some(raw) = valkey_get(&state.valkey, &session_key).await? else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = match serde_json::from_str::<SessionPayload>(&raw) {
        Ok(payload) if valid_session_payload(&payload, now) => payload,
        Ok(_) => {
            tracing::warn!("pending MFA session payload contains invalid authentication metadata");
            let _ = valkey_del(&state.valkey, session_key).await;
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!(%error, "pending MFA session payload is malformed");
            let _ = valkey_del(&state.valkey, session_key).await;
            return Ok(None);
        }
    };
    if !payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(state, session_key, payload).await
}

pub(crate) async fn complete_mfa_session(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<bool> {
    record_mfa_step_up(state, req, method, true).await
}

pub(crate) async fn step_up_current_session(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<bool> {
    record_mfa_step_up(state, req, method, false).await
}

async fn record_mfa_step_up(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<bool> {
    let Some(sid) = cookie_value(req, &state.settings.session_cookie_name) else {
        return Ok(false);
    };
    let session_key = format!("oauth:session:{sid}");
    let Some(raw) = valkey_get(&state.valkey, &session_key).await? else {
        return Ok(false);
    };
    let now = Utc::now().timestamp();
    let mut payload = match serde_json::from_str::<SessionPayload>(&raw) {
        Ok(payload)
            if valid_session_payload(&payload, now)
                && (!require_pending_mfa || payload.pending_mfa) =>
        {
            payload
        }
        Ok(_) => return Ok(false),
        Err(error) => {
            tracing::warn!(%error, "MFA session payload is malformed");
            let _ = valkey_del(&state.valkey, session_key).await;
            return Ok(false);
        }
    };
    payload.pending_mfa = false;
    payload.auth_time = now;
    add_amr(&mut payload.amr, method);
    add_amr(&mut payload.amr, "mfa");
    let body = serde_json::to_string(&payload)?;
    valkey_set_ex(
        &state.valkey,
        session_key,
        body,
        state.settings.session_ttl_seconds,
    )
    .await?;
    Ok(true)
}

async fn session_from_payload(
    state: &AppState,
    session_key: String,
    payload: SessionPayload,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(user) = find_user_by_id(&state.diesel_db, payload.user_id)
        .await?
        .filter(|u| u.is_active)
    else {
        let _ = valkey_del(&state.valkey, session_key).await;
        return Ok(None);
    };
    Ok(Some(CurrentSession {
        user,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid.expect("valid session payload has sid"),
    }))
}

fn add_amr(amr: &mut Vec<String>, value: &str) {
    if !amr.iter().any(|method| method == value) {
        amr.push(value.to_owned());
    }
}

fn valid_session_payload(payload: &SessionPayload, now: i64) -> bool {
    payload.auth_time > 0
        && payload.auth_time <= now.saturating_add(30)
        && !payload.amr.is_empty()
        && payload
            .oidc_sid
            .as_deref()
            .is_some_and(|sid| !sid.trim().is_empty())
}

pub(crate) async fn require_admin(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<UserRow>> {
    Ok(current_user(state, req)
        .await?
        .filter(|u| u.role == "admin" && u.admin_level > 0))
}

pub(crate) async fn current_user_or_login_required(
    state: &AppState,
    req: &HttpRequest,
) -> Result<UserRow, HttpResponse> {
    match current_user(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(login_required_response(state)),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

pub(crate) async fn require_admin_or_forbidden(
    state: &AppState,
    req: &HttpRequest,
) -> Result<UserRow, HttpResponse> {
    match require_admin(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前账号无管理权限.",
        )),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

fn session_lookup_error_response(error: anyhow::Error) -> HttpResponse {
    tracing::warn!(%error, "failed to resolve current session user");
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "会话查询失败.",
    )
}

#[cfg(test)]
#[path = "../../tests/unit/src/support/tests/sessions.rs"]
mod tests;
