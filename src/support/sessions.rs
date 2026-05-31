//! 会话用户与权限解析。
// 只处理从请求 Cookie 到当前用户/管理员身份的解析。

use super::{login_required_response, oauth_error, prelude::*};

#[derive(Deserialize, Serialize)]
pub(crate) struct SessionPayload {
    pub(crate) user_id: Uuid,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
}

pub(crate) struct CurrentSession {
    pub(crate) user: UserRow,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
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
    let Some(raw) = valkey_get(&state.valkey, format!("oauth:session:{sid}")).await? else {
        return Ok(None);
    };
    let payload = serde_json::from_str::<SessionPayload>(&raw)?;
    let Some(user) = find_user_by_id(&state.diesel_db, payload.user_id)
        .await?
        .filter(|u| u.is_active)
    else {
        return Ok(None);
    };
    Ok(Some(CurrentSession {
        user,
        auth_time: payload.auth_time,
        amr: payload.amr,
    }))
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
