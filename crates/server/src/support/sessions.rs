//! 会话用户与权限解析。
// 只处理从请求 Cookie 到当前用户/管理员身份的解析。

#[cfg(test)]
use super::valkey_set_ex;
use super::{
    DEFAULT_TENANT_ID, login_required_response, oauth_error, prelude::*, random_urlsafe_token,
};
use nazo_identity::session::add_amr;

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
    pub(crate) user: PublicAccount,
    pub(crate) auth_time: i64,
    pub(crate) amr: Vec<String>,
    pub(crate) oidc_sid: String,
}

pub(crate) struct SessionRotation {
    pub(crate) session_id: String,
    pub(crate) csrf_token: String,
}

impl SessionPayload {
    fn to_record(&self) -> anyhow::Result<nazo_identity::session::SessionRecord> {
        Ok(nazo_identity::session::SessionRecord::new(
            nazo_identity::UserId::new(self.user_id)?,
            self.auth_time,
            self.amr.clone(),
            self.pending_mfa,
            self.oidc_sid.clone(),
        ))
    }

    fn from_record(record: &nazo_identity::session::SessionRecord) -> Self {
        Self {
            user_id: record.user_id().as_uuid(),
            auth_time: record.auth_time(),
            amr: record.amr().to_vec(),
            pending_mfa: record.pending_mfa(),
            oidc_sid: record.oidc_sid().map(str::to_owned),
        }
    }
}

pub(crate) async fn store_session(
    state: &AppState,
    session_id: &str,
    payload: &SessionPayload,
) -> anyhow::Result<()> {
    nazo_valkey::SessionStore::new(&state.valkey_connection())
        .store(
            session_id,
            &payload.to_record()?,
            state.settings.session_ttl_seconds,
        )
        .await?;
    Ok(())
}

pub(crate) fn require_active_session_principal(user: &PublicAccount) -> Result<(), HttpResponse> {
    if user.principal.active {
        return Ok(());
    }
    Err(oauth_error(
        StatusCode::UNAUTHORIZED,
        "access_denied",
        "当前账号已停用.",
    ))
}

pub(crate) async fn current_user(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
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
    let store = nazo_valkey::SessionStore::new(&state.valkey_connection());
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::Protocol => {
            tracing::warn!(%error, "session payload is malformed");
            let _ = store.delete(&sid).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = SessionPayload::from_record(stored.value());
    let payload = if valid_session_payload(&payload, now) {
        payload
    } else {
        tracing::warn!("session payload contains invalid authentication metadata");
        let _ = store.delete(&sid).await;
        return Ok(None);
    };
    if payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(state, &sid, payload).await
}

pub(crate) async fn current_pending_mfa_session(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, &state.settings.session_cookie_name) else {
        return Ok(None);
    };
    let store = nazo_valkey::SessionStore::new(&state.valkey_connection());
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::Protocol => {
            tracing::warn!(%error, "pending MFA session payload is malformed");
            let _ = store.delete(&sid).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let payload = SessionPayload::from_record(stored.value());
    let payload = if valid_session_payload(&payload, now) {
        payload
    } else {
        tracing::warn!("pending MFA session payload contains invalid authentication metadata");
        let _ = store.delete(&sid).await;
        return Ok(None);
    };
    if !payload.pending_mfa {
        return Ok(None);
    }
    session_from_payload(state, &sid, payload).await
}

pub(crate) async fn complete_mfa_session(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, true).await
}

pub(crate) async fn step_up_current_session(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, false).await
}

async fn record_mfa_step_up(
    state: &AppState,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<Option<SessionRotation>> {
    let Some(sid) = cookie_value(req, &state.settings.session_cookie_name) else {
        return Ok(None);
    };
    let store = nazo_valkey::SessionStore::new(&state.valkey_connection());
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::Protocol => {
            tracing::warn!(%error, "MFA session payload is malformed");
            let _ = store.delete(&sid).await;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let now = Utc::now().timestamp();
    let mut payload = SessionPayload::from_record(stored.value());
    if !valid_session_payload(&payload, now) || (require_pending_mfa && !payload.pending_mfa) {
        return Ok(None);
    }
    payload.pending_mfa = false;
    payload.auth_time = now;
    add_amr(&mut payload.amr, method);
    add_amr(&mut payload.amr, "mfa");
    let new_session_id = random_urlsafe_token();
    let result = store
        .rotate(
            &sid,
            &stored,
            &new_session_id,
            &payload.to_record()?,
            state.settings.session_ttl_seconds,
        )
        .await?;
    match result {
        nazo_valkey::SessionRotationResult::Applied => Ok(Some(SessionRotation {
            session_id: new_session_id,
            csrf_token: random_urlsafe_token(),
        })),
        nazo_valkey::SessionRotationResult::Conflict => Ok(None),
        nazo_valkey::SessionRotationResult::Collision => {
            anyhow::bail!("generated MFA session identifier already exists")
        }
    }
}

async fn session_from_payload(
    state: &AppState,
    session_id: &str,
    payload: SessionPayload,
) -> anyhow::Result<Option<CurrentSession>> {
    let tenant_id = nazo_identity::TenantId::new(DEFAULT_TENANT_ID)?;
    let user_id = nazo_identity::UserId::new(payload.user_id)?;
    let Some(user) = nazo_postgres::UserRepository::new(state.diesel_db.clone())
        .public_account_by_id(tenant_id, user_id)
        .await?
        .filter(|u| u.principal.active)
    else {
        let _ = nazo_valkey::SessionStore::new(&state.valkey_connection())
            .delete(session_id)
            .await;
        return Ok(None);
    };
    Ok(Some(CurrentSession {
        user,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid.expect("valid session payload has sid"),
    }))
}

fn valid_session_payload(payload: &SessionPayload, now: i64) -> bool {
    nazo_identity::session::valid_authentication_metadata(
        payload.auth_time,
        &payload.amr,
        payload.oidc_sid.as_deref(),
        now,
    )
}

pub(crate) async fn require_admin(
    state: &AppState,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
    Ok(current_user(state, req)
        .await?
        .filter(|u| u.admin_level() > 0))
}

pub(crate) async fn current_user_or_login_required(
    state: &AppState,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match current_user(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(login_required_response(state)),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

pub(crate) async fn require_admin_or_forbidden(
    state: &AppState,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
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
#[path = "../../tests/in_source/src/support/tests/sessions.rs"]
mod tests;
