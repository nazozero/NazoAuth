use crate::domain::TestInfrastructure;

use crate::settings::Settings;

use crate::test_support::valkey::valkey_get;

use actix_web::http::header;

use serde_json::{Value, json};

use crate::adapters::security::random_urlsafe_token;

use crate::test_support::valkey::valkey_set_ex;

use nazo_identity::session::add_amr;

impl SessionProfileHandles {
    pub(crate) fn from_test_infrastructure(state: &TestInfrastructure) -> Self {
        let session = &state.settings.session;
        Self::new(
            SessionStore::new(&state.valkey_connection()),
            UserRepository::new(state.diesel_db.clone()),
            SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )
    }
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
}

pub(crate) fn login_required_response(state: &TestInfrastructure) -> HttpResponse {
    let session = &state.settings.session;
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(&session.session_cookie_name, session.cookie_secure),
            clear_cookie(&session.csrf_cookie_name, session.cookie_secure),
        ],
    )
}

pub(crate) struct SessionRotation {
    pub(crate) session_id: String,
    pub(crate) csrf_token: String,
}

pub(crate) async fn current_user(
    state: &TestInfrastructure,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
    Ok(current_session(state, req)
        .await?
        .map(|session| session.user))
}

pub(crate) async fn current_session(
    state: &TestInfrastructure,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let sessions = SessionStore::new(&state.valkey_connection());
    let users = UserRepository::new(state.diesel_db.clone());
    current_session_from_handles(
        &sessions,
        &users,
        &state.settings.session.session_cookie_name,
        req,
    )
    .await
}

pub(crate) async fn current_pending_mfa_session(
    state: &TestInfrastructure,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let store = SessionStore::new(&state.valkey_connection());
    let users = UserRepository::new(state.diesel_db.clone());
    current_pending_mfa_session_from_handles(
        &store,
        &users,
        &state.settings.session.session_cookie_name,
        req,
    )
    .await
}

async fn current_pending_mfa_session_from_handles(
    store: &SessionStore,
    users: &UserRepository,
    session_cookie_name: &str,
    req: &HttpRequest,
) -> anyhow::Result<Option<CurrentSession>> {
    let Some(sid) = cookie_value(req, session_cookie_name) else {
        return Ok(None);
    };
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
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
    let logged_in_client_ids = stored.value().logged_in_client_ids().to_vec();
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
    session_from_payload(store, users, &sid, payload, logged_in_client_ids).await
}

pub(crate) async fn complete_mfa_session(
    state: &TestInfrastructure,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, true).await
}

pub(crate) async fn step_up_current_session(
    state: &TestInfrastructure,
    req: &HttpRequest,
    method: &str,
) -> anyhow::Result<Option<SessionRotation>> {
    record_mfa_step_up(state, req, method, false).await
}

async fn record_mfa_step_up(
    state: &TestInfrastructure,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<Option<SessionRotation>> {
    let store = SessionStore::new(&state.valkey_connection());
    record_mfa_step_up_with_store(
        &store,
        &state.settings.session.session_cookie_name,
        state.settings.session.session_ttl_seconds,
        req,
        method,
        require_pending_mfa,
    )
    .await
}

async fn record_mfa_step_up_with_store(
    store: &SessionStore,
    session_cookie_name: &str,
    session_ttl_seconds: u64,
    req: &HttpRequest,
    method: &str,
    require_pending_mfa: bool,
) -> anyhow::Result<Option<SessionRotation>> {
    let Some(sid) = cookie_value(req, session_cookie_name) else {
        return Ok(None);
    };
    let stored = match store.load(&sid).await {
        Ok(stored) => stored,
        Err(error) if error.kind() == nazo_valkey::ErrorKind::CorruptData => {
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
            session_ttl_seconds,
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

pub(crate) async fn require_admin(
    state: &TestInfrastructure,
    req: &HttpRequest,
) -> anyhow::Result<Option<PublicAccount>> {
    Ok(current_user(state, req)
        .await?
        .filter(|u| u.admin_level() > 0))
}

pub(crate) async fn current_user_or_login_required(
    state: &TestInfrastructure,
    req: &HttpRequest,
) -> Result<PublicAccount, HttpResponse> {
    match current_user(state, req).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(login_required_response(state)),
        Err(error) => Err(session_lookup_error_response(error)),
    }
}

pub(crate) async fn require_admin_or_forbidden(
    state: &TestInfrastructure,
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
