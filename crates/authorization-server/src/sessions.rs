//! Session resolution and administrator authentication policy.
use chrono::Utc;
use nazo_identity::{
    PublicAccount, SessionId, TenantId,
    ports::{RepositoryError, SessionAccountPort, SessionStorePort},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
pub struct SessionPayload {
    pub user_id: Uuid,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default)]
    pub pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
}

pub struct CurrentSession {
    pub user: PublicAccount,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub oidc_sid: String,
    pub logged_in_client_ids: Vec<String>,
}

/// Maximum age of an interactive MFA step-up accepted for high-impact admin
/// mutations.  This is intentionally a fixed security default: making the
/// check configurable would make an accidental deployment setting capable of
/// silently turning the admin write boundary back into password-only access.
pub const ADMIN_MFA_MAX_AGE_SECONDS: i64 = 5 * 60;
const AUTH_TIME_CLOCK_SKEW_SECONDS: i64 = 30;

pub struct SessionResolver {
    sessions: Arc<dyn SessionStorePort>,
    users: Arc<dyn SessionAccountPort>,
    tenant_id: TenantId,
}

impl SessionResolver {
    pub fn new(
        sessions: Arc<dyn SessionStorePort>,
        users: Arc<dyn SessionAccountPort>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            sessions,
            users,
            tenant_id,
        }
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<(), RepositoryError> {
        self.sessions
            .delete(&SessionId::new(session_id))
            .await
            .map(|_| ())
    }

    pub async fn current_session_by_id(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<CurrentSession>> {
        let sessions = self.sessions.as_ref();
        let users = self.users.as_ref();
        let tenant_id = self.tenant_id;

        let session_id = SessionId::new(session_id);
        let stored = match sessions.load(&session_id).await {
            Ok(stored) => stored,
            Err(error @ RepositoryError::Consistency(_)) => {
                tracing::warn!(%error, "session payload is malformed");
                let _ = sessions.delete(&session_id).await;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let now = Utc::now().timestamp();
        let logged_in_client_ids = stored.record().logged_in_client_ids().to_vec();
        let payload = SessionPayload::from_record(stored.record());
        let payload = if valid_session_payload(&payload, now) {
            payload
        } else {
            tracing::warn!("session payload contains invalid authentication metadata");
            let _ = sessions.delete(&session_id).await;
            return Ok(None);
        };
        if payload.pending_mfa {
            return Ok(None);
        }
        session_from_payload(
            sessions,
            users,
            tenant_id,
            &session_id,
            payload,
            logged_in_client_ids,
        )
        .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionError {
    AccessDenied,
    MfaStepUpRequired,
}

pub fn require_admin_session(
    session: Option<CurrentSession>,
) -> Result<CurrentSession, AdminSessionError> {
    match session {
        Some(session) if session.user.admin_level() > 0 => Ok(session),
        Some(_) | None => Err(AdminSessionError::AccessDenied),
    }
}

pub fn require_recent_mfa(session: &CurrentSession, now: i64) -> Result<(), AdminSessionError> {
    if recent_mfa_authentication(session.auth_time, &session.amr, now) {
        Ok(())
    } else {
        Err(AdminSessionError::MfaStepUpRequired)
    }
}

impl SessionPayload {
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

async fn session_from_payload(
    sessions: &dyn SessionStorePort,
    users: &dyn SessionAccountPort,
    tenant_id: nazo_identity::TenantId,
    session_id: &SessionId,
    payload: SessionPayload,
    logged_in_client_ids: Vec<String>,
) -> anyhow::Result<Option<CurrentSession>> {
    let user_id = nazo_identity::UserId::new(payload.user_id)?;
    let Some(user) = users
        .public_account_by_id(tenant_id, user_id)
        .await?
        .filter(|u| u.principal.active)
    else {
        let _ = sessions.delete(session_id).await;
        return Ok(None);
    };
    Ok(Some(CurrentSession {
        user,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid.expect("valid session payload has sid"),
        logged_in_client_ids,
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

fn recent_mfa_authentication(auth_time: i64, amr: &[String], now: i64) -> bool {
    let age = now.saturating_sub(auth_time);
    auth_time <= now.saturating_add(AUTH_TIME_CLOCK_SKEW_SECONDS)
        && (0..=ADMIN_MFA_MAX_AGE_SECONDS).contains(&age)
        && amr.iter().any(|method| method == "mfa")
        && amr
            .iter()
            .any(|method| matches!(method.as_str(), "otp" | "recovery_code"))
}

#[cfg(test)]
#[path = "../tests/unit/sessions.rs"]
mod tests;
