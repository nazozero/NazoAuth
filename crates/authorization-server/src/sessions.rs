//! Session resolution and administrator authentication policy.
use chrono::Utc;
use nazo_identity::{
    Principal, PublicAccount, SessionId, TenantId,
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

pub struct CurrentSession<A = Principal> {
    pub user: A,
    pub auth_time: i64,
    pub auth_time_micros: Option<i64>,
    pub amr: Vec<String>,
    pub oidc_sid: String,
    pub logged_in_client_ids: Vec<String>,
}

pub use nazo_identity::session::ADMIN_MFA_MAX_AGE_SECONDS;
use nazo_identity::session::recent_interactive_mfa as recent_mfa_authentication;

pub struct SessionResolver {
    service: nazo_identity::SessionService,
    tenant_id: TenantId,
}

impl SessionResolver {
    pub fn new(
        sessions: Arc<dyn SessionStorePort>,
        users: Arc<dyn SessionAccountPort>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            service: nazo_identity::SessionService::new(sessions, users, tenant_id),
            tenant_id,
        }
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<(), RepositoryError> {
        self.service
            .delete(&SessionId::new(session_id))
            .await
            .map(|_| ())
    }

    pub async fn bind_client(
        &self,
        session_id: &SessionId,
        client_id: &str,
    ) -> Result<bool, RepositoryError> {
        self.service.bind_client(session_id, client_id).await
    }

    pub async fn current_session_by_id(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<CurrentSession>> {
        Ok(resolved_session(
            self.service
                .current_principal(&SessionId::new(session_id), Utc::now().timestamp())
                .await?,
        ))
    }

    pub async fn current_profile_session_by_id(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Option<CurrentSession<PublicAccount>>> {
        Ok(resolved_session(
            self.service
                .current(&SessionId::new(session_id), Utc::now().timestamp())
                .await?,
        ))
    }
}

fn resolved_session<A>(
    resolution: nazo_identity::SessionResolution<A>,
) -> Option<CurrentSession<A>> {
    match resolution {
        nazo_identity::SessionResolution::Present(session) => {
            let auth_time = session.auth_time();
            let auth_time_micros = session.auth_time_micros();
            let amr = session.amr().to_vec();
            let oidc_sid = session.oidc_sid().to_owned();
            let logged_in_client_ids = session.logged_in_client_ids().to_vec();
            Some(CurrentSession {
                user: (*session).into_user(),
                auth_time,
                auth_time_micros,
                amr,
                oidc_sid,
                logged_in_client_ids,
            })
        }
        nazo_identity::SessionResolution::Missing
        | nazo_identity::SessionResolution::Invalidated => None,
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
        Some(session) if session.user.admin_level().unwrap_or(0) > 0 => Ok(session),
        Some(_) | None => Err(AdminSessionError::AccessDenied),
    }
}

pub fn require_recent_mfa<A>(
    session: &CurrentSession<A>,
    now: i64,
) -> Result<(), AdminSessionError> {
    if recent_mfa_authentication(session.auth_time, &session.amr, now) {
        Ok(())
    } else {
        Err(AdminSessionError::MfaStepUpRequired)
    }
}

#[cfg(test)]
#[path = "../tests/unit/sessions.rs"]
mod tests;
