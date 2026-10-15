use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{PublicAccount, TenantId, UserId, ports::RepositoryError};

#[must_use]
pub fn valid_authentication_metadata(
    auth_time: i64,
    amr: &[String],
    oidc_sid: Option<&str>,
    now: i64,
) -> bool {
    auth_time > 0
        && auth_time <= now.saturating_add(30)
        && !amr.is_empty()
        && amr.iter().all(|method| !method.trim().is_empty())
        && oidc_sid.is_some_and(|sid| !sid.trim().is_empty())
}

/// High-impact administration requires an interactive MFA completed within five minutes.
/// Future authentication times may be valid session metadata but are not completed step-ups.
pub const ADMIN_MFA_MAX_AGE_SECONDS: i64 = 5 * 60;

#[must_use]
pub fn recent_interactive_mfa(auth_time: i64, amr: &[String], now: i64) -> bool {
    (0..=ADMIN_MFA_MAX_AGE_SECONDS).contains(&now.saturating_sub(auth_time))
        && amr.iter().any(|method| method == "mfa")
        && amr
            .iter()
            .any(|method| matches!(method.as_str(), "otp" | "recovery_code"))
}

pub fn add_amr(amr: &mut Vec<String>, value: &str) {
    if !amr.iter().any(|method| method == value) {
        amr.push(value.to_owned());
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    user_id: UserId,
    auth_time: i64,
    auth_time_micros: Option<i64>,
    amr: Vec<String>,
    pending_mfa: bool,
    oidc_sid: Option<String>,
    logged_in_client_ids: Vec<String>,
}

/// Opaque identifier for a browser login session.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SessionId(Box<str>);

impl std::fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionId([REDACTED])")
    }
}

impl SessionId {
    #[must_use]
    pub fn new(value: impl Into<Box<str>>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn generate() -> Self {
        let bytes: [u8; 32] = rand::random();
        Self(URL_SAFE_NO_PAD.encode(bytes).into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Opaque persistence revision used only for compare-and-swap rotation.
///
/// Storage adapters may preserve their exact serialized representation here;
/// domain callers cannot interpret or mutate it.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionVersion(Box<[u8]>);

impl std::fmt::Debug for SessionVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionVersion([REDACTED])")
    }
}

impl SessionVersion {
    #[doc(hidden)]
    #[must_use]
    pub fn from_storage(value: impl Into<Box<[u8]>>) -> Self {
        Self(value.into())
    }

    #[doc(hidden)]
    #[must_use]
    pub fn storage_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    record: SessionRecord,
    version: SessionVersion,
}

impl SessionSnapshot {
    #[must_use]
    pub fn new(record: SessionRecord, version: SessionVersion) -> Self {
        Self { record, version }
    }

    #[must_use]
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    #[doc(hidden)]
    #[must_use]
    pub fn version(&self) -> &SessionVersion {
        &self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRotationOutcome {
    Applied,
    Conflict,
    Collision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionUpdateOutcome {
    Applied,
    Conflict,
    Missing,
}

/// Account and authentication metadata resolved by `SessionService`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSession<A = PublicAccount> {
    pub user: A,
    pub pending_mfa: bool,
    pub auth_time: i64,
    pub auth_time_micros: Option<i64>,
    pub amr: Vec<String>,
    pub oidc_sid: String,
    pub logged_in_client_ids: Vec<String>,
}

impl<A> CurrentSession<A> {
    /// MFA flows may resolve either state from one validated storage snapshot.
    #[must_use]
    pub const fn pending_mfa(&self) -> bool {
        self.pending_mfa
    }

    #[must_use]
    pub fn user(&self) -> &A {
        &self.user
    }

    #[must_use]
    pub fn into_user(self) -> A {
        self.user
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.auth_time
    }

    #[must_use]
    pub const fn auth_time_micros(&self) -> Option<i64> {
        self.auth_time_micros
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    #[must_use]
    pub fn oidc_sid(&self) -> &str {
        &self.oidc_sid
    }

    #[must_use]
    pub fn logged_in_client_ids(&self) -> &[String] {
        &self.logged_in_client_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionResolution<A = PublicAccount> {
    Present(Box<CurrentSession<A>>),
    Missing,
    Invalidated,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionRotation {
    session_id: SessionId,
    csrf_token: Box<str>,
}

impl std::fmt::Debug for SessionRotation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionRotation([REDACTED])")
    }
}

impl SessionRotation {
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// Identity application service for resolving and atomically rotating sessions.
#[derive(Clone)]
pub struct SessionService {
    sessions: Arc<dyn crate::ports::SessionStorePort>,
    accounts: Arc<dyn crate::ports::SessionAccountPort>,
    tenant_id: TenantId,
}

impl SessionService {
    #[must_use]
    pub fn new(
        sessions: Arc<dyn crate::ports::SessionStorePort>,
        accounts: Arc<dyn crate::ports::SessionAccountPort>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            sessions,
            accounts,
            tenant_id,
        }
    }

    pub async fn delete(&self, session_id: &SessionId) -> Result<bool, RepositoryError> {
        self.sessions.delete(session_id).await
    }

    /// Remembers an RP as logged in within this exact OP browser session.
    ///
    /// The compare-and-set loop prevents concurrent authorization responses from
    /// losing each other's RP membership updates.
    pub async fn bind_client(
        &self,
        session_id: &SessionId,
        client_id: &str,
    ) -> Result<bool, RepositoryError> {
        if client_id.trim().is_empty() {
            return Err(RepositoryError::Consistency(
                "logged-in client identifier is empty".to_owned(),
            ));
        }
        for _ in 0..4 {
            let Some(snapshot) = self.load_fail_closed(session_id).await? else {
                return Ok(false);
            };
            if snapshot
                .record()
                .logged_in_client_ids()
                .iter()
                .any(|id| id == client_id)
            {
                return Ok(true);
            }
            let mut replacement = snapshot.record().clone();
            replacement.add_logged_in_client(client_id);
            match self
                .sessions
                .compare_and_set(session_id, &snapshot, &replacement)
                .await?
            {
                SessionUpdateOutcome::Applied => return Ok(true),
                SessionUpdateOutcome::Missing => return Ok(false),
                SessionUpdateOutcome::Conflict => {}
            }
        }
        Err(RepositoryError::Consistency(
            "session changed repeatedly while binding logged-in client".to_owned(),
        ))
    }

    pub async fn current(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution, RepositoryError> {
        self.resolve(session_id, now, Some(false), |id| {
            self.accounts.public_account_by_id(self.tenant_id, id)
        })
        .await
    }

    /// Resolve an identity/authorization guard without loading profile data.
    pub async fn current_principal(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution<crate::Principal>, RepositoryError> {
        self.resolve(session_id, now, Some(false), |id| {
            self.accounts.principal_by_id(self.tenant_id, id)
        })
        .await
    }

    pub async fn pending_mfa(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution, RepositoryError> {
        self.resolve(session_id, now, Some(true), |id| {
            self.accounts.public_account_by_id(self.tenant_id, id)
        })
        .await
    }

    /// Resolve active or pending MFA state with one session read and one active
    /// account check. State classification comes from that same validated snapshot.
    pub async fn resolve_for_mfa(
        &self,
        session_id: &SessionId,
        now: i64,
    ) -> Result<SessionResolution, RepositoryError> {
        self.resolve(session_id, now, None, |id| {
            self.accounts.public_account_by_id(self.tenant_id, id)
        })
        .await
    }

    pub async fn step_up(
        &self,
        session_id: &SessionId,
        method: &str,
        ttl_seconds: u64,
        require_pending_mfa: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<SessionRotation>, RepositoryError> {
        let Some(snapshot) = self.load_fail_closed(session_id).await? else {
            return Ok(None);
        };
        let mut replacement = snapshot.record().clone();
        if !valid_authentication_metadata(
            replacement.auth_time(),
            replacement.amr(),
            replacement.oidc_sid(),
            now.timestamp(),
        ) || (require_pending_mfa && !replacement.pending_mfa())
        {
            return Ok(None);
        }
        replacement.set_pending_mfa(false);
        replacement.record_authentication_at(now);
        replacement.add_amr(method);
        replacement.add_amr("mfa");

        let new_session_id = SessionId::generate();
        match self
            .sessions
            .rotate(
                session_id,
                &snapshot,
                &new_session_id,
                &replacement,
                ttl_seconds,
            )
            .await?
        {
            SessionRotationOutcome::Applied => Ok(Some(SessionRotation {
                session_id: new_session_id,
                csrf_token: random_urlsafe_token().into(),
            })),
            SessionRotationOutcome::Conflict => Ok(None),
            SessionRotationOutcome::Collision => Err(RepositoryError::Unexpected(
                "generated session identifier already exists".to_owned(),
            )),
        }
    }

    async fn resolve<'a, A: AsRef<crate::Principal>>(
        &'a self,
        session_id: &SessionId,
        now: i64,
        expected_pending_mfa: Option<bool>,
        load_account: impl FnOnce(UserId) -> crate::ports::RepositoryFuture<'a, Option<A>>,
    ) -> Result<SessionResolution<A>, RepositoryError> {
        let Some(snapshot) = self.load_fail_closed(session_id).await? else {
            return Ok(SessionResolution::Missing);
        };
        let record = snapshot.record;
        if !valid_authentication_metadata(record.auth_time(), record.amr(), record.oidc_sid(), now)
        {
            let _ = self.sessions.delete(session_id).await;
            return Ok(SessionResolution::Invalidated);
        }
        if expected_pending_mfa.is_some_and(|expected| record.pending_mfa() != expected) {
            return Ok(SessionResolution::Missing);
        }
        let Some(user) = load_account(record.user_id())
            .await?
            .filter(|account| account.as_ref().active)
        else {
            let _ = self.sessions.delete(session_id).await;
            return Ok(SessionResolution::Invalidated);
        };
        Ok(SessionResolution::Present(Box::new(CurrentSession {
            user,
            pending_mfa: record.pending_mfa(),
            auth_time: record.auth_time(),
            auth_time_micros: record.auth_time_micros(),
            amr: record.amr,
            oidc_sid: record.oidc_sid.expect("validated session has an OIDC sid"),
            logged_in_client_ids: record.logged_in_client_ids,
        })))
    }

    async fn load_fail_closed(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionSnapshot>, RepositoryError> {
        match self.sessions.load(session_id).await {
            Ok(snapshot) => Ok(snapshot),
            Err(RepositoryError::Consistency(_)) => {
                let _ = self.sessions.delete(session_id).await;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

fn random_urlsafe_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

impl SessionRecord {
    #[must_use]
    pub fn new(
        user_id: UserId,
        auth_time: i64,
        amr: Vec<String>,
        pending_mfa: bool,
        oidc_sid: Option<String>,
    ) -> Self {
        Self {
            user_id,
            auth_time,
            auth_time_micros: None,
            amr,
            pending_mfa,
            oidc_sid,
            logged_in_client_ids: Vec::new(),
        }
    }

    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.auth_time
    }

    #[must_use]
    pub const fn auth_time_micros(&self) -> Option<i64> {
        self.auth_time_micros
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    #[must_use]
    pub const fn pending_mfa(&self) -> bool {
        self.pending_mfa
    }

    #[must_use]
    pub fn oidc_sid(&self) -> Option<&str> {
        self.oidc_sid.as_deref()
    }

    #[must_use]
    pub fn logged_in_client_ids(&self) -> &[String] {
        &self.logged_in_client_ids
    }

    pub fn add_logged_in_client(&mut self, client_id: impl AsRef<str> + Into<String>) {
        if !self
            .logged_in_client_ids
            .iter()
            .any(|id| id == client_id.as_ref())
        {
            self.logged_in_client_ids.push(client_id.into());
        }
    }

    /// Record an authentication event without losing ordering within an OIDC second.
    pub fn record_authentication_at(&mut self, now: chrono::DateTime<chrono::Utc>) {
        self.auth_time = now.timestamp();
        self.auth_time_micros = Some(now.timestamp_micros());
    }

    /// Restore optional precision from persistence; legacy seconds are not fresh-login proof.
    pub fn restore_auth_time_micros(&mut self, value: Option<i64>) -> bool {
        if value.is_some_and(|micros| micros <= 0 || micros / 1_000_000 != self.auth_time) {
            return false;
        }
        self.auth_time_micros = value;
        true
    }

    pub fn set_auth_time(&mut self, auth_time: i64) {
        self.auth_time = auth_time;
        self.auth_time_micros = None;
    }

    pub fn set_pending_mfa(&mut self, pending_mfa: bool) {
        self.pending_mfa = pending_mfa;
    }

    pub fn add_amr(&mut self, value: &str) {
        add_amr(&mut self.amr, value);
    }
}

#[cfg(test)]
#[path = "../tests/unit/session.rs"]
mod tests;
