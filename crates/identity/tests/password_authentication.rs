use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use chrono::Utc;
use nazo_identity::{
    AuthenticatePasswordError, AuthenticatePasswordInput, AuthenticationIdentity,
    AuthenticationService, AuthenticationServiceConfig, PasswordHash, TenantContext, TenantId,
    UserId,
    ports::{
        AuthenticationAuditEvent, AuthenticationAuditPort, LoginAccountRepositoryPort,
        LoginAccountState, LoginSessionCreate, LoginSessionPort, LoginThrottlePort,
        RememberedMfaDevicePort, RepositoryFuture, SecretVerifyFuture, SecretVerifyPort,
    },
    session::SessionRecord,
};
use uuid::Uuid;

#[derive(Clone)]
struct Accounts(Option<AuthenticationIdentity>);

impl LoginAccountRepositoryPort for Accounts {
    fn authentication_by_email<'a>(
        &'a self,
        _tenant_id: TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<AuthenticationIdentity>> {
        let identity = self.0.clone();
        Box::pin(async move { Ok(identity) })
    }

    fn login_state_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<LoginAccountState>> {
        Box::pin(async { panic!("non-authenticatable accounts must not load login state") })
    }
}

#[derive(Clone, Default)]
struct Throttles(Arc<AtomicUsize>);

impl LoginThrottlePort for Throttles {
    fn failure_count<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
    ) -> RepositoryFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn record_failure<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
        _window_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }

    fn clear_failure<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone)]
struct Verifier(Arc<Mutex<Vec<PasswordHash>>>);

impl SecretVerifyPort for Verifier {
    fn verify_secret(
        &self,
        _secret: String,
        password_hash: PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        self.0.lock().unwrap().push(password_hash);
        Box::pin(async { Ok(false) })
    }
}

#[derive(Clone, Copy)]
struct RememberedMfa;

impl RememberedMfaDevicePort for RememberedMfa {
    fn is_valid<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        _token_hash: &'a str,
        _user_agent_hash: Option<&'a str>,
        _now: chrono::DateTime<Utc>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Clone, Copy)]
struct Sessions;

impl LoginSessionPort for Sessions {
    fn create<'a>(
        &'a self,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        panic!("invalid credentials must not create a session")
    }

    fn create_replacing<'a>(
        &'a self,
        _previous_session_id: Option<&'a str>,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        panic!("invalid credentials must not replace a session")
    }
}

#[derive(Clone, Default)]
struct RecordingSessions(Arc<Mutex<Vec<u64>>>);

impl LoginSessionPort for RecordingSessions {
    fn create<'a>(
        &'a self,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.0.lock().unwrap().push(ttl_seconds);
        Box::pin(async { Ok(LoginSessionCreate::Created) })
    }

    fn create_replacing<'a>(
        &'a self,
        _previous_session_id: Option<&'a str>,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.0.lock().unwrap().push(ttl_seconds);
        Box::pin(async { Ok(LoginSessionCreate::Created) })
    }
}

#[derive(Clone, Copy)]
struct AlwaysValidVerifier;

impl SecretVerifyPort for AlwaysValidVerifier {
    fn verify_secret(
        &self,
        _secret: String,
        _password_hash: PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Clone)]
struct ActiveAccounts {
    authentication: AuthenticationIdentity,
    state: LoginAccountState,
}

impl LoginAccountRepositoryPort for ActiveAccounts {
    fn authentication_by_email<'a>(
        &'a self,
        _tenant_id: TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<AuthenticationIdentity>> {
        let authentication = self.authentication.clone();
        Box::pin(async move { Ok(Some(authentication)) })
    }

    fn login_state_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<LoginAccountState>> {
        let state = self.state;
        Box::pin(async move { Ok(Some(state)) })
    }
}

#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Vec<AuthenticationAuditEvent>>>);

impl AuthenticationAuditPort for Audit {
    fn record(&self, event: AuthenticationAuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn inactive_identity() -> AuthenticationIdentity {
    AuthenticationIdentity {
        user_id: UserId::new(Uuid::now_v7()).unwrap(),
        active: false,
        password_hash: PasswordHash::new("persisted-password-hash").unwrap(),
    }
}

fn active_identity() -> AuthenticationIdentity {
    AuthenticationIdentity {
        active: true,
        ..inactive_identity()
    }
}

#[tokio::test]
async fn missing_and_inactive_accounts_share_dummy_verification_and_failure_behavior() {
    for authentication in [None, Some(inactive_identity())] {
        let dummy_hash = PasswordHash::new("dummy-password-hash").unwrap();
        let verified_hashes = Arc::new(Mutex::new(Vec::new()));
        let throttles = Throttles::default();
        let audit = Audit::default();
        let service = AuthenticationService::new(
            Accounts(authentication.clone()),
            throttles.clone(),
            Verifier(verified_hashes.clone()),
            RememberedMfa,
            Sessions,
            audit.clone(),
            AuthenticationServiceConfig {
                tenant_id: TenantContext::default_system().tenant_id,
                dummy_password_hash: dummy_hash.clone(),
                failure_window_seconds: 60,
                failure_ip_email_max_attempts: 5,
                session_ttl_seconds: 300,
                pending_mfa_session_ttl_seconds: 120,
            },
        );

        let result = service
            .authenticate_password(AuthenticatePasswordInput {
                email: "account@example.com".to_owned(),
                password: "candidate".to_owned(),
                source_ip: "192.0.2.1".to_owned(),
                remembered_mfa: None,
                previous_session_id: Some("old-session".to_owned()),
                now: Utc::now(),
            })
            .await;

        assert_eq!(result, Err(AuthenticatePasswordError::InvalidCredentials));
        assert_eq!(*verified_hashes.lock().unwrap(), vec![dummy_hash]);
        assert_eq!(throttles.0.load(Ordering::Relaxed), 1);
        let events = audit.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            AuthenticationAuditEvent::Failure { user_id, .. }
                if *user_id == authentication.as_ref().map(|identity| identity.user_id)
        ));
    }
}

#[tokio::test]
async fn login_uses_current_account_state_after_password_verification() {
    for (active, mfa_enabled) in [(true, true), (true, false), (false, true)] {
        let authentication = active_identity();
        let state = LoginAccountState {
            active,
            mfa_enabled,
        };
        let sessions = RecordingSessions::default();
        let service = AuthenticationService::new(
            ActiveAccounts {
                authentication,
                state,
            },
            Throttles::default(),
            AlwaysValidVerifier,
            RememberedMfa,
            sessions.clone(),
            Audit::default(),
            AuthenticationServiceConfig {
                tenant_id: TenantContext::default_system().tenant_id,
                dummy_password_hash: PasswordHash::new("dummy-password-hash").unwrap(),
                failure_window_seconds: 60,
                failure_ip_email_max_attempts: 5,
                session_ttl_seconds: 300,
                pending_mfa_session_ttl_seconds: 120,
            },
        );

        let result = service
            .authenticate_password(AuthenticatePasswordInput {
                email: "active@example.com".to_owned(),
                password: "candidate".to_owned(),
                source_ip: "192.0.2.1".to_owned(),
                remembered_mfa: None,
                previous_session_id: None,
                now: Utc::now(),
            })
            .await;

        if active {
            assert_eq!(result.unwrap().session.pending_mfa(), mfa_enabled);
            assert_eq!(
                *sessions.0.lock().unwrap(),
                vec![if mfa_enabled { 120 } else { 300 }]
            );
        } else {
            assert_eq!(result, Err(AuthenticatePasswordError::InactiveAccount));
            assert!(sessions.0.lock().unwrap().is_empty());
        }
    }
}
