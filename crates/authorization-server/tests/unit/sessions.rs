use super::*;
use futures_executor::block_on;
use nazo_identity::{
    AccountIdentity, Principal, TenantContext, UserId, UserProfile, UserRole,
    ports::RepositoryFuture,
    session::{
        SessionRecord, SessionRotationOutcome, SessionSnapshot, SessionUpdateOutcome,
        SessionVersion,
    },
};
use std::sync::Mutex;

struct FakeSessionStore {
    loaded: Result<Option<SessionSnapshot>, RepositoryError>,
    deleted: Mutex<Vec<SessionId>>,
}

impl FakeSessionStore {
    fn new(loaded: Result<Option<SessionSnapshot>, RepositoryError>) -> Self {
        Self {
            loaded,
            deleted: Mutex::new(Vec::new()),
        }
    }
}

impl SessionStorePort for FakeSessionStore {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async { self.loaded.clone() })
    }

    fn delete<'a>(&'a self, session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        self.deleted.lock().unwrap().push(session_id.clone());
        Box::pin(async { Ok(true) })
    }

    fn rotate<'a>(
        &'a self,
        _old_session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _new_session_id: &'a SessionId,
        _replacement: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        panic!("session lookup must not rotate sessions")
    }

    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, SessionUpdateOutcome> {
        panic!("session lookup must not update sessions")
    }
}

struct FakeAccounts {
    account: Result<Option<PublicAccount>, RepositoryError>,
    lookups: Mutex<Vec<(TenantId, UserId)>>,
}

impl FakeAccounts {
    fn new(account: Result<Option<PublicAccount>, RepositoryError>) -> Self {
        Self {
            account,
            lookups: Mutex::new(Vec::new()),
        }
    }
}

impl SessionAccountPort for FakeAccounts {
    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        self.lookups.lock().unwrap().push((tenant_id, user_id));
        Box::pin(async { self.account.clone() })
    }
}

fn snapshot(pending_mfa: bool, oidc_sid: Option<&str>) -> SessionSnapshot {
    let mut record = SessionRecord::new(
        UserId::new(Uuid::from_u128(2)).unwrap(),
        1_000,
        vec!["password".to_owned(), "otp".to_owned(), "mfa".to_owned()],
        pending_mfa,
        oidc_sid.map(str::to_owned),
    );
    record.add_logged_in_client("client-b");
    record.add_logged_in_client("client-a");
    SessionSnapshot::new(
        record,
        SessionVersion::from_storage(b"version-1".to_vec().into_boxed_slice()),
    )
}

fn account(active: bool) -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(2)).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active,
        },
        account: AccountIdentity {
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}

fn resolver(store: Arc<FakeSessionStore>, accounts: Arc<FakeAccounts>) -> SessionResolver {
    SessionResolver::new(store, accounts, TenantContext::default_system().tenant_id)
}

#[test]
fn corrupt_session_snapshot_is_deleted_and_treated_as_anonymous_through_port() {
    let sid = "corrupt-session";
    let store = Arc::new(FakeSessionStore::new(Err(RepositoryError::Consistency(
        "malformed session".to_owned(),
    ))));
    let accounts = Arc::new(FakeAccounts::new(Ok(None)));
    let current = block_on(resolver(store.clone(), accounts.clone()).current_session_by_id(sid))
        .expect("corrupt session should be invalidated rather than fail open");

    assert!(current.is_none());
    assert_eq!(
        store.deleted.lock().unwrap().as_slice(),
        &[SessionId::new(sid)]
    );
    assert!(accounts.lookups.lock().unwrap().is_empty());
}

#[test]
fn unavailable_session_store_fails_closed_without_deleting_state() {
    let store = Arc::new(FakeSessionStore::new(Err(RepositoryError::Unavailable)));
    let accounts = Arc::new(FakeAccounts::new(Ok(None)));

    assert!(
        block_on(
            resolver(store.clone(), accounts.clone()).current_session_by_id("unavailable-session")
        )
        .is_err(),
        "infrastructure errors must not become anonymous sessions"
    );
    assert!(store.deleted.lock().unwrap().is_empty());
    assert!(accounts.lookups.lock().unwrap().is_empty());
}

#[test]
fn missing_and_pending_sessions_are_anonymous_without_account_lookup_or_deletion() {
    for stored in [None, Some(snapshot(true, Some("sid-1")))] {
        let store = Arc::new(FakeSessionStore::new(Ok(stored)));
        let accounts = Arc::new(FakeAccounts::new(Ok(None)));

        assert!(
            block_on(resolver(store.clone(), accounts.clone()).current_session_by_id("session-1"))
                .unwrap()
                .is_none()
        );
        assert!(store.deleted.lock().unwrap().is_empty());
        assert!(accounts.lookups.lock().unwrap().is_empty());
    }
}

#[test]
fn invalid_authentication_metadata_is_cleared_before_pending_mfa_is_considered() {
    for pending_mfa in [false, true] {
        let store = Arc::new(FakeSessionStore::new(Ok(Some(snapshot(pending_mfa, None)))));
        let accounts = Arc::new(FakeAccounts::new(Ok(None)));

        assert!(
            block_on(resolver(store.clone(), accounts.clone()).current_session_by_id("session-1"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.deleted.lock().unwrap().as_slice(),
            &[SessionId::new("session-1")]
        );
        assert!(accounts.lookups.lock().unwrap().is_empty());
    }
}

#[test]
fn deleted_and_inactive_accounts_invalidate_sessions() {
    for user in [None, Some(account(false))] {
        let store = Arc::new(FakeSessionStore::new(Ok(Some(snapshot(
            false,
            Some("sid-1"),
        )))));
        let accounts = Arc::new(FakeAccounts::new(Ok(user)));

        assert!(
            block_on(resolver(store.clone(), accounts.clone()).current_session_by_id("session-1"))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.deleted.lock().unwrap().as_slice(),
            &[SessionId::new("session-1")]
        );
        assert_eq!(
            accounts.lookups.lock().unwrap().as_slice(),
            &[(
                TenantContext::default_system().tenant_id,
                UserId::new(Uuid::from_u128(2)).unwrap()
            )]
        );
    }
}

#[test]
fn unavailable_accounts_fail_closed_without_invalidating_the_session() {
    let store = Arc::new(FakeSessionStore::new(Ok(Some(snapshot(
        false,
        Some("sid-1"),
    )))));
    let accounts = Arc::new(FakeAccounts::new(Err(RepositoryError::Unavailable)));

    assert!(
        block_on(resolver(store.clone(), accounts).current_session_by_id("session-1")).is_err()
    );
    assert!(store.deleted.lock().unwrap().is_empty());
}

#[test]
fn resolved_session_preserves_account_authentication_and_logged_in_clients() {
    let user = account(true);
    let store = Arc::new(FakeSessionStore::new(Ok(Some(snapshot(
        false,
        Some("sid-1"),
    )))));
    let accounts = Arc::new(FakeAccounts::new(Ok(Some(user.clone()))));

    let current = block_on(resolver(store.clone(), accounts).current_session_by_id("session-1"))
        .unwrap()
        .unwrap();
    assert_eq!(current.user, user);
    assert_eq!(current.auth_time, 1_000);
    assert_eq!(current.amr, ["password", "otp", "mfa"]);
    assert_eq!(current.oidc_sid, "sid-1");
    assert_eq!(current.logged_in_client_ids, ["client-b", "client-a"]);
    assert!(store.deleted.lock().unwrap().is_empty());
}

#[test]
fn administrator_policy_requires_a_positive_admin_level() {
    assert!(matches!(
        require_admin_session(None),
        Err(AdminSessionError::AccessDenied)
    ));
    for (role, allowed) in [
        (UserRole::User, false),
        (UserRole::Admin { level: 0 }, false),
        (UserRole::Admin { level: 1 }, true),
    ] {
        let mut user = account(true);
        user.principal.role = role;
        let session = CurrentSession {
            user,
            auth_time: 1_000,
            amr: vec!["password".to_owned()],
            oidc_sid: "sid-1".to_owned(),
            logged_in_client_ids: Vec::new(),
        };
        assert_eq!(require_admin_session(Some(session)).is_ok(), allowed);
    }
}

fn valid_payload() -> SessionPayload {
    SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        pending_mfa: false,
        oidc_sid: Some("sid-1".to_owned()),
    }
}

#[test]
fn session_payload_requires_authentication_metadata_and_oidc_sid() {
    let valid = valid_payload();

    assert!(valid_session_payload(&valid, 1_001));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: None,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: Some(" ".to_owned()),
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 0,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 2_000,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            amr: Vec::new(),
            ..valid
        },
        1_001
    ));
}

#[test]
fn session_payload_allows_only_small_clock_skew_for_auth_time() {
    let mut payload = valid_payload();

    payload.auth_time = 1_030;
    assert!(valid_session_payload(&payload, 1_000));

    payload.auth_time = 1_031;
    assert!(!valid_session_payload(&payload, 1_000));
}

#[test]
fn session_payload_preserves_pending_mfa_as_metadata_not_validity() {
    let mut payload = valid_payload();
    payload.pending_mfa = true;

    assert!(valid_session_payload(&payload, 1_001));
}

#[test]
fn session_payload_requires_non_blank_oidc_sid_after_trimming() {
    for sid in ["", " ", "\t\n"] {
        let mut payload = valid_payload();
        payload.oidc_sid = Some(sid.to_owned());

        assert!(
            !valid_session_payload(&payload, 1_001),
            "blank sid {sid:?} must not produce an OIDC session"
        );
    }
}

#[test]
fn recent_admin_mfa_requires_a_fresh_interactive_factor() {
    let fresh = vec!["password".to_owned(), "otp".to_owned(), "mfa".to_owned()];
    assert!(recent_mfa_authentication(1_000, &fresh, 1_300));

    let old = vec!["password".to_owned(), "otp".to_owned(), "mfa".to_owned()];
    assert!(!recent_mfa_authentication(1_000, &old, 1_301));

    let no_factor = vec!["password".to_owned(), "mfa".to_owned()];
    assert!(!recent_mfa_authentication(1_000, &no_factor, 1_001));

    let remembered = vec![
        "password".to_owned(),
        "remembered_mfa".to_owned(),
        "mfa".to_owned(),
    ];
    assert!(!recent_mfa_authentication(1_000, &remembered, 1_001));

    let stepped_up_after_remembered = vec![
        "password".to_owned(),
        "remembered_mfa".to_owned(),
        "otp".to_owned(),
        "mfa".to_owned(),
    ];
    assert!(recent_mfa_authentication(
        1_000,
        &stepped_up_after_remembered,
        1_001
    ));

    let future = vec![
        "password".to_owned(),
        "recovery_code".to_owned(),
        "mfa".to_owned(),
    ];
    assert!(!recent_mfa_authentication(1_100, &future, 1_000));
}
