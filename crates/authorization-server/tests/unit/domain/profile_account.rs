use std::sync::Arc;

use crate::contracts::profile_account::{ProfileAccountError, ProfileMe};
use chrono::{TimeZone as _, Utc};
use nazo_identity::{
    AccountIdentity, AccountProfileService, Principal, ProfilePatch, PublicAccount, SessionId,
    SessionService, TenantContext, TenantId, UserId, UserProfile, UserRole,
    ports::{
        AuthorizedApplication, AuthorizedApplicationRepositoryPort, GrantSummaryRepositoryPort,
        ProfileRepositoryPort, RepositoryError, RepositoryFuture, SessionAccountPort,
        SessionStorePort,
    },
    session::{SessionRecord, SessionRotationOutcome, SessionSnapshot, SessionVersion},
};
use serde_json::json;
use uuid::Uuid;

use super::ServerProfileAccountOperations;

#[derive(Clone)]
struct FixedSessionStore {
    load: Result<Option<SessionSnapshot>, RepositoryError>,
    loads: Arc<std::sync::atomic::AtomicUsize>,
}

impl SessionStorePort for FixedSessionStore {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        let load = self.load.clone();
        let loads = self.loads.clone();
        Box::pin(async move {
            loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            load
        })
    }

    fn delete<'a>(&'a self, _session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn rotate<'a>(
        &'a self,
        _old_session_id: &'a SessionId,
        _expected: &'a SessionVersion,
        _new_session_id: &'a SessionId,
        _replacement: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async { Ok(SessionRotationOutcome::Applied) })
    }

    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a SessionId,
        _expected: &'a SessionVersion,
        _replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, nazo_identity::SessionUpdateOutcome> {
        Box::pin(async { Ok(nazo_identity::SessionUpdateOutcome::Applied) })
    }
}

#[derive(Clone)]
struct FixedSessionAccounts(Option<PublicAccount>, bool);

impl SessionAccountPort for FixedSessionAccounts {
    fn principal_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<Principal>> {
        Box::pin(async move { Ok(self.0.as_ref().map(|account| account.principal.clone())) })
    }

    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        assert!(self.1, "this operation must use the principal projection");
        let account = self.0.clone();
        Box::pin(async move { Ok(account) })
    }
}

#[derive(Clone)]
struct StoredProfile(PublicAccount);

impl ProfileRepositoryPort for StoredProfile {
    fn update_profile<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        update: ProfilePatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        let mut account = self.0.clone();
        let phone_number_verified = account.profile.phone_number_verified
            && account.profile.phone_number == update.phone_number;
        account.profile = UserProfile {
            display_name: update.display_name,
            given_name: update.given_name,
            family_name: update.family_name,
            middle_name: update.middle_name,
            nickname: update.nickname,
            profile_url: update.profile_url,
            website_url: update.website_url,
            gender: update.gender,
            birthdate: update.birthdate,
            zoneinfo: update.zoneinfo,
            locale: update.locale,
            phone_number: update.phone_number,
            avatar_url: account.profile.avatar_url.take(),
            phone_number_verified,
            address: nazo_identity::PostalAddress {
                formatted: update.address_formatted,
                street_address: update.address_street_address,
                locality: update.address_locality,
                region: update.address_region,
                postal_code: update.address_postal_code,
                country: update.address_country,
            },
        };
        Box::pin(async move { Ok(account) })
    }
}

#[derive(Clone, Copy)]
struct FixedGrantSummary(i64);

impl GrantSummaryRepositoryPort for FixedGrantSummary {
    fn authorized_client_count(
        &self,
        _tenant_id: TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        let count = self.0;
        Box::pin(async move { Ok(count) })
    }
}

#[derive(Clone)]
struct FixedApplications(Vec<AuthorizedApplication>);

impl AuthorizedApplicationRepositoryPort for FixedApplications {
    fn applications_for_user(
        &self,
        _tenant_id: TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        let applications = self.0.clone();
        Box::pin(async move { Ok(applications) })
    }
}

type Operations = ServerProfileAccountOperations;

fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(10)).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile {
            display_name: Some("Alice".to_owned()),
            phone_number: Some("+15550000001".to_owned()),
            phone_number_verified: true,
            ..UserProfile::default()
        },
        created_at: now,
        updated_at: now,
    }
}

fn snapshot(pending_mfa: bool) -> SessionSnapshot {
    SessionSnapshot::new(
        SessionRecord::new(
            account().user_id(),
            Utc::now().timestamp(),
            vec!["pwd".to_owned()],
            pending_mfa,
            Some("oidc-session".to_owned()),
        ),
        SessionVersion::from_storage(b"version-1".to_vec().into_boxed_slice()),
    )
}

fn operations(
    load: Result<Option<SessionSnapshot>, RepositoryError>,
    applications: Vec<AuthorizedApplication>,
) -> Operations {
    operations_with_loads(load, applications, Arc::default())
}

fn operations_with_loads(
    load: Result<Option<SessionSnapshot>, RepositoryError>,
    applications: Vec<AuthorizedApplication>,
    loads: Arc<std::sync::atomic::AtomicUsize>,
) -> Operations {
    let account = account();
    ServerProfileAccountOperations::new(
        SessionService::new(
            Arc::new(FixedSessionStore { load, loads }),
            Arc::new(FixedSessionAccounts(Some(account.clone()), true)),
            account.tenant().tenant_id,
        ),
        AccountProfileService::new(
            StoredProfile(account),
            FixedGrantSummary(2),
            FixedApplications(applications),
        ),
    )
}

#[test]
fn profile_update_and_application_list_only_load_the_session_principal() {
    futures_executor::block_on(async {
        let account = account();
        let operations = ServerProfileAccountOperations::new(
            SessionService::new(
                Arc::new(FixedSessionStore {
                    load: Ok(Some(snapshot(false))),
                    loads: Arc::default(),
                }),
                Arc::new(FixedSessionAccounts(Some(account.clone()), false)),
                account.tenant().tenant_id,
            ),
            AccountProfileService::new(
                StoredProfile(account),
                FixedGrantSummary(2),
                FixedApplications(Vec::new()),
            ),
        );
        let updated = operations
            .update(
                SessionId::new("active"),
                ProfilePatch {
                    display_name: Some(" Alice Updated ".into()),
                    ..ProfilePatch::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name.as_deref(), Some("Alice Updated"));
        let applications = operations
            .applications(SessionId::new("active"))
            .await
            .unwrap();
        assert_eq!(applications.total, 0);
    });
}

#[test]
fn active_and_pending_sessions_expose_their_distinct_profile_shapes() {
    futures_executor::block_on(async {
        let active = operations(Ok(Some(snapshot(false))), Vec::new())
            .me(SessionId::new("active"))
            .await
            .unwrap();
        let ProfileMe::Active(active) = active else {
            panic!("active session must produce the full profile")
        };
        assert_eq!(active.email, "alice@example.test");
        assert_eq!(active.display_name.as_deref(), Some("Alice"));
        assert_eq!(active.authorized_app_count, 2);

        let pending = operations(Ok(Some(snapshot(true))), Vec::new())
            .me(SessionId::new("pending"))
            .await
            .unwrap();
        let ProfileMe::PendingMfa(pending) = pending else {
            panic!("pending MFA session must produce the reduced profile")
        };
        assert_eq!(pending.email, "alice@example.test");
        assert_eq!(pending.id, account().id());
    });
}

#[test]
fn missing_and_unavailable_sessions_remain_distinct_errors() {
    futures_executor::block_on(async {
        let missing = operations(Ok(None), Vec::new())
            .me(SessionId::new("missing"))
            .await;
        assert_eq!(missing, Err(ProfileAccountError::LoginRequired));

        let unavailable = operations(Err(RepositoryError::Unavailable), Vec::new())
            .me(SessionId::new("unavailable"))
            .await;
        assert_eq!(
            unavailable,
            Err(ProfileAccountError::SessionLookupUnavailable)
        );
    });
}

#[test]
fn update_validation_and_application_projection_stay_in_focused_services() {
    futures_executor::block_on(async {
        let application = AuthorizedApplication {
            client_id: "client-1".to_owned(),
            client_name: "Example Client".to_owned(),
            last_scopes: json!(["openid", 42, null, "profile"]),
            last_authorized_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            authorization_count: 3,
        };
        let operations = operations(Ok(Some(snapshot(false))), vec![application]);

        let update = operations
            .update(
                SessionId::new("active"),
                ProfilePatch {
                    profile_url: Some("javascript:alert(1)".to_owned()),
                    ..ProfilePatch::default()
                },
            )
            .await;
        assert_eq!(
            update,
            Err(ProfileAccountError::Validation(
                nazo_identity::ProfileValidationError::InvalidHttpUrl("profile_url")
            ))
        );

        let applications = operations
            .applications(SessionId::new("active"))
            .await
            .unwrap();
        assert_eq!(applications.total, 1);
        assert_eq!(applications.items[0].last_scopes, vec!["openid", "profile"]);
        assert_eq!(applications.items[0].authorization_count, 3);
    });
}

#[test]
fn auth_me_classifies_active_pending_missing_and_invalidated_from_one_session_read() {
    futures_executor::block_on(async {
        for pending in [false, true] {
            let loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let result =
                operations_with_loads(Ok(Some(snapshot(pending))), Vec::new(), loads.clone())
                    .me(SessionId::new("classified"))
                    .await
                    .unwrap();
            assert_eq!(matches!(result, ProfileMe::PendingMfa(_)), pending);
            assert_eq!(loads.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
        let invalid = SessionSnapshot::new(
            SessionRecord::new(
                account().user_id(),
                i64::MAX,
                vec!["pwd".to_owned()],
                true,
                Some("sid".to_owned()),
            ),
            SessionVersion::from_storage(b"invalid".to_vec().into_boxed_slice()),
        );
        for load in [
            Ok(None),
            Ok(Some(invalid)),
            Err(RepositoryError::Unavailable),
        ] {
            let unavailable = load.is_err();
            let loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let result = operations_with_loads(load, Vec::new(), loads.clone())
                .me(SessionId::new("missing-or-invalid"))
                .await;
            assert_eq!(
                result,
                Err(if unavailable {
                    ProfileAccountError::SessionLookupUnavailable
                } else {
                    ProfileAccountError::LoginRequired
                })
            );
            assert_eq!(loads.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    });
}
