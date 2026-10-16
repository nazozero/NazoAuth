use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use chrono::Utc;
use uuid::Uuid;

use crate::{
    AccountIdentity, Principal, PublicAccount, TenantContext, TenantId, UserId, UserProfile,
    UserRole,
    ports::{
        AuthorizedApplication, AuthorizedApplicationRepositoryPort, GrantSummaryRepositoryPort,
        ProfileRepositoryPort, RepositoryError, RepositoryFuture,
    },
};

use super::{
    AccountProfileService, ProfilePatch, ProfileValidationError, UpdateProfileError,
    normalize_profile_url, profile_text,
};

#[derive(Clone)]
struct StoredProfileRepository {
    account: Arc<Mutex<PublicAccount>>,
    writes: Arc<AtomicUsize>,
}

impl ProfileRepositoryPort for StoredProfileRepository {
    fn update_profile<'a>(
        &'a self,
        _tenant_id: crate::TenantId,
        _user_id: UserId,
        update: ProfilePatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        let mut account = self.account.lock().unwrap();
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
            address: crate::PostalAddress {
                formatted: update.address_formatted,
                street_address: update.address_street_address,
                locality: update.address_locality,
                region: update.address_region,
                postal_code: update.address_postal_code,
                country: update.address_country,
            },
        };
        self.writes.fetch_add(1, Ordering::Relaxed);
        let account = account.clone();
        Box::pin(async move { Ok(account) })
    }
}

#[derive(Clone)]
struct FailFirstGrantSummary {
    calls: Arc<AtomicUsize>,
}

impl GrantSummaryRepositoryPort for FailFirstGrantSummary {
    fn authorized_client_count(
        &self,
        _tenant_id: TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, i64> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            if call == 0 {
                Err(RepositoryError::Unavailable)
            } else {
                Ok(2)
            }
        })
    }
}

#[derive(Clone, Copy)]
struct EmptyApplications;

impl AuthorizedApplicationRepositoryPort for EmptyApplications {
    fn applications_for_user(
        &self,
        _tenant_id: TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[derive(Clone)]
struct RecordingApplications(Arc<Mutex<Vec<TenantId>>>);

impl AuthorizedApplicationRepositoryPort for RecordingApplications {
    fn applications_for_user(
        &self,
        tenant_id: TenantId,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        self.0.lock().unwrap().push(tenant_id);
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(10)).unwrap(),
            tenant: TenantContext::default(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        },
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn applications_are_loaded_from_the_accounts_tenant() {
    let account = account();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let service = AccountProfileService::new(
        StoredProfileRepository {
            account: Arc::new(Mutex::new(account.clone())),
            writes: Arc::new(AtomicUsize::new(0)),
        },
        FailFirstGrantSummary {
            calls: Arc::new(AtomicUsize::new(1)),
        },
        RecordingApplications(observed.clone()),
    );

    assert!(
        service
            .applications(&account.principal)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(*observed.lock().unwrap(), vec![account.tenant().tenant_id]);
}

#[test]
fn profile_text_trims_blanks_and_enforces_byte_limit() {
    assert_eq!(profile_text(None, 8, "name").unwrap(), None);
    assert_eq!(profile_text(Some("   ".into()), 8, "name").unwrap(), None);
    assert_eq!(
        profile_text(Some(" Alice ".into()), 8, "name").unwrap(),
        Some("Alice".into())
    );
    assert_eq!(
        profile_text(Some("abcdefghi".into()), 8, "name"),
        Err(ProfileValidationError::FieldTooLong("name"))
    );
}

#[test]
fn profile_normalization_reuses_owned_text_and_scope_strings() {
    let text = String::from("  阿丽丝\u{3000}");
    let allocation = text.as_ptr();
    let result = profile_text(Some(text), 32, "name").unwrap().unwrap();
    assert_eq!(result, "阿丽丝");
    assert_eq!(result.as_ptr(), allocation);
    let scope = String::from("openid");
    let allocation = scope.as_ptr();
    let view = super::AuthorizedApplicationView::from(AuthorizedApplication {
        client_id: "client".into(),
        client_name: "Client".into(),
        last_scopes: serde_json::Value::Array(vec![
            serde_json::Value::String(scope),
            serde_json::Value::Null,
        ]),
        last_authorized_at: Utc::now(),
        authorization_count: 1,
    });
    assert_eq!(view.last_scopes, ["openid"]);
    assert_eq!(view.last_scopes[0].as_ptr(), allocation);
}

#[test]
fn profile_url_accepts_only_absolute_http_urls() {
    assert_eq!(
        normalize_profile_url(Some(" https://example.com/u ".into()), "profile_url").unwrap(),
        Some("https://example.com/u".into())
    );
    for value in ["relative", "/relative", "javascript:alert(1)", "mailto:a@b"] {
        assert_eq!(
            normalize_profile_url(Some(value.into()), "profile_url"),
            Err(if matches!(value, "relative" | "/relative") {
                ProfileValidationError::InvalidAbsoluteUrl("profile_url")
            } else {
                ProfileValidationError::InvalidHttpUrl("profile_url")
            })
        );
    }
}

#[tokio::test]
async fn retry_is_idempotent_when_profile_write_succeeds_before_overview_failure() {
    let original = account();
    let stored = Arc::new(Mutex::new(original.clone()));
    let writes = Arc::new(AtomicUsize::new(0));
    let service = AccountProfileService::new(
        StoredProfileRepository {
            account: stored.clone(),
            writes: writes.clone(),
        },
        FailFirstGrantSummary {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        EmptyApplications,
    );
    let patch = ProfilePatch {
        display_name: Some(" Alice ".to_owned()),
        ..ProfilePatch::default()
    };

    let first = service.update(&original.principal, patch.clone()).await;
    assert_eq!(
        first,
        Err(UpdateProfileError::OverviewRepository(
            RepositoryError::Unavailable
        ))
    );
    assert_eq!(
        stored.lock().unwrap().profile.display_name.as_deref(),
        Some("Alice"),
        "the profile write is committed before the independent overview read"
    );

    let retry = service.update(&original.principal, patch).await.unwrap();
    assert_eq!(retry.account.profile.display_name.as_deref(), Some("Alice"));
    assert_eq!(retry.authorized_application_count, 2);
    assert_eq!(writes.load(Ordering::Relaxed), 2);
    assert_eq!(
        stored.lock().unwrap().profile.display_name.as_deref(),
        Some("Alice"),
        "repeating the same full profile replacement must not compound state"
    );
}

#[tokio::test]
async fn profile_update_normalizes_only_writable_profile_fields() {
    let mut original = account();
    original.profile.phone_number = Some("+15550000001".to_owned());
    original.profile.phone_number_verified = true;
    let stored = Arc::new(Mutex::new(original.clone()));
    let service = AccountProfileService::new(
        StoredProfileRepository {
            account: stored.clone(),
            writes: Arc::new(AtomicUsize::new(0)),
        },
        FailFirstGrantSummary {
            calls: Arc::new(AtomicUsize::new(1)),
        },
        EmptyApplications,
    );

    let updated = service
        .update(
            &original.principal,
            ProfilePatch {
                display_name: Some("  Alice Example  ".to_owned()),
                given_name: Some(" Alice ".to_owned()),
                middle_name: Some("   ".to_owned()),
                profile_url: Some(" https://profile.example/alice ".to_owned()),
                phone_number: Some(" +15559999999 ".to_owned()),
                ..ProfilePatch::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.account.account.email, original.account.email);
    assert_eq!(updated.account.principal.role, original.principal.role);
    assert_eq!(
        updated.account.profile.display_name.as_deref(),
        Some("Alice Example")
    );
    assert_eq!(updated.account.profile.given_name.as_deref(), Some("Alice"));
    assert_eq!(updated.account.profile.middle_name, None);
    assert_eq!(
        updated.account.profile.profile_url.as_deref(),
        Some("https://profile.example/alice")
    );
    assert_eq!(
        updated.account.profile.phone_number.as_deref(),
        Some("+15559999999")
    );
    assert!(!updated.account.profile.phone_number_verified);
    assert_eq!(stored.lock().unwrap().profile, updated.account.profile);
}
