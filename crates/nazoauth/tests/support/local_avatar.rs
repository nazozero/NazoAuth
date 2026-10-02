use std::{path::PathBuf, sync::{Arc, Mutex}};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::{
    AccountIdentity, AvatarObject, AvatarContentType, Principal, PublicAccount,
    TenantContext, TenantId, UserId, UserProfile, UserRole,
    ports::{AvatarRepositoryPort, GrantSummaryRepositoryPort, RepositoryError, RepositoryFuture},
};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::adapters::avatar_files::LocalAvatarStorage;

pub(crate) struct LocalFixture {
    pub(crate) root: PathBuf,
    pub(crate) storage: LocalAvatarStorage,
    pub(crate) account: PublicAccount,
}

impl LocalFixture {
    pub(crate) fn new() -> Self {
        let root = std::env::temp_dir().join(format!("nazo-avatar-versions-{}", Uuid::now_v7()));
        let now = chrono::Utc::now();
        Self {
            storage: LocalAvatarStorage::new(root.clone()),
            root,
            account: PublicAccount {
                principal: Principal {
                    user_id: UserId::new(Uuid::now_v7()).unwrap(),
                    tenant: TenantContext::default_system(),
                    role: UserRole::User,
                    active: true,
                },
                account: AccountIdentity {
                    username: "avatar".to_owned(),
                    email: "avatar@example.test".to_owned(),
                    email_verified: true,
                    mfa_enabled: false,
                },
                profile: UserProfile::default(),
                created_at: now,
                updated_at: now,
            },
        }
    }
}

impl Drop for LocalFixture {
    fn drop(&mut self) {
        // The fixture owns this unique temporary root.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn png() -> Vec<u8> {
    STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==").unwrap()
}

pub(crate) fn object(version: &str) -> AvatarObject {
    AvatarObject {
        bytes: png(),
        content_type: AvatarContentType::Png,
        version: version.to_owned(),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CasOutcome {
    Success,
    Miss,
    ErrorBeforeCommit,
    ErrorAfterCommit,
    PauseBeforeCommit,
    PauseAfterCommit,
}

#[derive(Clone)]
pub(crate) struct CasRepository {
    pub(crate) account: Arc<Mutex<PublicAccount>>,
    pub(crate) entered: Arc<Notify>,
    outcome: CasOutcome,
}

impl CasRepository {
    pub(crate) fn new(account: PublicAccount, outcome: CasOutcome) -> Self {
        Self {
            account: Arc::new(Mutex::new(account)),
            entered: Arc::new(Notify::new()),
            outcome,
        }
    }
}

impl AvatarRepositoryPort for CasRepository {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            match self.outcome {
                CasOutcome::Miss => return Ok(None),
                CasOutcome::ErrorBeforeCommit => return Err(RepositoryError::Unavailable),
                CasOutcome::PauseBeforeCommit => {
                    self.entered.notify_one();
                    return std::future::pending().await;
                }
                _ => {}
            }
            let updated = {
                let mut account = self.account.lock().unwrap();
                assert_eq!(tenant_id, account.tenant().tenant_id);
                assert_eq!(user_id, account.user_id());
                if account.profile.avatar_url.as_deref() != expected_avatar_url {
                    return Ok(None);
                }
                account.profile.avatar_url = avatar_url;
                account.clone()
            };
            match self.outcome {
                CasOutcome::ErrorAfterCommit => Err(RepositoryError::Unavailable),
                CasOutcome::PauseAfterCommit => {
                    self.entered.notify_one();
                    std::future::pending().await
                }
                _ => Ok(Some(updated)),
            }
        })
    }
}

pub(crate) struct NoGrants;

impl GrantSummaryRepositoryPort for NoGrants {
    fn authorized_client_count(&self, _tenant_id: TenantId, _user_id: Uuid) -> RepositoryFuture<'_, i64> {
        Box::pin(async { Ok(0) })
    }
}

/// Wrap the real PostgreSQL adapter in HTTP regressions: the durable CAS
/// completes normally before the caller receives an injected unknown outcome.
pub(crate) struct CommitThenError<R>(pub(crate) R);

impl<R: AvatarRepositoryPort> AvatarRepositoryPort for CommitThenError<R> {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            match self.0.compare_and_set_avatar(tenant_id, user_id, expected_avatar_url, avatar_url).await? {
                Some(_) => Err(RepositoryError::Unavailable),
                None => Ok(None),
            }
        })
    }
}
