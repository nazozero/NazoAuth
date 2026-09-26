use std::sync::{Arc, Mutex};

use chrono::Utc;
use nazo_identity::ports::{
    NewScimUser, PasswordHashInput, RepositoryError, RepositoryFuture, ScimCredentialPort,
    ScimListQuery, ScimRepositoryPort, UserPage,
};
use nazo_identity::scim::{NormalizedScimUser, ScimPatch, ScimService, ScimTokenCredential};
use nazo_identity::{
    AccountIdentity, Principal, PublicAccount, TenantContext, UserId, UserProfile, UserRole,
};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingScimRepository {
    list_query: Arc<Mutex<Option<ScimListQuery>>>,
}

impl ScimRepositoryPort for RecordingScimRepository {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(async move {
            *self.list_query.lock().expect("query recorder poisoned") = Some(query);
            Ok(UserPage {
                total: 0,
                users: Vec::new(),
            })
        })
    }

    fn get<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        unsupported()
    }

    fn create<'a>(&'a self, _new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        unsupported()
    }

    fn replace<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _replacement: NormalizedScimUser,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        unsupported()
    }

    fn patch<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _patch: ScimPatch,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        unsupported()
    }

    fn deactivate<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        unsupported()
    }
}

#[derive(Default)]
struct RecordingCredentials {
    credential: Option<ScimTokenCredential>,
}

impl ScimCredentialPort for RecordingCredentials {
    fn active_credential<'a>(
        &'a self,
        _token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<ScimTokenCredential>> {
        Box::pin(async move { Ok(self.credential.clone()) })
    }
}

fn unsupported<'a, T>() -> RepositoryFuture<'a, T> {
    Box::pin(async {
        Err(RepositoryError::Unexpected(
            "unused test operation".to_owned(),
        ))
    })
}

#[tokio::test]
async fn list_users_builds_a_tenant_scoped_repository_query() {
    let repository = RecordingScimRepository::default();
    let service = ScimService::new(
        Arc::new(repository.clone()),
        Arc::new(RecordingCredentials::default()),
    );
    let tenant = TenantContext::default_system();

    let page = service
        .list_users(tenant, Some("alice@example.test".to_owned()), None, 51, 7)
        .await
        .expect("recording repository should succeed");

    assert_eq!(page.total, 0);
    let query = repository
        .list_query
        .lock()
        .expect("query recorder poisoned")
        .clone()
        .expect("query should be recorded");
    assert_eq!(query.tenant_id, tenant.tenant_id);
    assert_eq!(query.email.as_deref(), Some("alice@example.test"));
    assert_eq!(query.after, None);
    assert_eq!(query.limit, 51);
    assert_eq!(query.offset, 7);
}

#[tokio::test]
async fn credential_lookup_is_delegated_to_the_credential_port() {
    let credential = ScimTokenCredential {
        id: Uuid::from_u128(11),
        tenant_id: Uuid::from_u128(12),
        scopes: vec!["scim:read".to_owned()],
        event_audience: None,
    };
    let credentials = Arc::new(RecordingCredentials {
        credential: Some(credential.clone()),
    });
    let service = ScimService::new(Arc::new(RecordingScimRepository::default()), credentials);

    assert_eq!(
        service
            .active_credential("hashed-token")
            .await
            .expect("credential lookup should succeed"),
        Some(credential.clone())
    );
}

struct CrudScimRepository {
    user: PublicAccount,
    operations: Mutex<Vec<&'static str>>,
}

impl ScimRepositoryPort for CrudScimRepository {
    fn list<'a>(&'a self, _query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        unsupported()
    }

    fn get<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operation recorder poisoned")
                .push("get");
            Ok(Some(self.user.clone()))
        })
    }

    fn create<'a>(&'a self, _new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operation recorder poisoned")
                .push("create");
            Ok(self.user.clone())
        })
    }

    fn replace<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _replacement: NormalizedScimUser,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operation recorder poisoned")
                .push("replace");
            Ok(self.user.clone())
        })
    }

    fn patch<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _patch: ScimPatch,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operation recorder poisoned")
                .push("patch");
            Ok(self.user.clone())
        })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.operations
                .lock()
                .expect("operation recorder poisoned")
                .push("deactivate");
            Ok(true)
        })
    }
}

fn public_account(tenant: TenantContext, user_id: UserId) -> PublicAccount {
    PublicAccount {
        principal: Principal {
            user_id,
            tenant,
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice@example.test".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: false,
        },
        profile: UserProfile::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn normalized_user() -> NormalizedScimUser {
    NormalizedScimUser {
        user_name: "alice@example.test".to_owned(),
        email: "alice@example.test".to_owned(),
        active: true,
        display_name: None,
        given_name: None,
        family_name: None,
    }
}

#[tokio::test]
async fn get_post_put_patch_and_delete_use_the_single_scim_repository_boundary() {
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa))
        .expect("fixture user ID is non-nil");
    let repository = Arc::new(CrudScimRepository {
        user: public_account(tenant, user_id),
        operations: Mutex::new(Vec::new()),
    });
    let service = ScimService::new(
        repository.clone(),
        Arc::new(RecordingCredentials::default()),
    );

    assert!(service.user(tenant, user_id).await.unwrap().is_some());
    service
        .create_user(
            tenant,
            normalized_user(),
            PasswordHashInput::new("opaque-password-verifier")
                .expect("fixture verifier is non-empty"),
        )
        .await
        .expect("POST core should delegate");
    service
        .replace_user(tenant, user_id, normalized_user())
        .await
        .expect("PUT core should delegate");
    service
        .patch_user(
            tenant,
            user_id,
            ScimPatch {
                active: Some(false),
                ..ScimPatch::default()
            },
        )
        .await
        .expect("PATCH core should delegate");
    assert!(
        service
            .deactivate_user(tenant, user_id)
            .await
            .expect("DELETE core should delegate")
    );

    assert_eq!(
        *repository
            .operations
            .lock()
            .expect("operation recorder poisoned"),
        ["get", "create", "replace", "patch", "deactivate"]
    );
}
