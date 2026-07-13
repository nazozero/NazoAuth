use std::sync::{Arc, Mutex};

use nazo_identity::ports::{
    NewScimUser, RepositoryError, RepositoryFuture, ScimListQuery, ScimRepositoryPort, UserPage,
};
use nazo_identity::scim::{NormalizedScimUser, ScimPatch, ScimService};
use nazo_identity::{PublicAccount, TenantContext, UserId};

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
    ) -> RepositoryFuture<'a, PublicAccount> {
        unsupported()
    }

    fn patch<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _patch: ScimPatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        unsupported()
    }

    fn deactivate<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, bool> {
        unsupported()
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
    let service = ScimService::new(repository.clone());
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
