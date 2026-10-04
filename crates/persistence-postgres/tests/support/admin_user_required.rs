//! Required user lifecycle evidence shares the actual creation/hierarchy owner.
use super::*;
use diesel_async::SimpleAsyncConnection;
use futures_util::FutureExt as _;
use nazo_identity::ports::{
    AdminUserRepositoryPort, NewUser, PasswordHashInput, RegistrationAccountRepositoryPort,
    RepositoryFuture, UserPage,
};
use std::sync::{Arc, Mutex};

fn new_user() -> NewUser {
    let id = Uuid::now_v7();
    let hash = nazo_crypto::password::hash_argon2id(b"fixture-only password", 64, 1, 1).unwrap();
    NewUser {
        tenant: TenantContext::default_system(),
        username: id.to_string(),
        email: format!("{id}@example.test"),
        password_hash: PasswordHashInput::new(hash).unwrap(),
        email_verified: true,
    }
}

async fn setup() -> Option<(nazo_postgres::DbPool, UserRepository, UserId)> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let url = match url {
        Ok(url) => url,
        Err(_) => {
            assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
            return None;
        }
    };
    let pool = create_pool(url, 4).unwrap();
    let repo = UserRepository::new(pool.clone());
    let actor = repo.create(new_user()).await.unwrap().user_id();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role='admin',admin_level=10 WHERE id=$1")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    Some((pool, repo, actor))
}

#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}
async fn snapshot(pool: &nazo_postgres::DbPool, email: &str, actor: UserId) -> serde_json::Value {
    let mut connection = get_conn(pool).await.unwrap();
    sql_query("SELECT jsonb_build_object('rows',(SELECT count(*) FROM users WHERE email=$1),'fingerprint',(SELECT md5(to_jsonb(u)::text) FROM users u WHERE email=$1),'canonical',COALESCE((SELECT jsonb_agg(payload ORDER BY event_id) FROM security_audit_events WHERE event_type IN ('admin_user_created','admin_user_updated') AND payload->>'admin_user_id'=$2::text),'[]'::jsonb),'identity',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM identity_security_events e WHERE actor_id=$2),'[]'::jsonb)) AS value")
        .bind::<Text,_>(email).bind::<SqlUuid,_>(actor.as_uuid())
        .get_result::<Snapshot>(&mut connection).await.unwrap().value
}

async fn fault(pool: &nazo_postgres::DbPool, actor: UserId) -> String {
    let name = format!("admin_user_required_{}", Uuid::now_v7().simple());
    get_conn(pool).await.unwrap().batch_execute(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture canonical append failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type IN ('admin_user_created','admin_user_updated') AND NEW.payload->>'admin_user_id'='{}') EXECUTE FUNCTION {name}();",actor.as_uuid(),
    )).await.unwrap();
    name
}
async fn unfault(pool: &nazo_postgres::DbPool, name: &str) {
    get_conn(pool)
        .await
        .unwrap()
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();"
        ))
        .await
        .expect("remove only fixture-owned fault");
}
fn patch() -> AdminUserUpdate {
    AdminUserUpdate {
        role: Some("admin".to_owned()),
        admin_level: Some(1),
        active: Some(false),
    }
}
fn noop() -> AdminUserUpdate {
    AdminUserUpdate {
        role: None,
        admin_level: None,
        active: None,
    }
}

#[tokio::test]
async fn admin_user_required_ledger_failure_rolls_back_create_patch_and_noop_outcome() {
    let Some((pool, repo, actor)) = setup().await else {
        return;
    };
    let proposed = new_user();
    let before = snapshot(&pool, &proposed.email, actor).await;
    let name = fault(&pool, actor).await;
    let caught = std::panic::AssertUnwindSafe(async {
        assert!(
            repo.create_user_with_required_audit(
                proposed.clone(),
                actor,
                "fixture-source".to_owned()
            )
            .await
            .is_err()
        );
        assert_eq!(snapshot(&pool, &proposed.email, actor).await, before);
    })
    .catch_unwind()
    .await;
    unfault(&pool, &name).await;
    if let Err(error) = caught {
        std::panic::resume_unwind(error);
    }
    let target = repo
        .create_user_with_required_audit(proposed.clone(), actor, "fixture-source".to_owned())
        .await
        .unwrap();
    let before = snapshot(&pool, &proposed.email, actor).await;
    assert_eq!(before["canonical"].as_array().unwrap().len(), 1);
    let name = fault(&pool, actor).await;
    let caught = std::panic::AssertUnwindSafe(async {
        assert!(
            repo.update_authorized_with_required_audit(
                target.tenant(),
                actor,
                target.user_id(),
                patch(),
                "fixture-source".to_owned()
            )
            .await
            .is_err()
        );
        assert_eq!(
            snapshot(&pool, &proposed.email, actor).await,
            before,
            "canonical failure also rolls back tenant-local identity event and entire account"
        );
    })
    .catch_unwind()
    .await;
    unfault(&pool, &name).await;
    if let Err(error) = caught {
        std::panic::resume_unwind(error);
    }
    let AdminUserUpdateOutcome::Updated(written) = repo
        .update_authorized_with_required_audit(
            target.tenant(),
            actor,
            target.user_id(),
            patch(),
            "fixture-source".to_owned(),
        )
        .await
        .unwrap()
    else {
        panic!("valid lower-rank update accepted");
    };
    assert!(!written.principal.active);
    assert_eq!(written.principal.admin_level(), Some(1));
    let before = snapshot(&pool, &proposed.email, actor).await;
    assert_eq!(before["canonical"].as_array().unwrap().len(), 2);
    let name = fault(&pool, actor).await;
    let caught = std::panic::AssertUnwindSafe(async {
        assert!(
            repo.update_authorized_with_required_audit(
                target.tenant(),
                actor,
                target.user_id(),
                noop(),
                "fixture-source".to_owned()
            )
            .await
            .is_err()
        );
        assert_eq!(
            snapshot(&pool, &proposed.email, actor).await,
            before,
            "no-op still requires same-owner canonical ACK"
        );
    })
    .catch_unwind()
    .await;
    unfault(&pool, &name).await;
    if let Err(error) = caught {
        std::panic::resume_unwind(error);
    }
    assert!(matches!(
        repo.update_authorized_with_required_audit(
            target.tenant(),
            actor,
            target.user_id(),
            noop(),
            "fixture-source".to_owned()
        )
        .await
        .unwrap(),
        AdminUserUpdateOutcome::Updated(_)
    ));
    let after = snapshot(&pool, &proposed.email, actor).await;
    assert_eq!(after["canonical"].as_array().unwrap().len(), 3);
    assert_eq!(
        after["fingerprint"], before["fingerprint"],
        "no-op keeps exact account and updated_at"
    );
}

#[tokio::test]
async fn admin_user_required_current_actor_context_and_hierarchy_denials_commit_no_success() {
    let Some((pool, repo, actor)) = setup().await else {
        return;
    };
    let proposed = new_user();
    let target = repo.create(new_user()).await.unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    for state in ["inactive", "demoted"] {
        let sql = if state == "inactive" {
            "UPDATE users SET is_active=false WHERE id=$1"
        } else {
            "UPDATE users SET is_active=true,role='user',admin_level=0 WHERE id=$1"
        };
        sql_query(sql)
            .bind::<SqlUuid, _>(actor.as_uuid())
            .execute(&mut connection)
            .await
            .unwrap();
        let before = snapshot(&pool, &target.account.email, actor).await;
        assert!(
            repo.create_user_with_required_audit(
                proposed.clone(),
                actor,
                "fixture-source".to_owned()
            )
            .await
            .is_err()
        );
        assert!(matches!(
            repo.update_authorized_with_required_audit(
                target.tenant(),
                actor,
                target.user_id(),
                patch(),
                "fixture-source".to_owned()
            )
            .await
            .unwrap(),
            AdminUserUpdateOutcome::Denied(AdminPolicyError::ActorNotAuthorized)
        ));
        let after = snapshot(&pool, &target.account.email, actor).await;
        assert_eq!(before["fingerprint"], after["fingerprint"]);
        assert_eq!(before["canonical"], after["canonical"]);
        assert_eq!(
            snapshot(&pool, &proposed.email, actor).await["rows"],
            serde_json::json!(0)
        );
    }
    sql_query("UPDATE users SET is_active=true,role='admin',admin_level=10 WHERE id=$1 OR id=$2")
        .bind::<SqlUuid, _>(actor.as_uuid())
        .bind::<SqlUuid, _>(target.id())
        .execute(&mut connection)
        .await
        .unwrap();
    let before = snapshot(&pool, &target.account.email, actor).await;
    assert!(matches!(
        repo.update_authorized_with_required_audit(
            target.tenant(),
            actor,
            target.user_id(),
            patch(),
            "fixture-source".to_owned()
        )
        .await
        .unwrap(),
        AdminUserUpdateOutcome::Denied(AdminPolicyError::TargetAtOrAboveActor)
    ));
    let after = snapshot(&pool, &target.account.email, actor).await;
    assert_eq!(before["fingerprint"], after["fingerprint"]);
    assert_eq!(before["canonical"], after["canonical"]);
    let realm = Uuid::now_v7();
    sql_query("INSERT INTO realms (id,tenant_id,slug,display_name) VALUES ($1,$2,$1::text,'Required user context')")
        .bind::<SqlUuid,_>(realm).bind::<SqlUuid,_>(target.tenant().tenant_id.as_uuid()).execute(&mut connection).await.unwrap();
    sql_query("UPDATE users SET realm_id=$2,role='user',admin_level=0 WHERE id=$1")
        .bind::<SqlUuid, _>(target.id())
        .bind::<SqlUuid, _>(realm)
        .execute(&mut connection)
        .await
        .unwrap();
    let before = snapshot(&pool, &target.account.email, actor).await;
    assert!(matches!(
        repo.update_authorized_with_required_audit(
            target.tenant(),
            actor,
            target.user_id(),
            patch(),
            "fixture-source".to_owned()
        )
        .await
        .unwrap(),
        AdminUserUpdateOutcome::Denied(AdminPolicyError::CrossTenant)
    ));
    let after = snapshot(&pool, &target.account.email, actor).await;
    assert_eq!(before["fingerprint"], after["fingerprint"]);
    assert_eq!(before["canonical"], after["canonical"]);
}

struct HiddenAck {
    inner: UserRepository,
    committed: Arc<Mutex<Vec<Uuid>>>,
}
impl RegistrationAccountRepositoryPort for HiddenAck {
    fn account_by_email<'a>(
        &'a self,
        tenant: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move { self.inner.public_account_by_email(tenant, email).await })
    }
    fn create_user(&self, user: NewUser) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move { self.inner.create(user).await })
    }
    fn create_user_with_required_audit(
        &self,
        user: NewUser,
        actor: UserId,
        source: String,
    ) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move {
            let written = self
                .inner
                .create_with_required_audit(user, actor, source)
                .await?;
            self.committed.lock().unwrap().push(written.id());
            Err(RepositoryError::Unavailable)
        })
    }
}
impl AdminUserRepositoryPort for HiddenAck {
    fn page(&self, tenant: TenantId, limit: i64, offset: i64) -> RepositoryFuture<'_, UserPage> {
        Box::pin(async move { self.inner.page(tenant, limit, offset).await })
    }
    fn update_authorized(
        &self,
        tenant: TenantId,
        actor: UserId,
        target: UserId,
        update: AdminUserUpdate,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(async move {
            self.inner
                .admin_update_authorized(tenant, actor, target, update)
                .await
        })
    }
    fn update_authorized_with_required_audit(
        &self,
        tenant: TenantContext,
        actor: UserId,
        target: UserId,
        update: AdminUserUpdate,
        source: String,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(async move {
            let outcome = self
                .inner
                .admin_update_with_required_audit(tenant, actor, target, update, source)
                .await?;
            if let AdminUserUpdateOutcome::Updated(written) = outcome {
                self.committed.lock().unwrap().push(written.id());
                Err(RepositoryError::Unavailable)
            } else {
                Ok(outcome)
            }
        })
    }
}
#[tokio::test]
async fn admin_user_required_hidden_committed_ack_returns_no_account_receipt() {
    let Some((pool, repo, actor)) = setup().await else {
        return;
    };
    let committed = Arc::new(Mutex::new(Vec::new()));
    let hidden = HiddenAck {
        inner: repo.clone(),
        committed: committed.clone(),
    };
    let proposed = new_user();
    assert!(matches!(
        hidden
            .create_user_with_required_audit(proposed.clone(), actor, "fixture-source".to_owned())
            .await,
        Err(RepositoryError::Unavailable)
    ));
    let target = repo
        .public_account_by_email(proposed.tenant.tenant_id, &proposed.email)
        .await
        .unwrap()
        .unwrap();
    let before = snapshot(&pool, &proposed.email, actor).await;
    assert_eq!(before["canonical"].as_array().unwrap().len(), 1);
    assert!(matches!(
        hidden
            .update_authorized_with_required_audit(
                target.tenant(),
                actor,
                target.user_id(),
                patch(),
                "fixture-source".to_owned()
            )
            .await,
        Err(RepositoryError::Unavailable)
    ));
    let after = snapshot(&pool, &proposed.email, actor).await;
    assert_eq!(after["canonical"].as_array().unwrap().len(), 2);
    assert_ne!(before["fingerprint"], after["fingerprint"]);
    assert_eq!(*committed.lock().unwrap(), vec![target.id(), target.id()]);
}

struct Unsupported;
impl RegistrationAccountRepositoryPort for Unsupported {
    fn account_by_email<'a>(
        &'a self,
        _tenant: TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async { Ok(None) })
    }
    fn create_user(&self, _user: NewUser) -> RepositoryFuture<'_, PublicAccount> {
        panic!("Required creation must not fall back to bare mutation")
    }
}
impl AdminUserRepositoryPort for Unsupported {
    fn page(&self, _tenant: TenantId, _limit: i64, _offset: i64) -> RepositoryFuture<'_, UserPage> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn update_authorized(
        &self,
        _tenant: TenantId,
        _actor: UserId,
        _target: UserId,
        _update: AdminUserUpdate,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        panic!("Required patch must not fall back to bare mutation")
    }
}
#[tokio::test]
async fn admin_user_required_ports_have_no_bare_mutation_fallback() {
    let repo = Unsupported;
    let tenant = TenantContext::default_system();
    let actor = UserId::new(Uuid::now_v7()).unwrap();
    assert!(matches!(
        repo.create_user_with_required_audit(new_user(), actor, "fixture-source".to_owned())
            .await,
        Err(RepositoryError::Unavailable)
    ));
    assert!(matches!(
        repo.update_authorized_with_required_audit(
            tenant,
            actor,
            UserId::new(Uuid::now_v7()).unwrap(),
            noop(),
            "fixture-source".to_owned()
        )
        .await,
        Err(RepositoryError::Unavailable)
    ));
}
