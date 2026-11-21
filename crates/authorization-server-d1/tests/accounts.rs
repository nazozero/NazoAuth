#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_identity::{
    AdminPolicyError, AdminUserUpdateOutcome, OrganizationId, RealmId, TenantContext, TenantId,
    UserId,
    ports::{
        AdminUserRepositoryPort, AdminUserUpdate, NewUser, PasswordHashInput,
        RegistrationAccountRepositoryPort, RepositoryError, SessionAccountPort,
    },
};
use nazo_oauth_server_d1::{D1Provider, Database};
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};
use support::{CLIENT, TENANT, USER};
use uuid::Uuid;

fn tenant() -> TenantContext {
    TenantContext {
        tenant_id: TenantId::new(TENANT).unwrap(),
        realm_id: RealmId::new(TENANT).unwrap(),
        organization_id: OrganizationId::new(TENANT).unwrap(),
    }
}
fn id(value: Uuid) -> UserId {
    UserId::new(value).unwrap()
}
fn input(name: &str) -> NewUser {
    NewUser {
        tenant: tenant(),
        username: name.into(),
        email: format!("{name}@example.com"),
        password_hash: PasswordHashInput::new("$argon2id$fixture").unwrap(),
        email_verified: true,
    }
}
fn update(role: Option<&str>, level: Option<i32>, active: Option<bool>) -> AdminUserUpdate {
    AdminUserUpdate {
        role: role.map(str::to_owned),
        admin_level: level,
        active,
    }
}
fn assert_sql(database: &Database, predicate: &str) {
    database.execute_sql(&format!("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1));INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;DROP TABLE assertion;")).unwrap();
}
async fn assert_statement(database: &Database, sql: &'static str, params: Vec<Value>) {
    database
        .execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1))")
        .unwrap();
    database.execute_statement(sql, params).await.unwrap();
    database.execute_sql("DROP TABLE assertion").unwrap();
}
async fn admin(database: &Database, provider: &D1Provider, name: &str, level: u32) -> UserId {
    let account = provider.create_user(input(name)).await.unwrap();
    database.execute_sql(&format!("UPDATE nazo_users SET principal=json_set(principal,'$.role',json('{{\"Admin\":{{\"level\":{level}}}}}')) WHERE id='{}'",account.id())).unwrap();
    account.user_id()
}
async fn family(database: &Database, user: UserId) {
    let user = user.as_uuid();
    let now = jiff::Timestamp::now().as_microsecond();
    let family = Uuid::new_v4();
    database.execute_statement("INSERT INTO nazo_refresh_families(tenant_id,id,client_id,user_id,contract,contract_hash,member,member_id,token_hash,created_at,expires_at) VALUES(?1,?2,?3,?4,'{}','contract','{}','member','token',?5,?6)",
        vec![json!(TENANT),json!(family),json!(CLIENT),json!(user),json!(now),json!(now+3_600_000_000)]).await.unwrap();
    database.execute_statement("INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision) VALUES(?1,?2,?3,'[]','[]','[]','grant')",
        vec![json!(TENANT),json!(user),json!(CLIENT)]).await.unwrap();
}

#[test]
fn registration_creation_preserves_context_and_handles_unique_identity_races() {
    let (database, provider) = block_on(support::fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    let tasks = (0..12)
        .map(|_| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.create_user(input("new")))
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| *error == RepositoryError::Conflict)
    );
    let account = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(account.principal.tenant, tenant());
    assert_eq!(account.principal.admin_level(), None);
    assert!(account.principal.active);
    assert!(account.account.email_verified);
    assert!(block_on(provider.email_exists(tenant().tenant_id, "NEW@example.com")).unwrap());
    let mut duplicate = input("other");
    duplicate.email = "NEW@example.com".into();
    assert_eq!(
        block_on(provider.create_user(duplicate)),
        Err(RepositoryError::Conflict)
    );
    assert_sql(&database, "(SELECT count(*) FROM nazo_users)=2");
}

#[test]
fn administrative_create_requires_current_exact_context_and_atomic_required_audit() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        assert!(
            provider
                .create_user_with_required_audit(input("denied"), id(USER), "source".into())
                .await
                .is_err()
        );
        let actor = admin(&database, &provider, "administrator", 3).await;
        let mut wrong = input("wrongcontext");
        wrong.tenant.organization_id = OrganizationId::new(Uuid::new_v4()).unwrap();
        assert!(
            provider
                .create_user_with_required_audit(wrong, actor, "source".into())
                .await
                .is_err()
        );
        database.execute_sql("CREATE TRIGGER fail_account_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='admin_user_created' BEGIN SELECT RAISE(ABORT,'required audit unavailable');END;").unwrap();
        assert!(
            provider
                .create_user_with_required_audit(input("rollback"), actor, "source".into())
                .await
                .is_err()
        );
        assert!(
            !provider
                .email_exists(tenant().tenant_id, "rollback@example.com")
                .await
                .unwrap()
        );
        database
            .execute_sql("DROP TRIGGER fail_account_audit")
            .unwrap();
        let account = provider
            .create_user_with_required_audit(input("created"), actor, "source".into())
            .await
            .unwrap();
        assert_eq!(account.principal.admin_level(), None);
        assert_statement(
            &database,
            "INSERT INTO assertion SELECT CASE WHEN (SELECT count(*) FROM nazo_audit WHERE event_type='admin_user_created' AND json_extract(payload,'$.admin_user_id')=?1 AND json_extract(payload,'$.user_id')=?2 AND json_extract(payload,'$.role')='user' AND json_extract(payload,'$.outcome')='success')=1 THEN 1 ELSE 0 END",
            vec![json!(actor.as_uuid()),json!(account.id())],
        ).await;
        database
            .execute_statement(
                "UPDATE nazo_users SET active=0,epoch=epoch+1 WHERE id=?1",
                vec![json!(actor.as_uuid())],
            )
            .await
            .unwrap();
        assert!(
            provider
                .create_user_with_required_audit(input("stale"), actor, "source".into())
                .await
                .is_err()
        );
    });
}

#[test]
fn administrative_create_rolls_back_when_required_audit_is_ignored() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let actor = admin(&database, &provider, "administrator", 3).await;
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_audit WHEN NEW.event_type='admin_user_created' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .create_user_with_required_audit(input("ignored"), actor, "source".into())
                .await
                .is_err()
        );
        assert!(
            !provider
                .email_exists(tenant().tenant_id, "ignored@example.com")
                .await
                .unwrap()
        );
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='admin_user_created')",
        );
    });
}

#[test]
fn administrator_deactivation_requires_refresh_and_grant_retirement() {
    block_on(async {
        for (table, operation) in [
            ("nazo_refresh_families", "UPDATE"),
            ("nazo_grants", "DELETE"),
        ] {
            let (database, provider) = support::fixture().await;
            let actor = admin(&database, &provider, "administrator", 3).await;
            family(&database, id(USER)).await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE {operation} ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .update_authorized_with_required_audit(
                        tenant(),
                        actor,
                        id(USER),
                        update(None, None, Some(false)),
                        "source".into()
                    )
                    .await
                    .is_err(),
                "{table}"
            );
            assert_sql(
                &database,
                &format!(
                    "EXISTS(SELECT 1 FROM nazo_users WHERE id='{USER}' AND active=1 AND epoch=0) AND EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL) AND EXISTS(SELECT 1 FROM nazo_grants) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='admin_user_updated')"
                ),
            );
        }
    });
}

#[test]
fn shared_hierarchy_policy_is_enforced_and_denials_are_durable() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let actor = admin(&database, &provider, "actor", 3).await;
        let peer = admin(&database, &provider, "peer", 3).await;
        for (target, change, reason) in [
            (
                actor,
                update(None, Some(4), None),
                AdminPolicyError::SelfElevation,
            ),
            (
                actor,
                update(None, None, Some(false)),
                AdminPolicyError::SelfDemotionOrDisable,
            ),
            (
                peer,
                update(None, None, Some(false)),
                AdminPolicyError::TargetAtOrAboveActor,
            ),
            (
                id(USER),
                update(Some("admin"), Some(3), None),
                AdminPolicyError::GrantAtOrAboveActor,
            ),
            (
                id(USER),
                update(Some("user"), Some(2), None),
                AdminPolicyError::InvalidRoleLevel,
            ),
        ] {
            assert_eq!(
                provider
                    .update_authorized_with_required_audit(
                        tenant(),
                        actor,
                        target,
                        change,
                        "source".into()
                    )
                    .await
                    .unwrap(),
                AdminUserUpdateOutcome::Denied(reason)
            );
        }
        let mut context = tenant();
        context.organization_id = OrganizationId::new(Uuid::new_v4()).unwrap();
        assert_eq!(
            provider
                .update_authorized_with_required_audit(
                    context,
                    actor,
                    id(USER),
                    update(None, None, Some(false)),
                    "source".into()
                )
                .await
                .unwrap(),
            AdminUserUpdateOutcome::Denied(AdminPolicyError::ActorNotAuthorized)
        );
        assert_eq!(
            provider
                .update_authorized_with_required_audit(
                    tenant(),
                    actor,
                    id(Uuid::new_v4()),
                    update(None, None, None),
                    "source".into()
                )
                .await
                .unwrap(),
            AdminUserUpdateOutcome::TargetNotFound
        );
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_audit WHERE event_type='admin_user_update_denied')=7",
        );
        let AdminUserUpdateOutcome::Updated(account) = provider
            .update_authorized_with_required_audit(
                tenant(),
                actor,
                id(USER),
                update(Some("admin"), Some(2), None),
                "source".into(),
            )
            .await
            .unwrap()
        else {
            panic!("authorized update denied")
        };
        assert_eq!(account.principal.admin_level(), Some(2));
        assert_eq!(account.principal.authorization_epoch, 0);
    });
}

#[test]
fn disabling_a_user_retires_authority_and_a_late_failure_rolls_back_all_effects() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let actor = admin(&database, &provider, "admin", 3).await;
        family(&database, id(USER)).await;
        database.execute_sql("CREATE TRIGGER fail_grant_delete BEFORE DELETE ON nazo_grants BEGIN SELECT RAISE(ABORT,'late delete failed');END;").unwrap();
        assert!(
            provider
                .update_authorized_with_required_audit(
                    tenant(),
                    actor,
                    id(USER),
                    update(None, None, Some(false)),
                    "source".into()
                )
                .await
                .is_err()
        );
        assert_sql(
            &database,
            &format!(
                "(SELECT active=1 AND epoch=0 FROM nazo_users WHERE id='{USER}') AND (SELECT count(*) FROM nazo_refresh_families WHERE revoked_at IS NULL)=1 AND (SELECT count(*) FROM nazo_grants)=1 AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE event_type='admin_user_updated')"
            ),
        );
        database
            .execute_sql("DROP TRIGGER fail_grant_delete")
            .unwrap();
        let AdminUserUpdateOutcome::Updated(account) = provider
            .update_authorized_with_required_audit(
                tenant(),
                actor,
                id(USER),
                update(None, None, Some(false)),
                "source".into(),
            )
            .await
            .unwrap()
        else {
            panic!("disable denied")
        };
        assert!(!account.principal.active);
        assert_eq!(account.principal.authorization_epoch, 1);
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_grants) AND NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL)",
        );
        let AdminUserUpdateOutcome::Updated(account) = provider
            .update_authorized_with_required_audit(
                tenant(),
                actor,
                id(USER),
                update(None, None, Some(true)),
                "source".into(),
            )
            .await
            .unwrap()
        else {
            panic!("reactivation denied")
        };
        assert!(account.principal.active);
        assert_eq!(account.principal.authorization_epoch, 1);
        assert_sql(
            &database,
            "NOT EXISTS(SELECT 1 FROM nazo_refresh_families WHERE revoked_at IS NULL)",
        );
    });
}

#[test]
fn concurrent_actor_demotion_cannot_authorize_a_later_target_change() {
    let (database, provider) = block_on(support::fixture());
    let actor = block_on(admin(&database, &provider, "actor", 3));
    let supervisor = block_on(admin(&database, &provider, "supervisor", 4));
    let barrier = Arc::new(Barrier::new(2));
    let other_barrier = barrier.clone();
    let other = provider.clone();
    let first = std::thread::spawn(move || {
        other_barrier.wait();
        block_on(other.update_authorized_with_required_audit(
            tenant(),
            actor,
            id(USER),
            update(Some("admin"), Some(2), None),
            "grant".into(),
        ))
        .unwrap()
    });
    barrier.wait();
    assert!(matches!(
        block_on(provider.update_authorized_with_required_audit(
            tenant(),
            supervisor,
            actor,
            update(Some("user"), Some(0), None),
            "demotion".into()
        ))
        .unwrap(),
        AdminUserUpdateOutcome::Updated(_)
    ));
    match first.join().unwrap() {
        AdminUserUpdateOutcome::Updated(_) => assert_sql(
            &database,
            "(SELECT sequence FROM nazo_audit WHERE json_extract(payload,'$.source_ip_hash')='grant')<(SELECT sequence FROM nazo_audit WHERE json_extract(payload,'$.source_ip_hash')='demotion')",
        ),
        AdminUserUpdateOutcome::Denied(reason) => {
            assert_eq!(reason, AdminPolicyError::ActorNotAuthorized)
        }
        other => panic!("unexpected race outcome: {other:?}"),
    }
    assert_eq!(
        block_on(provider.principal_by_id(tenant().tenant_id, actor))
            .unwrap()
            .unwrap()
            .admin_level(),
        None
    );
}

#[test]
fn tenant_admin_operation_binds_both_rows_and_audits_in_one_database_transaction() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let actor = admin(&database, &provider, "system", 2).await;
        let target_tenant = TenantId::new(Uuid::new_v4()).unwrap();
        let foreign = D1Provider::new(database.clone(), target_tenant);
        let mut new = input("foreign");
        new.tenant.tenant_id = target_tenant;
        let target = foreign.create_user(new).await.unwrap();
        let AdminUserUpdateOutcome::Updated(updated) = provider
            .set_tenant_admin_authorized(
                tenant().tenant_id,
                actor,
                target_tenant,
                target.user_id(),
                5,
                "system".into(),
            )
            .await
            .unwrap()
        else {
            panic!("system update denied")
        };
        assert_eq!(updated.principal.admin_level(), Some(5));
        assert_eq!(updated.principal.tenant.tenant_id, target_tenant);
        assert_eq!(
            provider
                .set_tenant_admin_authorized(
                    tenant().tenant_id,
                    actor,
                    tenant().tenant_id,
                    id(USER),
                    1,
                    "system".into()
                )
                .await
                .unwrap(),
            AdminUserUpdateOutcome::Denied(AdminPolicyError::InvalidRoleLevel)
        );
        database
            .execute_statement(
                "UPDATE nazo_users SET active=0 WHERE id=?1",
                vec![json!(actor.as_uuid())],
            )
            .await
            .unwrap();
        assert_eq!(
            provider
                .set_tenant_admin_authorized(
                    tenant().tenant_id,
                    actor,
                    target_tenant,
                    target.user_id(),
                    0,
                    "system".into()
                )
                .await
                .unwrap(),
            AdminUserUpdateOutcome::Denied(AdminPolicyError::ActorNotAuthorized)
        );
        assert_statement(
            &database,
            "INSERT INTO assertion SELECT CASE WHEN (SELECT count(*) FROM nazo_audit WHERE event_type='system_tenant_admin_updated' AND tenant_id=?1)=2 THEN 1 ELSE 0 END",
            vec![json!(target_tenant.as_uuid())],
        ).await;
    });
}

#[test]
fn admin_listing_is_ordered_tenant_bound_and_noop_still_requires_audit() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let actor = admin(&database, &provider, "admin", 3).await;
        let target = provider.create_user(input("last")).await.unwrap();
        let page = AdminUserRepositoryPort::page(&provider, tenant().tenant_id, 1, 0)
            .await
            .unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.users.len(), 1);
        assert_eq!(
            AdminUserRepositoryPort::page(&provider, tenant().tenant_id, 0, 0)
                .await
                .unwrap()
                .total,
            3
        );
        let AdminUserUpdateOutcome::Updated(noop) = provider
            .update_authorized_with_required_audit(
                tenant(),
                actor,
                target.user_id(),
                update(None, None, None),
                "noop".into(),
            )
            .await
            .unwrap()
        else {
            panic!("noop denied")
        };
        assert_eq!(*noop, target);
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_audit WHERE event_type='admin_user_updated')=1",
        );
        assert!(
            AdminUserRepositoryPort::page(&provider, TenantId::new(Uuid::new_v4()).unwrap(), 10, 0)
                .await
                .is_err()
        );
    });
}
