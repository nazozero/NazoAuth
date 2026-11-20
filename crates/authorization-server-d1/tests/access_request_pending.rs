#![cfg(feature = "local-sqlite")]
mod support;

use futures_executor::block_on;
use nazo_identity::{
    AccessRequestStatus, NewAccessRequest, TenantId, UserId,
    ports::{AccessRequestRepositoryPort, RepositoryError},
};
use nazo_oauth_server_d1::{D1Provider, Database};
use std::sync::{Arc, Barrier};
use support::{TENANT, USER};
use uuid::Uuid;

const MIGRATION: &str = include_str!("../migrations/0013_access_request_pending.sql");

fn request(tenant: Uuid, user: Uuid, name: &str) -> NewAccessRequest {
    NewAccessRequest {
        tenant_id: TenantId::new(tenant).unwrap(),
        user_id: UserId::new(user).unwrap(),
        site_name: name.into(),
        site_url: "https://client.example/callback".into(),
        request_description: "Pending request contract".into(),
    }
}

fn assert_sql(database: &Database, predicate: &str) {
    database
        .execute_sql(&format!(
            "CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1));
         INSERT INTO assertion SELECT CASE WHEN ({predicate}) THEN 1 ELSE 0 END;
         DROP TABLE assertion;",
        ))
        .unwrap();
}

#[test]
fn concurrent_pending_requests_have_one_winner_and_conflicts() {
    let (_database, provider) = block_on(support::fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(8));
    let tasks = (0..8)
        .map(|index| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.create(request(TENANT, USER, &format!("Applicant {index}"))))
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(RepositoryError::Conflict)))
            .count(),
        7
    );
    let items = block_on(
        provider.list_for_user(TenantId::new(TENANT).unwrap(), UserId::new(USER).unwrap()),
    )
    .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].status, AccessRequestStatus::Pending);
    assert_eq!(
        items[0],
        *results.into_iter().find_map(Result::ok).as_ref().unwrap()
    );
}

#[test]
fn pending_conflict_is_scoped_to_tenant_user_and_released_by_a_decision() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        let first = provider
            .create(request(TENANT, USER, "First"))
            .await
            .unwrap();
        assert!(matches!(
            provider
                .create(request(TENANT, USER, "Different site"))
                .await,
            Err(RepositoryError::Conflict)
        ));
        let other_tenant = Uuid::new_v4();
        database.execute_sql(&format!(
            "INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at)
             SELECT '{other_tenant}',id,email,json_set(principal,'$.tenant.tenant_id','{other_tenant}'),claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at
             FROM nazo_users WHERE tenant_id='{TENANT}' AND id='{USER}';"
        )).unwrap();
        let scoped = D1Provider::new(database.clone(), TenantId::new(other_tenant).unwrap());
        let foreign = scoped
            .create(request(other_tenant, USER, "Independent tenant"))
            .await
            .unwrap();
        assert_eq!(foreign.tenant_id.as_uuid(), other_tenant);
        assert!(
            provider
                .create(request(other_tenant, USER, "Wrong context"))
                .await
                .is_err()
        );
        assert!(matches!(
            provider
                .create(request(TENANT, Uuid::new_v4(), "Missing account"))
                .await,
            Err(RepositoryError::NotFound)
        ));
        database.execute_sql(&format!(
            "UPDATE nazo_access_requests SET status=2,admin_note='Resolved fixture',resolved_at=created_at WHERE tenant_id='{TENANT}' AND id='{}'",first.id,
        )).unwrap();
        let next = provider
            .create(request(TENANT, USER, "Next request"))
            .await
            .unwrap();
        assert_ne!(next.id, first.id);
        assert_eq!(
            provider
                .list_for_user(TenantId::new(TENANT).unwrap(), UserId::new(USER).unwrap())
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            scoped
                .list_for_user(
                    TenantId::new(other_tenant).unwrap(),
                    UserId::new(USER).unwrap()
                )
                .await
                .unwrap(),
            vec![foreign]
        );
    });
}

#[test]
fn database_constraint_rejects_bypasses_and_migration_keeps_historical_duplicates() {
    block_on(async {
        let (database, provider) = support::fixture().await;
        provider
            .create(request(TENANT, USER, "Original"))
            .await
            .unwrap();
        database.execute_sql(MIGRATION).unwrap();
        let duplicate = format!(
            "INSERT INTO nazo_access_requests(tenant_id,id,user_id,site_name,site_url,request_description,status,created_at)
             SELECT tenant_id,'{}',user_id,'Historical duplicate',site_url,request_description,status,created_at FROM nazo_access_requests LIMIT 1",Uuid::new_v4(),
        );
        assert!(database.execute_sql(&duplicate).is_err());
        database
            .execute_sql("DROP INDEX nazo_access_requests_tenant_user_pending")
            .unwrap();
        database.execute_sql(&duplicate).unwrap();
        assert!(database.execute_sql(MIGRATION).is_err());
        assert_sql(
            &database,
            "(SELECT count(*) FROM nazo_access_requests WHERE status=0)=2 AND NOT EXISTS(SELECT 1 FROM nazo_audit) AND NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='nazo_access_requests_tenant_user_pending')",
        );
        assert!(matches!(
            provider
                .create(request(TENANT, USER, "Further duplicate"))
                .await,
            Err(RepositoryError::Conflict)
        ));
        assert_sql(&database, "(SELECT count(*) FROM nazo_access_requests)=2");
    });
}

#[test]
fn ignored_or_changed_insert_never_becomes_a_success_or_pending_conflict() {
    block_on(async {
        for trigger in [
            "CREATE TRIGGER suppress BEFORE INSERT ON nazo_access_requests BEGIN SELECT RAISE(IGNORE);END;",
            "CREATE TRIGGER suppress AFTER INSERT ON nazo_access_requests BEGIN UPDATE nazo_access_requests SET site_name='Changed' WHERE tenant_id=NEW.tenant_id AND id=NEW.id;END;",
        ] {
            let (database, provider) = support::fixture().await;
            database.execute_sql(trigger).unwrap();
            assert!(matches!(
                provider
                    .create(request(TENANT, USER, "Exact request"))
                    .await,
                Err(RepositoryError::Unavailable)
            ));
            assert_sql(&database, "NOT EXISTS(SELECT 1 FROM nazo_access_requests)");
        }
    });
}
