//! Canonical Required evidence shares the real grant/family mutation owner.

use super::*;
use futures_util::FutureExt as _;

#[derive(QueryableByName)]
struct GrantSnapshot {
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    value: serde_json::Value,
}

async fn snapshot(connection: &mut AsyncPgConnection, fixture: &FixtureIds) -> serde_json::Value {
    sql_query("SELECT jsonb_build_object('grants', COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY g.client_id) FROM user_client_grants g WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3),'[]'::jsonb), 'families', COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY f.token_family_id) FROM oauth_refresh_families f WHERE tenant_id=$1 AND user_id=$2 AND client_id=$3),'[]'::jsonb), 'ledger', COALESCE((SELECT jsonb_agg(payload ORDER BY event_id) FROM security_audit_events WHERE event_type='admin_grant_revoked' AND payload->>'tenant_id'=$1::text AND payload->>'user_id'=$2::text AND payload->>'client_id'=$4),'[]'::jsonb)) AS value")
        .bind::<SqlUuid, _>(Uuid::from_u128(1))
        .bind::<SqlUuid, _>(fixture.user_id)
        .bind::<SqlUuid, _>(fixture.client_id)
        .bind::<Text, _>(&fixture.client_public_id)
        .get_result::<GrantSnapshot>(connection)
        .await
        .unwrap()
        .value
}

pub(super) async fn seed_current_admin(database_url: &str) -> Uuid {
    let actor = Uuid::now_v7();
    let suffix = actor.simple().to_string();
    let mut connection = AsyncPgConnection::establish(database_url).await.unwrap();
    sql_query("INSERT INTO users (id,username,email,password_hash,role,admin_level) VALUES ($1,$2,$3,'fixture-current-admin','admin',1)")
        .bind::<SqlUuid,_>(actor).bind::<Text,_>(format!("grant-admin-{suffix}"))
        .bind::<Text,_>(format!("grant-admin-{suffix}@example.test"))
        .execute(&mut connection).await.unwrap();
    actor
}

async fn seed_grant_and_family(database_url: &str) -> (FixtureIds, GrantRepository) {
    let fixture = fixture(database_url).await;
    let repository = GrantRepository::new(create_pool(database_url, 1).unwrap());
    repository
        .upsert(
            Uuid::from_u128(1),
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .unwrap();
    let mut connection = AsyncPgConnection::establish(database_url).await.unwrap();
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());
    insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            Uuid::from_u128(1),
            Uuid::now_v7(),
            &format!("required-grant-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    (fixture, repository)
}

#[tokio::test]
async fn required_ledger_failure_rolls_back_exact_grant_and_refresh_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let (fixture, repository) = seed_grant_and_family(&database_url).await;
    let actor = seed_current_admin(&database_url).await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let before = snapshot(&mut connection, &fixture).await;
    let name = format!("grant_required_failure_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture required ledger failure'; END $$; CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.event_type='admin_grant_revoked' AND NEW.payload->>'user_id'='{}' AND NEW.payload->>'client_id'='{}') EXECUTE FUNCTION {name}();",
        fixture.user_id, fixture.client_public_id,
    )).await.unwrap();
    let body = std::panic::AssertUnwindSafe(async {
        let result = repository
            .revoke_by_client_id(
                Uuid::from_u128(1),
                fixture.user_id,
                &fixture.client_public_id,
                actor,
            )
            .await;
        assert!(matches!(
            result,
            Err(nazo_auth::AdminGrantRevokeError::Revoke(_))
        ));
        assert_eq!(
            snapshot(&mut connection, &fixture).await,
            before,
            "Required append failure preserves the entire grant, family and ledger snapshot"
        );
    })
    .catch_unwind()
    .await;
    connection
        .batch_execute(&format!(
            "DROP TRIGGER {name} ON security_audit_events; DROP FUNCTION {name}();",
        ))
        .await
        .expect("fixture-owned ledger fault removed");
    if let Err(error) = body {
        std::panic::resume_unwind(error);
    }

    let revoked = repository
        .revoke_by_client_id(
            Uuid::from_u128(1),
            fixture.user_id,
            &fixture.client_public_id,
            actor,
        )
        .await
        .unwrap();
    assert_eq!(revoked.removed_grants, 1);
    assert_eq!(revoked.revoked_refresh_tokens, 1);
    let after = snapshot(&mut connection, &fixture).await;
    assert_eq!(after["grants"], json!([]));
    assert!(!after["families"][0]["revoked_at"].is_null());
    let ledger = after["ledger"].as_array().unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0]["admin_user_id"], actor.to_string());
    assert_eq!(ledger[0]["user_id"], fixture.user_id.to_string());
    assert_eq!(ledger[0]["tenant_id"], Uuid::from_u128(1).to_string());
    assert_eq!(ledger[0]["client_id"], fixture.client_public_id);
    assert_eq!(ledger[0]["removed_grants"], 1);
    assert_eq!(ledger[0]["revoked_refresh_tokens"], 1);
    assert_eq!(
        ledger[0]["schema_version"],
        nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(ledger[0]["event_category"], "administration");
}

#[tokio::test]
async fn grant_owner_rejects_missing_inactive_or_demoted_current_actor_without_effect_or_outcome() {
    let Some(url) = database_url() else {
        return;
    };
    let (fixture, repository) = seed_grant_and_family(&url).await;
    let actor = seed_current_admin(&url).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let before = snapshot(&mut connection, &fixture).await;
    for (active, role, level) in [(false, "admin", 1), (true, "user", 0), (true, "admin", 0)] {
        sql_query("UPDATE users SET is_active=$2,role=$3,admin_level=$4 WHERE id=$1")
            .bind::<SqlUuid, _>(actor)
            .bind::<diesel::sql_types::Bool, _>(active)
            .bind::<Text, _>(role)
            .bind::<diesel::sql_types::Integer, _>(level)
            .execute(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            repository
                .revoke_by_client_id(
                    Uuid::from_u128(1),
                    fixture.user_id,
                    &fixture.client_public_id,
                    actor
                )
                .await,
            Err(nazo_auth::AdminGrantRevokeError::Revoke(
                nazo_auth::AuthorizationPortError::Unavailable
            ))
        );
        assert_eq!(snapshot(&mut connection, &fixture).await, before);
    }
    assert_eq!(
        repository
            .revoke_by_client_id(
                Uuid::from_u128(1),
                fixture.user_id,
                &fixture.client_public_id,
                Uuid::now_v7()
            )
            .await,
        Err(nazo_auth::AdminGrantRevokeError::Revoke(
            nazo_auth::AuthorizationPortError::Unavailable
        ))
    );
    assert_eq!(snapshot(&mut connection, &fixture).await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_owner_rechecks_current_actor_after_real_demotion_lock_wait() {
    let Some(url) = database_url() else {
        return;
    };
    let (fixture, _) = seed_grant_and_family(&url).await;
    let actor = seed_current_admin(&url).await;
    let application = format!("grant-current-{}", Uuid::now_v7().simple());
    let repository =
        GrantRepository::new(create_pool(tagged_database_url(&url, &application), 1).unwrap());
    let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
    let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
    let before = snapshot(&mut observer, &fixture).await;
    coordinator.batch_execute("BEGIN").await.unwrap();
    sql_query("UPDATE users SET role='user',admin_level=0 WHERE id=$1")
        .bind::<SqlUuid, _>(actor)
        .execute(&mut coordinator)
        .await
        .unwrap();
    let user = fixture.user_id;
    let client = fixture.client_public_id.clone();
    let mut task = tokio::spawn(async move {
        repository
            .revoke_by_client_id(Uuid::from_u128(1), user, &client, actor)
            .await
    });
    let result = std::panic::AssertUnwindSafe(async {
        wait_for_lock_wait(&mut observer, &application).await;
        assert!(!task.is_finished());
        coordinator.batch_execute("COMMIT").await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .unwrap()
                .unwrap(),
            Err(nazo_auth::AdminGrantRevokeError::Revoke(
                nazo_auth::AuthorizationPortError::Unavailable
            ))
        );
        assert_eq!(snapshot(&mut observer, &fixture).await, before);
    })
    .catch_unwind()
    .await;
    if !task.is_finished() {
        task.abort();
        let _ = task.await;
    }
    coordinator.batch_execute("ROLLBACK").await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

// The port caller has already admitted the actor to this target scope. This
// fixture proves the current-role gate does not invent home/target equality;
// it does not prove or grant cross-tenant HTTP admission policy.
#[tokio::test]
async fn grant_current_role_gate_preserves_separate_admitted_actor_home_tenant() {
    let Some(url) = database_url() else {
        return;
    };
    let (fixture, repository) = seed_grant_and_family(&url).await;
    let actor = Uuid::now_v7();
    let home = Uuid::now_v7();
    let realm = Uuid::now_v7();
    let organization = Uuid::now_v7();
    let suffix = actor.simple().to_string();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    sql_query("WITH t AS (INSERT INTO tenants(id,slug,display_name) VALUES($1,$5,'admitted actor home') RETURNING id), r AS (INSERT INTO realms(id,tenant_id,slug,display_name) SELECT $2,t.id,$5,'admitted actor realm' FROM t RETURNING id,tenant_id), o AS (INSERT INTO organizations(id,tenant_id,realm_id,slug,display_name) SELECT $3,r.tenant_id,r.id,$5,'admitted actor organization' FROM r RETURNING id,tenant_id,realm_id) INSERT INTO users(id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level) SELECT $4,o.tenant_id,o.realm_id,o.id,$5,$5||'@example.test','fixture','admin',2 FROM o")
        .bind::<SqlUuid,_>(home).bind::<SqlUuid,_>(realm).bind::<SqlUuid,_>(organization).bind::<SqlUuid,_>(actor)
        .bind::<Text,_>(format!("grant-admitted-{suffix}")).execute(&mut connection).await.unwrap();
    let revoked = repository
        .revoke_by_client_id(
            Uuid::from_u128(1),
            fixture.user_id,
            &fixture.client_public_id,
            actor,
        )
        .await
        .unwrap();
    assert_eq!(revoked.removed_grants, 1);
    assert_eq!(revoked.revoked_refresh_tokens, 1);
    let after = snapshot(&mut connection, &fixture).await;
    assert_eq!(after["ledger"].as_array().unwrap().len(), 1);
    assert_eq!(after["ledger"][0]["admin_user_id"], actor.to_string());
    assert_eq!(after["ledger"][0]["actor_tenant_id"], home.to_string());
    assert_eq!(
        after["ledger"][0]["tenant_id"],
        Uuid::from_u128(1).to_string()
    );
}
