use super::*;
use crate::repositories::query_counter;
use diesel_async::AsyncConnection as _;

#[tokio::test]
async fn identity_event_checks_both_participants_and_inserts_in_one_query() {
    let Ok(url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI requires a test database"
        );
        return;
    };
    let mut conn = AsyncPgConnection::establish(&url).await.unwrap();
    conn.begin_test_transaction().await.unwrap();
    let tenant = nazo_identity::TenantContext::default_system();
    let actor = nazo_identity::UserId::new(Uuid::now_v7()).unwrap();
    let target = nazo_identity::UserId::new(Uuid::now_v7()).unwrap();
    for user in [actor, target] {
        diesel::sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
            .bind::<diesel::sql_types::Uuid,_>(user.as_uuid())
            .bind::<diesel::sql_types::Uuid,_>(tenant.tenant_id.as_uuid())
            .bind::<diesel::sql_types::Uuid,_>(tenant.realm_id.as_uuid())
            .bind::<diesel::sql_types::Uuid,_>(tenant.organization_id.as_uuid())
            .bind::<diesel::sql_types::Text,_>(format!("event-user-{}", user.as_uuid()))
            .bind::<diesel::sql_types::Text,_>(format!("event-user-{}@example.test", user.as_uuid()))
            .execute(&mut conn).await.unwrap();
    }
    let mut event = IdentitySecurityEvent {
        tenant_id: tenant.tenant_id,
        actor_id: Some(actor),
        target_user_id: Some(target),
        event_type: IdentitySecurityEventType::AdminUserUpdate,
        outcome: IdentitySecurityOutcome::Success,
        reason: IdentitySecurityReason::AdminUpdated,
        occurred_at: std::time::SystemTime::now(),
    };
    let counter = query_counter::QueryCounter::new();
    conn.set_instrumentation(counter.clone());
    for (actor_id, target_id, expected_queries) in [
        (Some(actor), Some(target), 1),
        (Some(actor), Some(actor), 1),
        (Some(actor), None, 1),
        (None, Some(target), 1),
        (None, None, 1),
    ] {
        event.actor_id = actor_id;
        event.target_user_id = target_id;
        let before = counter.snapshot();
        insert_identity_security_event(&mut conn, &event)
            .await
            .unwrap();
        assert_eq!(counter.since(before).data_queries, expected_queries);
    }
    event.actor_id = Some(actor);
    event.target_user_id = Some(nazo_identity::UserId::new(Uuid::now_v7()).unwrap());
    let before = counter.snapshot();
    let result = insert_identity_security_event(&mut conn, &event).await;
    assert!(
        matches!(result, Err(RepositoryError::Consistency(message)) if message == "identity security event target tenant mismatch")
    );
    assert_eq!(counter.since(before).data_queries, 1);
}

#[tokio::test]
async fn identity_event_rejects_a_real_cross_tenant_actor() {
    let Ok(url) =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"))
    else {
        return;
    };
    let pool = crate::create_pool(url, 1).unwrap();
    let mut conn = crate::get_conn(&pool).await.unwrap();
    let actor = uuid::Uuid::now_v7();
    let tenant = nazo_identity::TenantContext::default_system();
    diesel::sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<diesel::sql_types::Uuid,_>(actor)
        .bind::<diesel::sql_types::Uuid,_>(tenant.tenant_id.as_uuid())
        .bind::<diesel::sql_types::Uuid,_>(tenant.realm_id.as_uuid())
        .bind::<diesel::sql_types::Uuid,_>(tenant.organization_id.as_uuid())
        .bind::<diesel::sql_types::Text,_>(format!("event-actor-{actor}"))
        .bind::<diesel::sql_types::Text,_>(format!("event-actor-{actor}@example.test"))
        .execute(&mut conn).await.unwrap();
    let event = IdentitySecurityEvent {
        tenant_id: nazo_identity::TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        actor_id: Some(nazo_identity::UserId::new(actor).unwrap()),
        target_user_id: None,
        event_type: IdentitySecurityEventType::AdminUserUpdate,
        outcome: IdentitySecurityOutcome::Success,
        reason: IdentitySecurityReason::AdminUpdated,
        occurred_at: std::time::SystemTime::now(),
    };
    let result = insert_identity_security_event(&mut conn, &event).await;
    diesel::sql_query("DELETE FROM users WHERE id=$1")
        .bind::<diesel::sql_types::Uuid, _>(actor)
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        matches!(result, Err(RepositoryError::Consistency(message)) if message == "identity security event actor tenant mismatch")
    );
}
