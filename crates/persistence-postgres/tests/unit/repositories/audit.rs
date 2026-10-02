use super::*;

#[tokio::test]
async fn identity_event_rejects_a_real_cross_tenant_actor() {
    let Ok(url) = std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) else { return; };
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
    diesel::sql_query("DELETE FROM users WHERE id=$1").bind::<diesel::sql_types::Uuid,_>(actor).execute(&mut conn).await.unwrap();
    assert!(matches!(result, Err(RepositoryError::Consistency(message)) if message == "identity security event actor tenant mismatch"));
}
