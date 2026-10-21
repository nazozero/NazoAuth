#[path = "support/database.rs"]
mod database;
use diesel::{
    sql_query,
    sql_types::{Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{TenantContext, UserId};
use nazo_postgres::{UserRepository, create_pool, get_conn};
use uuid::Uuid;

#[tokio::test]
async fn avatar_revision_fences_aba_and_recovers_same_candidate_commit() {
    let base =
        match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
            Ok(base) => base,
            Err(_) if std::env::var_os("CI").is_none() => return,
            Err(error) => panic!("real PostgreSQL required: {error}"),
        };
    let database = database::OwnedDatabase::new(&base).await;
    nazo_postgres::run_pending_migrations(&database.url)
        .await
        .unwrap();
    let pool = create_pool(database.url.clone(), 2).unwrap();
    let tenant = TenantContext::default_system();
    let user = UserId::new(Uuid::now_v7()).unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,'avatar','avatar@example.test','test')")
        .bind::<SqlUuid,_>(user.as_uuid()).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid())
        .bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
        .execute(&mut connection).await.unwrap();
    let repository = UserRepository::new(pool);
    let a = repository
        .compare_and_set_avatar(tenant.tenant_id, user, None, 0, Some("a".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.profile.avatar_revision, 1);
    // A second upload worker or lost-ACK retry must not report a miss and delete A.
    let replay = repository
        .compare_and_set_avatar(tenant.tenant_id, user, None, 0, Some("a".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay.profile.avatar_revision, 1);
    assert_eq!(replay.profile.avatar_url.as_deref(), Some("a"));
    let empty = repository
        .compare_and_set_avatar(tenant.tenant_id, user, Some("a"), 1, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(empty.profile.avatar_revision, 2);
    assert!(
        repository
            .compare_and_set_avatar(tenant.tenant_id, user, None, 0, Some("a".into()))
            .await
            .unwrap()
            .is_none()
    );
    let b = repository
        .compare_and_set_avatar(tenant.tenant_id, user, None, 2, Some("b".into()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.profile.avatar_revision, 3);
    assert!(
        repository
            .compare_and_set_avatar(tenant.tenant_id, user, Some("a"), 1, None)
            .await
            .unwrap()
            .is_none()
    );
    // Non-avatar profile writes preserve the fence; another avatar writer advances it.
    sql_query("UPDATE users SET display_name = 'updated' WHERE id = $1")
        .bind::<SqlUuid, _>(user.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        repository
            .public_account_by_id(tenant.tenant_id, user)
            .await
            .unwrap()
            .unwrap()
            .profile
            .avatar_revision,
        3
    );
    sql_query("UPDATE users SET avatar_url = $1 WHERE id = $2")
        .bind::<Text, _>("external")
        .bind::<SqlUuid, _>(user.as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        repository
            .public_account_by_id(tenant.tenant_id, user)
            .await
            .unwrap()
            .unwrap()
            .profile
            .avatar_revision,
        4
    );
}
