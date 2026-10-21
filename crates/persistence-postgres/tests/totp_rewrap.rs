#[path = "support/database.rs"]
mod database;

use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{TenantContext, UserId, mfa::totp_for_step};
use nazo_postgres::{MfaRepository, MfaTotpKey, MfaTotpKeyRing, create_pool, get_conn};
use uuid::Uuid;

fn repository(
    pool: nazo_postgres::DbPool,
    current: (&str, u8),
    previous: Option<(&str, u8)>,
) -> MfaRepository {
    MfaRepository::with_totp_key_ring(
        pool,
        Some(
            MfaTotpKeyRing::new(
                MfaTotpKey::new(current.0, [current.1; 32]).unwrap(),
                previous.map(|(id, byte)| MfaTotpKey::new(id, [byte; 32]).unwrap()),
            )
            .unwrap(),
        ),
    )
}
#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[tokio::test]
async fn totp_rotation_rewraps_bounded_batches_and_fences_retirement_and_old_writers() {
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
    let pool = create_pool(database.url.clone(), 4).unwrap();
    let tenant = TenantContext::default_system();
    let a = repository(pool.clone(), ("a", 1), None);
    let b = repository(pool.clone(), ("b", 2), Some(("a", 1)));
    let c = repository(pool.clone(), ("c", 3), Some(("b", 2)));
    a.activate_totp_key().await.unwrap();
    let mut users = Vec::new();
    let secret = "JBSWY3DPEHPK3PXP";
    let mut connection = get_conn(&pool).await.unwrap();
    for i in 0..260 {
        let user = UserId::new(Uuid::now_v7()).unwrap();
        sql_query("INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
            .bind::<SqlUuid,_>(user.as_uuid()).bind::<SqlUuid,_>(tenant.tenant_id.as_uuid())
            .bind::<SqlUuid,_>(tenant.realm_id.as_uuid()).bind::<SqlUuid,_>(tenant.organization_id.as_uuid())
            .bind::<Text,_>(format!("totp-{i}")).bind::<Text,_>(format!("totp-{i}@example.test"))
            .execute(&mut connection).await.unwrap();
        assert!(
            a.begin_totp_enrollment(tenant.tenant_id, user, secret)
                .await
                .unwrap()
        );
        users.push(user);
    }
    sql_query("UPDATE user_totp_credentials SET confirmed_at = NOW(), last_used_step = 123 WHERE user_id = $1")
        .bind::<SqlUuid,_>(users[0].as_uuid()).execute(&mut connection).await.unwrap();
    b.activate_totp_key().await.unwrap();
    assert!(
        c.activate_totp_key().await.is_err(),
        "A cannot retire while offline users still reference A"
    );
    assert!(
        a.activate_totp_key().await.is_err(),
        "a stale instance cannot reactivate A"
    );
    assert!(
        a.begin_totp_enrollment(tenant.tenant_id, users[1], secret)
            .await
            .is_err(),
        "database fence also rejects old writers"
    );
    assert_eq!(a.rewrap_totp_batch().await.unwrap(), 0);
    // Lock one enrollment as a concurrent verification/replacement would. The
    // bounded worker skips it and reports drain only for currently available rows.
    connection.begin_test_transaction().await.unwrap();
    sql_query("SELECT id FROM user_totp_credentials WHERE user_id = $1 FOR UPDATE")
        .bind::<SqlUuid, _>(users[0].as_uuid())
        .execute(&mut connection)
        .await
        .unwrap();
    assert_eq!(b.rewrap_totp_batch().await.unwrap(), 256);
    assert_eq!(b.rewrap_totp_batch().await.unwrap(), 3);
    assert_eq!(b.rewrap_totp_batch().await.unwrap(), 0);
    assert!(c.activate_totp_key().await.is_err());
    diesel_async::SimpleAsyncConnection::batch_execute(&mut *connection, "ROLLBACK")
        .await
        .unwrap();
    assert_eq!(b.rewrap_totp_batch().await.unwrap(), 1);
    assert_eq!(
        sql_query(
            "SELECT count(*)::bigint AS count FROM user_totp_credentials WHERE secret_key_id = 'a'"
        )
        .get_result::<Count>(&mut connection)
        .await
        .unwrap()
        .count,
        0
    );
    assert_eq!(sql_query("SELECT count(*)::bigint AS count FROM user_totp_credentials WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_used_step = 123")
        .bind::<SqlUuid,_>(users[0].as_uuid()).get_result::<Count>(&mut connection).await.unwrap().count, 1);
    let b_only = repository(pool.clone(), ("b", 2), None);
    b_only.activate_totp_key().await.unwrap();
    let code = totp_for_step(&nazo_identity::mfa::base32_decode(secret).unwrap(), 125).unwrap();
    assert_eq!(
        b_only
            .check_totp_enrollment(tenant.tenant_id, users[1], &code, 125 * 30)
            .await
            .unwrap(),
        nazo_identity::ports::TotpEnrollmentCheck::ValidCode
    );
    c.activate_totp_key().await.unwrap();
    assert_eq!(c.rewrap_totp_batch().await.unwrap(), 256);
    assert_eq!(c.rewrap_totp_batch().await.unwrap(), 4);
    let c_only = repository(pool.clone(), ("c", 3), None);
    c_only.activate_totp_key().await.unwrap();
    assert_eq!(
        c_only
            .check_totp_enrollment(tenant.tenant_id, users[1], &code, 125 * 30)
            .await
            .unwrap(),
        nazo_identity::ports::TotpEnrollmentCheck::ValidCode
    );
}
