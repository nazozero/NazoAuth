use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use nazo_identity::{TenantContext, ports::PasswordHashInput};
use nazo_postgres::{
    AdminProvisionError, AdminProvisionRepository, AdminProvisionRequest, create_pool,
};

mod support;

#[derive(QueryableByName)]
struct UserState {
    #[diesel(sql_type = diesel::sql_types::Text)]
    role: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    admin_level: i32,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    email_verified: bool,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI admin-provision tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn request(operation_id: &str, email: &str) -> AdminProvisionRequest {
    AdminProvisionRequest {
        tenant: TenantContext::default_system(),
        operation_id: operation_id.to_owned(),
        deployment_id: "deployment-test".to_owned(),
        email: email.to_owned(),
        password_hash: PasswordHashInput::new("provisioned-password-hash").unwrap(),
    }
}

async fn isolated_repository() -> Option<(AdminProvisionRepository, String)> {
    let database_url = database_url()?;
    let isolated_url = support::database::migrate(&database_url).await;
    Some((
        AdminProvisionRepository::new(
            create_pool(isolated_url.clone(), 4).expect("pool should create"),
        ),
        isolated_url,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provisioning_is_atomic_and_retries_return_the_same_receipt() {
    let Some((repository, isolated_url)) = isolated_repository().await else {
        return;
    };
    let first = repository
        .provision(request("admin-provision-1", "Admin@Example.COM"))
        .await
        .unwrap();
    let retry = repository
        .provision(request("admin-provision-1", "admin@example.com"))
        .await
        .unwrap();
    assert_eq!(first, retry);

    let mut connection = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    let user = sql_query(
        "SELECT role, admin_level, email_verified
         FROM users WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(first.user_id)
    .get_result::<UserState>(&mut connection)
    .await
    .unwrap();
    assert_eq!(user.role, "admin");
    assert_eq!(user.admin_level, 2);
    assert!(user.email_verified);
    for (table, predicate) in [
        (
            "admin_provision_receipts",
            "operation_id = 'admin-provision-1'",
        ),
        (
            "identity_security_events",
            "request_id = 'admin-provision-1' AND event_type = 'admin_user_created'",
        ),
    ] {
        let row = sql_query(format!(
            "SELECT count(*)::bigint AS count FROM {table} WHERE {predicate}"
        ))
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(row.count, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operation_and_email_conflicts_are_rejected() {
    let Some((repository, _isolated_url)) = isolated_repository().await else {
        return;
    };
    repository
        .provision(request("admin-provision-2", "one@example.com"))
        .await
        .unwrap();
    assert_eq!(
        repository
            .provision(request("admin-provision-2", "two@example.com"))
            .await
            .unwrap_err(),
        AdminProvisionError::OperationConflict
    );
    assert_eq!(
        repository
            .provision(request("admin-provision-3", "ONE@example.com"))
            .await
            .unwrap_err(),
        AdminProvisionError::EmailConflict
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_provisioning_returns_one_receipt_and_one_admin_effect() {
    let Some((repository, isolated_url)) = isolated_repository().await else {
        return;
    };
    let (left, right) = tokio::join!(
        repository.provision(request("admin-provision-concurrent", "Admin@Example.COM")),
        repository.provision(request("admin-provision-concurrent", "admin@example.com"))
    );
    let receipt = left.unwrap();
    assert_eq!(right.unwrap(), receipt);
    let mut connection = AsyncPgConnection::establish(&isolated_url).await.unwrap();
    let user = sql_query("SELECT role, admin_level, email_verified FROM users WHERE id = $1")
        .bind::<diesel::sql_types::Uuid, _>(receipt.user_id)
        .get_result::<UserState>(&mut connection)
        .await
        .unwrap();
    assert_eq!(user.role, "admin");
    assert_eq!(user.admin_level, 2);
    assert!(user.email_verified);
    for (table, predicate) in [
        ("users", "email = 'admin@example.com'"),
        (
            "admin_provision_receipts",
            "operation_id = 'admin-provision-concurrent'",
        ),
        (
            "identity_security_events",
            "request_id = 'admin-provision-concurrent' AND event_type = 'admin_user_created'",
        ),
    ] {
        let count = sql_query(format!(
            "SELECT count(*)::bigint AS count FROM {table} WHERE {predicate}"
        ))
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(count.count, 1, "{table} must contain one committed effect");
    }
}

#[tokio::test]
async fn provisioning_uses_unique_email_constraint_without_a_preflight_read() {
    let Some((_, isolated_url)) = isolated_repository().await else {
        return;
    };
    let pool = create_pool(isolated_url, 1).unwrap();
    let counter = support::query_counter::QueryCounter::new();
    {
        let mut connection = nazo_postgres::get_conn(&pool).await.unwrap();
        connection.set_instrumentation(counter.clone());
    }
    let repository = AdminProvisionRepository::new(pool);
    let before = counter.snapshot();
    let first = repository
        .provision(request("counted", "counted@example.test"))
        .await
        .unwrap();
    let delta = counter.since(before);
    // Operation lock, receipt lookup, user insert, receipt insert, event insert.
    assert_eq!(delta.data_queries, 5);
    assert_eq!(delta.begins, 1);
    assert_eq!(delta.commits, 1);
    assert_eq!(delta.failed_queries, 0);
    let before = counter.snapshot();
    let retry = repository
        .provision(request("counted", "COUNTED@example.test"))
        .await
        .unwrap();
    assert_eq!(retry, first);
    assert_eq!(counter.since(before).data_queries, 3);
    let before = counter.snapshot();
    assert_eq!(
        repository
            .provision(request("other-operation", "counted@example.test"))
            .await
            .unwrap_err(),
        AdminProvisionError::EmailConflict
    );
    let delta = counter.since(before);
    assert_eq!(delta.data_queries + delta.failed_queries, 3);
    assert_eq!(delta.rollbacks, 1);
    assert_eq!(delta.failed_queries, 1);
}
