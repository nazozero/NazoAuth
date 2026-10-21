use diesel::{sql_query, sql_types};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection as _,
};
use nazo_identity::TenantContext;
use nazo_postgres::{TenantDirectoryRepository, create_pool, get_conn};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI active-tenant tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_initialization_is_atomic_and_excludes_suspended_tenants() {
    let Some(database_url) = database_url() else {
        return;
    };
    let database_name = format!("tenancy_{}", Uuid::now_v7().simple());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    coordinator
        .batch_execute(&format!("CREATE DATABASE \"{database_name}\";"))
        .await
        .expect("isolated database should create");
    drop(coordinator);

    let mut isolated_url = url::Url::parse(&database_url).expect("test database URL is valid");
    isolated_url.set_path(&format!("/{database_name}"));
    let isolated_url = isolated_url.to_string();
    nazo_postgres::run_pending_migrations(&isolated_url)
        .await
        .expect("isolated database migrations should apply");
    let pool = create_pool(isolated_url, 4).expect("pool should create");
    let directory = TenantDirectoryRepository::new(pool.clone());
    let active = TenantContext::default_system();

    let fresh_directory = directory
        .load_active()
        .await
        .expect("fresh directory should load");
    assert_eq!(fresh_directory.revision, 0);
    assert!(fresh_directory.tenants.is_empty());

    let initial_binding = nazo_identity::TenantDirectoryBinding {
        tenant: active,
        runtime_revision: 1,
        issuer: "https://auth.example".to_owned(),
        external_host: "auth.example".to_owned(),
    };
    let first_directory = directory.clone();
    let second_directory = directory.clone();
    let (first, second) = tokio::join!(
        first_directory.initialize(initial_binding.clone()),
        second_directory.initialize(initial_binding)
    );
    let mut outcomes = [
        first.expect("first concurrent initialization should succeed"),
        second.expect("second concurrent initialization should succeed"),
    ];
    outcomes.sort_unstable();
    assert_eq!(outcomes, [false, true]);
    let conflicting = nazo_identity::TenantDirectoryBinding {
        tenant: active,
        runtime_revision: 1,
        issuer: "https://other.example".to_owned(),
        external_host: "other.example".to_owned(),
    };
    assert!(matches!(
        directory.initialize(conflicting).await,
        Err(nazo_identity::ports::RepositoryError::Consistency(_))
    ));
    let initial_directory = directory
        .load_active()
        .await
        .expect("active directory should load");
    assert_eq!(initial_directory.revision, 1);
    assert_eq!(initial_directory.tenants.len(), 1);
    assert_eq!(initial_directory.tenants[0].tenant, active);
    assert_eq!(
        directory
            .current_revision()
            .await
            .expect("directory revision should load"),
        initial_directory.revision
    );

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
    sql_query("UPDATE tenant_runtime_bindings SET runtime_revision = runtime_revision + 1 WHERE tenant_id = $1")
        .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
        .execute(&mut connection).await.unwrap();
    assert!(
        !directory
            .initialize(nazo_identity::TenantDirectoryBinding {
                tenant: active,
                runtime_revision: 1,
                issuer: "https://auth.example".into(),
                external_host: "auth.example".into(),
            })
            .await
            .expect("bootstrap must preserve the live runtime revision")
    );
    assert_eq!(
        directory.load_active().await.unwrap().tenants[0].runtime_revision,
        2
    );
    sql_query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
        .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .expect("tenant status should update");
    drop(connection);
    let suspended_directory = directory
        .load_active()
        .await
        .expect("suspended directory should load");
    assert_eq!(suspended_directory.revision, 3);
    assert!(suspended_directory.tenants.is_empty());

    let mut connection = get_conn(&pool)
        .await
        .expect("pool should provide connection");
    sql_query("UPDATE tenants SET status = 'active' WHERE id = $1")
        .bind::<sql_types::Uuid, _>(active.tenant_id.as_uuid())
        .execute(&mut connection)
        .await
        .expect("tenant status should restore");
    let restored_directory = directory
        .load_active()
        .await
        .expect("restored directory should load");
    assert_eq!(restored_directory.revision, 4);
    assert_eq!(restored_directory.tenants.len(), 1);

    drop(connection);
    drop(directory);
    drop(pool);
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("database should accept cleanup connection");
    coordinator
        .batch_execute(&format!("DROP DATABASE \"{database_name}\" WITH (FORCE);"))
        .await
        .expect("isolated database should be removed");
}
