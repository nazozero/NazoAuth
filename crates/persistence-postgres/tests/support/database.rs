use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};

/// Isolate the complete production schema, including public audit authorities.
pub async fn create(base: &str) -> String {
    let database = format!("nazo_test_{}", uuid::Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(base).await.unwrap();
    connection
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(base).unwrap();
    url.set_path(&database);
    url.to_string()
}

pub async fn migrate(base: &str) -> String {
    let url = create(base).await;
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    url
}

#[allow(dead_code)] // Some repository suites retain their fixtures until the test server exits.
pub async fn drop(url: &str) {
    let mut admin = url::Url::parse(url).unwrap();
    let database = admin.path().trim_start_matches('/').to_owned();
    assert!(database.starts_with("nazo_test_"));
    admin.set_path("postgres");
    let mut connection = AsyncPgConnection::establish(admin.as_str()).await.unwrap();
    connection
        .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .await
        .unwrap();
}
