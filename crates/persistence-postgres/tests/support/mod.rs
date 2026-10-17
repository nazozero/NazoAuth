pub mod query_counter;

use diesel::{migration::CREATE_MIGRATIONS_TABLE, sql_query, sql_types::Text};
use diesel_async::{
    AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};

pub fn schema_database_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic")
}

pub async fn run_isolated_application_migrations(database_url: &str) {
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("isolated migration database should connect");
    connection
        .batch_execute(CREATE_MIGRATIONS_TABLE)
        .await
        .expect("isolated migration ledger should create");
    // Public audit owners run once per database, outside per-schema fixtures.
    for version in include_str!("../../../../tests/fixtures/public_migrations.txt").lines() {
        sql_query(
            "INSERT INTO __diesel_schema_migrations (version)
             VALUES ($1)
             ON CONFLICT (version) DO NOTHING",
        )
        .bind::<Text, _>(version)
        .execute(&mut connection)
        .await
        .expect("public-only migration should be excluded from the application schema fixture");
    }
    drop(connection);

    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("isolated application schema migrations should apply");
}
