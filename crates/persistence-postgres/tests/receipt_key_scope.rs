//! Real PostgreSQL proof that the one-use key need not repeat the client's tenant.
use diesel::{QueryableByName, sql_query, sql_types::BigInt};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

#[derive(QueryableByName)]
struct KeyWidth {
    #[diesel(sql_type = BigInt)]
    columns: i64,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    assert!(
        url.is_some() || std::env::var_os("CI").is_none(),
        "CI requires isolated PostgreSQL"
    );
    url
}

#[tokio::test]
async fn receipt_key_does_not_repeat_globally_identified_clients_tenant() {
    let Some(url) = database_url() else { return };
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let key = sql_query(
        "SELECT indnkeyatts::bigint AS columns FROM pg_index \
         WHERE indexrelid='oauth_token_issuances_single_use_key_idx'::regclass",
    )
    .get_result::<KeyWidth>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        key.columns, 2,
        "client_id already identifies exactly one tenant"
    );
}
