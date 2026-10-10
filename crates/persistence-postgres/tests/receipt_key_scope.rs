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

#[tokio::test]
async fn populated_receipt_key_migration_preserves_facts_and_tenant_isolation() {
    use diesel::result::{DatabaseErrorKind, Error};
    use diesel_async::SimpleAsyncConnection;

    const UP: &str =
        include_str!("../../../migrations/20261010000600_compact_single_use_key/up.sql");
    const DOWN: &str =
        include_str!("../../../migrations/20261010000600_compact_single_use_key/down.sql");
    let Some(url) = database_url() else { return };
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let schema = format!("receipt_scope_{}", uuid::Uuid::now_v7().simple());
    connection.batch_execute(&format!("BEGIN; CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};
        CREATE TABLE tenants(id uuid PRIMARY KEY);
        CREATE TABLE oauth_clients(id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), UNIQUE(id,tenant_id));
        CREATE TABLE oauth_token_issuances(id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          tenant_id uuid NOT NULL REFERENCES tenants(id), client_id uuid NOT NULL,
          single_use_key_blake3 bytea, retain_until timestamptz NOT NULL,
          FOREIGN KEY(client_id,tenant_id) REFERENCES oauth_clients(id,tenant_id));
        CREATE UNIQUE INDEX oauth_token_issuances_single_use_key_idx
          ON oauth_token_issuances(tenant_id,client_id,single_use_key_blake3) WHERE single_use_key_blake3 IS NOT NULL;
        INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000002');
        INSERT INTO oauth_clients VALUES
          ('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000001'),
          ('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000001'),
          ('00000000-0000-0000-0000-000000000013','00000000-0000-0000-0000-000000000002');
        INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until)
          SELECT tenant_id,id,decode(repeat('01',32),'hex'),CURRENT_TIMESTAMP+INTERVAL '1 hour' FROM oauth_clients;
    ")).await.unwrap();

    #[derive(QueryableByName)]
    struct Facts {
        #[diesel(sql_type = diesel::sql_types::Text)]
        value: String,
    }
    async fn facts(connection: &mut AsyncPgConnection) -> String {
        sql_query(
            "SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text AS value FROM oauth_token_issuances t",
        )
        .get_result::<Facts>(connection)
        .await
        .unwrap()
        .value
    }
    let before = facts(&mut connection).await;
    connection.batch_execute(UP).await.unwrap();
    assert_eq!(facts(&mut connection).await, before);

    for (sql, expected) in [
        (
            "INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until) SELECT tenant_id,client_id,single_use_key_blake3,retain_until FROM oauth_token_issuances WHERE id=1",
            DatabaseErrorKind::UniqueViolation,
        ),
        (
            "INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until) SELECT '00000000-0000-0000-0000-000000000002',client_id,decode(repeat('02',32),'hex'),retain_until FROM oauth_token_issuances WHERE id=1",
            DatabaseErrorKind::ForeignKeyViolation,
        ),
        (
            "INSERT INTO oauth_clients VALUES ('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000002')",
            DatabaseErrorKind::UniqueViolation,
        ),
    ] {
        connection
            .batch_execute("SAVEPOINT rejected_write")
            .await
            .unwrap();
        let error = connection.batch_execute(sql).await.unwrap_err();
        assert!(matches!(error, Error::DatabaseError(kind, _) if kind == expected));
        connection
            .batch_execute("ROLLBACK TO SAVEPOINT rejected_write")
            .await
            .unwrap();
        assert_eq!(facts(&mut connection).await, before);
    }
    // Old application SQL must fail closed, never bypass the consumption fence.
    connection
        .batch_execute("SAVEPOINT old_writer")
        .await
        .unwrap();
    let error = connection.batch_execute("INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until) SELECT tenant_id,client_id,single_use_key_blake3,retain_until FROM oauth_token_issuances WHERE id=1 ON CONFLICT(tenant_id,client_id,single_use_key_blake3) WHERE single_use_key_blake3 IS NOT NULL DO NOTHING").await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("no unique or exclusion constraint")
    );
    connection
        .batch_execute("ROLLBACK TO SAVEPOINT old_writer")
        .await
        .unwrap();

    // Legacy receipts without a one-use key remain outside the partial index.
    connection.batch_execute("INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until) SELECT tenant_id,client_id,NULL,retain_until FROM oauth_token_issuances WHERE id=1;
        INSERT INTO oauth_token_issuances(tenant_id,client_id,single_use_key_blake3,retain_until) SELECT tenant_id,client_id,NULL,retain_until FROM oauth_token_issuances WHERE id=1;").await.unwrap();
    let populated = facts(&mut connection).await;
    connection.batch_execute(DOWN).await.unwrap();
    assert_eq!(facts(&mut connection).await, populated);
    connection.batch_execute(UP).await.unwrap();
    assert_eq!(facts(&mut connection).await, populated);
    connection.batch_execute("ROLLBACK").await.unwrap();
}
