use diesel::{QueryableByName, sql_query, sql_types::Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const SOCIAL_UP: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/up.sql");
const SOCIAL_DOWN: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/down.sql");
const RUNTIME_UP: &str =
    include_str!("../../../migrations/20260712000100_runtime_module_state/up.sql");
const RUNTIME_DOWN: &str =
    include_str!("../../../migrations/20260712000100_runtime_module_state/down.sql");

#[derive(QueryableByName)]
struct ProviderType {
    #[diesel(sql_type = Text)]
    provider_type: String,
}

#[derive(QueryableByName)]
struct RuntimeTable {
    #[diesel(sql_type = Text)]
    table_name: String,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[tokio::test]
async fn social_provider_type_migration_preserves_existing_rows_and_has_safe_down_policy() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("social_provider_type_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE external_identity_links (
                provider_type TEXT NOT NULL,
                CONSTRAINT ck_external_identity_links_provider_type
                    CHECK (provider_type IN ('oidc', 'saml'))
            );
            INSERT INTO external_identity_links (provider_type) VALUES ('oidc'), ('saml');
            "#
        ))
        .await
        .expect("baseline schema should create");

    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_UP).await
        })
        .await
        .expect("up migration should succeed");
    sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
        .execute(&mut connection)
        .await
        .expect("up migration should allow social links");
    let provider_types =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("provider rows should remain readable")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(provider_types, ["oauth2_social", "oidc", "saml"]);

    let down_with_social = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_DOWN).await
        })
        .await;
    assert!(
        down_with_social.is_err(),
        "down migration must fail rather than discard existing social links"
    );
    sql_query("DELETE FROM external_identity_links WHERE provider_type = 'oauth2_social'")
        .execute(&mut connection)
        .await
        .expect("operator cleanup policy should be representable");
    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_DOWN).await
        })
        .await
        .expect("down migration should succeed after social links are handled");
    assert!(
        sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
            .execute(&mut connection)
            .await
            .is_err(),
        "down migration must restore the baseline provider constraint"
    );
    let baseline =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("baseline provider rows should survive down migration")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(baseline, ["oidc", "saml"]);

    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[tokio::test]
async fn pending_migrations_create_all_runtime_module_state_tables() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let tables = sql_query(
        r#"
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name IN (
            'runtime_module_desired_states',
            'runtime_module_instance_states',
            'runtime_module_state_events'
          )
        ORDER BY table_name
        "#,
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("runtime table catalog should be readable")
    .into_iter()
    .map(|row| row.table_name)
    .collect::<Vec<_>>();
    assert_eq!(
        tables,
        [
            "runtime_module_desired_states",
            "runtime_module_instance_states",
            "runtime_module_state_events",
        ]
    );
}

#[tokio::test]
async fn runtime_module_state_migration_enforces_catalogs_and_round_trips() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("runtime_module_state_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE users (id UUID PRIMARY KEY);
            "#
        ))
        .await
        .expect("runtime migration baseline should create");
    connection
        .batch_execute(RUNTIME_UP)
        .await
        .expect("runtime up migration should succeed");

    for invalid in [
        "INSERT INTO runtime_module_desired_states (module_id, desired_mode, revision) VALUES ('ciba', 'automatic', 1)",
        "INSERT INTO runtime_module_instance_states (instance_id, module_id, actual_state, transition_revision) VALUES ('instance-1', 'ciba', 'running', 1)",
        "INSERT INTO runtime_module_state_events (event_id, module_id, event_type, revision) VALUES (gen_random_uuid(), 'ciba', 'unknown', 1)",
    ] {
        assert!(
            sql_query(invalid).execute(&mut connection).await.is_err(),
            "closed runtime state catalog should reject {invalid}"
        );
    }
    for event_type in [
        "desired_state_changed",
        "transition_started",
        "transition_completed",
        "transition_failed",
        "drain_started",
        "drain_completed",
        "stale_transition_discarded",
    ] {
        sql_query(format!(
            "INSERT INTO runtime_module_state_events (event_id, module_id, event_type, revision) VALUES (gen_random_uuid(), 'ciba', '{event_type}', 1)"
        ))
        .execute(&mut connection)
        .await
        .expect("closed runtime event kind should persist");
    }

    connection
        .batch_execute(RUNTIME_DOWN)
        .await
        .expect("runtime down migration should drop only runtime state");
    let users = sql_query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'users'",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("baseline table catalog should remain readable");
    assert_eq!(
        users.len(),
        1,
        "down migration must preserve baseline tables"
    );
    connection
        .batch_execute(RUNTIME_UP)
        .await
        .expect("runtime up migration should reapply after down");
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}
