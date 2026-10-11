//! The scope migration must preserve explicit global decisions for existing tenants.
use diesel::{QueryableByName, sql_query, sql_types::Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};

#[derive(QueryableByName)]
struct Mode {
    #[diesel(sql_type = Text)]
    desired_mode: String,
}

#[tokio::test]
async fn existing_tenants_inherit_global_module_decisions() {
    let url =
        std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").expect("isolated test database required");
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let schema = format!("module_scope_{}", uuid::Uuid::now_v7().simple());
    connection
        .batch_execute(&format!(
            "BEGIN; CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}, pg_catalog;"
        ))
        .await
        .unwrap();
    connection.batch_execute(r#"
        CREATE TABLE tenants (id UUID PRIMARY KEY);
        CREATE TABLE users (id UUID PRIMARY KEY);
        INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001'), ('00000000-0000-0000-0000-000000000002');
    "#).await.unwrap();
    connection
        .batch_execute(include_str!(
            "../../../migrations/20260712000100_runtime_module_state/up.sql"
        ))
        .await
        .unwrap();
    // Later migrations extend the module catalog before scoping; this fixture
    // deliberately leaves the enum list open and tests the actual scope SQL.
    connection.batch_execute(r#"
        ALTER TABLE runtime_module_desired_states DROP CONSTRAINT ck_runtime_module_desired_module_id;
        ALTER TABLE runtime_module_state_events DROP CONSTRAINT ck_runtime_module_event_module_id;
        INSERT INTO runtime_module_desired_states (module_id,desired_mode,revision,reason)
        VALUES ('dynamic_client_registration','disabled',4,'operator decision'), ('ciba','inherit',3,'operator decision');
    "#).await.unwrap();
    connection
        .batch_execute(include_str!(
            "../../../migrations/20260901000100_tenant_scoped_runtime_modules/up.sql"
        ))
        .await
        .unwrap();
    for (module, expected) in [
        ("dynamic_client_registration", "disabled"),
        ("ciba", "inherit"),
        ("native_sso", "enabled"),
    ] {
        let modes: Vec<Mode> = sql_query("SELECT desired_mode FROM runtime_module_desired_states WHERE module_id = $1 ORDER BY tenant_id")
            .bind::<Text,_>(module).load(&mut connection).await.unwrap();
        assert_eq!(modes.len(), 2);
        assert!(
            modes.iter().all(|mode| mode.desired_mode == expected),
            "{module}"
        );
    }
    connection.batch_execute("ROLLBACK").await.unwrap();
}
