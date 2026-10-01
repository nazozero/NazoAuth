//! Inert-state migration regressions. Fixtures are transaction-local schemas;
//! no deployed database or controller recovery state is modified.
use diesel::{QueryableByName, sql_query, sql_types::{Bool, Text}};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const UP: &str = include_str!("../../../migrations/20261001000300_remove_inert_schema_state/up.sql");
const DOWN: &str = include_str!("../../../migrations/20261001000300_remove_inert_schema_state/down.sql");

#[derive(QueryableByName)]
struct Flag {
    #[diesel(sql_type = Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct Snapshot {
    #[diesel(sql_type = Text)]
    value: String,
}

async fn fixture() -> Option<AsyncPgConnection> {
    let url = match std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL")) {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => panic!("CI schema cleanup tests require a test database"),
        Err(_) => return None,
    };
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let schema = format!("inert_cleanup_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "BEGIN; CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema};"
    )).await.unwrap();
    connection.batch_execute(r#"
        CREATE TABLE tenants (id UUID PRIMARY KEY);
        CREATE TABLE realms (
            id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
            CONSTRAINT uq_realms_id_tenant UNIQUE (id, tenant_id)
        );
        CREATE TABLE organizations (
            id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
            CONSTRAINT uq_organizations_id_tenant UNIQUE (id, tenant_id)
        );
        CREATE TABLE users (
            id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
            realm_id UUID NOT NULL, organization_id UUID NOT NULL,
            CONSTRAINT fk_users_realm FOREIGN KEY (realm_id) REFERENCES realms(id),
            CONSTRAINT fk_users_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id),
            CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
            CONSTRAINT fk_users_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id)
        );
        CREATE TABLE oauth_clients (
            id UUID PRIMARY KEY, tenant_id UUID NOT NULL REFERENCES tenants(id),
            realm_id UUID NOT NULL, organization_id UUID NOT NULL,
            backchannel_user_code_parameter BOOLEAN NOT NULL DEFAULT FALSE,
            CONSTRAINT ck_oauth_clients_ciba_user_code_disabled CHECK (backchannel_user_code_parameter = FALSE),
            CONSTRAINT fk_oauth_clients_realm FOREIGN KEY (realm_id) REFERENCES realms(id),
            CONSTRAINT fk_oauth_clients_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id),
            CONSTRAINT fk_oauth_clients_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
            CONSTRAINT fk_oauth_clients_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id)
        );
        CREATE TABLE controller_registry_slots (id INTEGER PRIMARY KEY, last_used_at TIMESTAMPTZ, marker TEXT NOT NULL);
        CREATE TABLE user_mfa_remembered_devices (id INTEGER PRIMARY KEY, last_used_at TIMESTAMPTZ, marker TEXT NOT NULL);
        CREATE TABLE openid4vci_credential_configurations (
            id VARCHAR(255) NOT NULL,
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            configuration JSONB NOT NULL, enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT ck_openid4vci_configuration_id CHECK (char_length(btrim(id)) BETWEEN 1 AND 255),
            CONSTRAINT ck_openid4vci_configuration_object CHECK (jsonb_typeof(configuration) = 'object' AND configuration <> '{}'::jsonb),
            PRIMARY KEY (tenant_id, id)
        );
        INSERT INTO tenants VALUES
            ('00000000-0000-0000-0000-000000000001'), ('00000000-0000-0000-0000-000000000002');
        INSERT INTO realms VALUES
            ('00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000001'),
            ('00000000-0000-0000-0000-000000000012', '00000000-0000-0000-0000-000000000002');
        INSERT INTO organizations VALUES
            ('00000000-0000-0000-0000-000000000021', '00000000-0000-0000-0000-000000000001'),
            ('00000000-0000-0000-0000-000000000022', '00000000-0000-0000-0000-000000000002');
        INSERT INTO users VALUES
            ('00000000-0000-0000-0000-000000000031', '00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000021');
        INSERT INTO oauth_clients (id, tenant_id, realm_id, organization_id) VALUES
            ('00000000-0000-0000-0000-000000000041', '00000000-0000-0000-0000-000000000001',
             '00000000-0000-0000-0000-000000000011', '00000000-0000-0000-0000-000000000021');
        INSERT INTO controller_registry_slots VALUES (1, NULL, 'slot identity survives');
        INSERT INTO user_mfa_remembered_devices VALUES (1, NULL, 'remembered credential survives');
    "#).await.unwrap();
    Some(connection)
}

async fn snapshot(connection: &mut AsyncPgConnection) -> String {
    sql_query(r#"SELECT jsonb_build_object(
        'users', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM users t),
        'clients', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM oauth_clients t),
        'slots', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM controller_registry_slots t),
        'devices', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM user_mfa_remembered_devices t),
        'configurations', (SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM openid4vci_credential_configurations t)
    )::text AS value"#).get_result::<Snapshot>(connection).await.unwrap().value
}

async fn assert_old_columns_exist(connection: &mut AsyncPgConnection) {
    let flag = sql_query(r#"SELECT count(*) = 3 AS value
        FROM pg_attribute
        WHERE NOT attisdropped AND (
            (attrelid = 'oauth_clients'::regclass AND attname = 'backchannel_user_code_parameter') OR
            (attrelid = 'controller_registry_slots'::regclass AND attname = 'last_used_at') OR
            (attrelid = 'user_mfa_remembered_devices'::regclass AND attname = 'last_used_at'))"#)
        .get_result::<Flag>(connection).await.unwrap();
    assert!(flag.value, "a rejected migration must leave all old columns intact");
}

#[tokio::test]
async fn constant_and_empty_state_cleanup_round_trips_without_losing_rows() {
    let Some(mut connection) = fixture().await else { return };
    let before = snapshot(&mut connection).await;
    connection.batch_execute(UP).await.unwrap();
    let state = sql_query(r#"SELECT
        to_regclass('openid4vci_credential_configurations') IS NULL
        AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE NOT attisdropped AND (
            (attrelid = 'oauth_clients'::regclass AND attname = 'backchannel_user_code_parameter') OR
            (attrelid = 'controller_registry_slots'::regclass AND attname = 'last_used_at') OR
            (attrelid = 'user_mfa_remembered_devices'::regclass AND attname = 'last_used_at')))
        AND (SELECT count(*) FROM pg_constraint AS c
             WHERE conrelid IN ('users'::regclass, 'oauth_clients'::regclass)
               AND conname IN ('fk_users_realm_tenant', 'fk_users_organization_tenant',
                   'fk_oauth_clients_realm_tenant', 'fk_oauth_clients_organization_tenant')
               AND COALESCE((to_jsonb(c)->>'conenforced')::boolean, TRUE)
               AND convalidated AND NOT condeferrable
               AND confmatchtype = 's' AND confupdtype = 'a' AND confdeltype = 'a') = 4
        AND NOT EXISTS (SELECT 1 FROM pg_constraint
             WHERE conrelid IN ('users'::regclass, 'oauth_clients'::regclass)
               AND conname IN ('fk_users_realm', 'fk_users_organization',
                   'fk_oauth_clients_realm', 'fk_oauth_clients_organization'))
        AS value"#).get_result::<Flag>(&mut connection).await.unwrap();
    assert!(state.value, "only the selected redundant schema objects should disappear");
    connection.batch_execute(DOWN).await.unwrap();
    assert_eq!(snapshot(&mut connection).await, before, "down must restore the proven false/NULL/empty state exactly");
    assert_old_columns_exist(&mut connection).await;
    connection.batch_execute(UP).await.unwrap();
    connection.batch_execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn cleanup_refuses_legacy_information_without_partial_ddl_or_data_loss() {
    let Some(mut connection) = fixture().await else { return };
    for (change, reason) in [
        ("INSERT INTO openid4vci_credential_configurations (id, tenant_id, configuration) VALUES ('legacy', '00000000-0000-0000-0000-000000000001', '{\"format\":\"legacy\"}')", "table is not empty"),
        ("ALTER TABLE oauth_clients DROP CONSTRAINT ck_oauth_clients_ciba_user_code_disabled; UPDATE oauth_clients SET backchannel_user_code_parameter = TRUE", "non-false legacy value"),
        ("UPDATE controller_registry_slots SET last_used_at = '2026-01-01T00:00:00Z'", "controller last-used state"),
        ("UPDATE user_mfa_remembered_devices SET last_used_at = '2026-01-01T00:00:00Z'", "remembered-device last-used state"),
    ] {
        connection.batch_execute("SAVEPOINT fixture_change").await.unwrap();
        connection.batch_execute(change).await.unwrap();
        let before = snapshot(&mut connection).await;
        connection.batch_execute("SAVEPOINT migration_attempt").await.unwrap();
        let error = connection.batch_execute(UP).await.unwrap_err();
        assert!(error.to_string().contains(reason), "unexpected refusal: {error}");
        connection.batch_execute("ROLLBACK TO migration_attempt").await.unwrap();
        assert_old_columns_exist(&mut connection).await;
        assert_eq!(snapshot(&mut connection).await, before, "a refusal cannot erase legacy information");
        connection.batch_execute("ROLLBACK TO fixture_change; RELEASE fixture_change").await.unwrap();
    }
    connection.batch_execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn cleanup_refuses_directory_constraint_drift_and_external_dependencies() {
    let Some(mut connection) = fixture().await else { return };
    let has_enforcement_catalog = sql_query(
        "SELECT EXISTS (SELECT 1 FROM pg_attribute \
         WHERE attrelid = 'pg_catalog.pg_constraint'::regclass \
           AND attname = 'conenforced' AND NOT attisdropped) AS value",
    ).get_result::<Flag>(&mut connection).await.unwrap().value;
    for (change, reason) in [
        ("ALTER TABLE users DROP CONSTRAINT fk_users_realm_tenant", "missing fk_users_realm_tenant"),
        ("ALTER TABLE users ALTER CONSTRAINT fk_users_realm_tenant DEFERRABLE INITIALLY DEFERRED", "unexpected semantics"),
        ("ALTER TABLE users DROP CONSTRAINT fk_users_realm_tenant; ALTER TABLE users ADD CONSTRAINT fk_users_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id) NOT VALID", "unexpected semantics"),
        ("ALTER TABLE oauth_clients DROP CONSTRAINT fk_oauth_clients_organization_tenant; ALTER TABLE oauth_clients ADD CONSTRAINT fk_oauth_clients_organization_tenant FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id) ON DELETE CASCADE", "unexpected semantics"),
        ("ALTER TABLE users DROP CONSTRAINT fk_users_realm_tenant; ALTER TABLE users ADD CONSTRAINT fk_users_realm_tenant FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id) NOT ENFORCED", "unexpected semantics"),
        ("ALTER TABLE users ALTER COLUMN tenant_id DROP NOT NULL", "non-null key shape drifted"),
        ("CREATE VIEW external_client_observation AS SELECT backchannel_user_code_parameter FROM oauth_clients", "depend"),
        ("CREATE VIEW external_configuration_observation AS SELECT id FROM openid4vci_credential_configurations", "depend"),
    ] {
        if change.contains("NOT ENFORCED") && !has_enforcement_catalog {
            continue;
        }
        connection.batch_execute("SAVEPOINT fixture_change").await.unwrap();
        connection.batch_execute(change).await.unwrap();
        let before = snapshot(&mut connection).await;
        connection.batch_execute("SAVEPOINT migration_attempt").await.unwrap();
        let error = connection.batch_execute(UP).await.unwrap_err();
        assert!(error.to_string().contains(reason), "unexpected refusal: {error}");
        connection.batch_execute("ROLLBACK TO migration_attempt").await.unwrap();
        assert_old_columns_exist(&mut connection).await;
        assert_eq!(snapshot(&mut connection).await, before);
        connection.batch_execute("ROLLBACK TO fixture_change; RELEASE fixture_change").await.unwrap();
    }
    connection.batch_execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn retained_composite_fks_reject_cross_tenant_children_and_parent_mutations() {
    let Some(mut connection) = fixture().await else { return };
    connection.batch_execute(UP).await.unwrap();
    for change in [
        "UPDATE users SET realm_id = '00000000-0000-0000-0000-000000000012'",
        "UPDATE users SET organization_id = '00000000-0000-0000-0000-000000000022'",
        "UPDATE oauth_clients SET realm_id = '00000000-0000-0000-0000-000000000012'",
        "UPDATE oauth_clients SET organization_id = '00000000-0000-0000-0000-000000000022'",
        "UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000002'",
        "UPDATE oauth_clients SET tenant_id = '00000000-0000-0000-0000-000000000002'",
        "DELETE FROM realms WHERE id = '00000000-0000-0000-0000-000000000011'",
        "DELETE FROM organizations WHERE id = '00000000-0000-0000-0000-000000000021'",
        "UPDATE realms SET id = '00000000-0000-0000-0000-000000000013' WHERE id = '00000000-0000-0000-0000-000000000011'",
        "UPDATE organizations SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE id = '00000000-0000-0000-0000-000000000021'",
    ] {
        connection.batch_execute("SAVEPOINT forbidden_change").await.unwrap();
        let error = connection.batch_execute(change).await.unwrap_err();
        assert!(matches!(&error, diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)));
        assert!(error.to_string().contains("_tenant"), "the retained composite FK must reject: {error}");
        connection.batch_execute("ROLLBACK TO forbidden_change; RELEASE forbidden_change").await.unwrap();
    }
    connection.batch_execute("ROLLBACK").await.unwrap();
}
