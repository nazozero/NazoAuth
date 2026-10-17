//! The released SQL is read from Git, never bundled into the current artifact.
use std::{collections::BTreeMap, path::Path, process::Command};

use diesel::{
    QueryableByName,
    migration::CREATE_MIGRATIONS_TABLE,
    sql_query,
    sql_types::{Jsonb, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use serde_json::Value;

#[path = "support/database.rs"]
mod database;

const RELEASE: &str = "385d23a330158ae78ff3fd55df2eac3a74cb2aec"; // v0.3.2
const BASELINE: &str = "20261017000400";

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct NameRow {
    #[diesel(sql_type = Text)]
    name: String,
}

async fn json(connection: &mut AsyncPgConnection, query: &str) -> Value {
    sql_query(query)
        .get_result::<JsonRow>(connection)
        .await
        .unwrap()
        .value
}

fn git(args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "v0.3.2 Git reference required: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

async fn released_schema(connection: &mut AsyncPgConnection) {
    connection
        .batch_execute(CREATE_MIGRATIONS_TABLE)
        .await
        .unwrap();
    let paths = git(&["ls-tree", "-r", "--name-only", RELEASE, "migrations"]);
    let up: Vec<_> = paths
        .lines()
        .filter(|path| path.ends_with("/up.sql"))
        .collect();
    assert_eq!(up.len(), 127);
    for path in up {
        let version = path
            .strip_prefix("migrations/")
            .unwrap()
            .split('_')
            .next()
            .unwrap();
        let sql = git(&["show", &format!("{RELEASE}:{path}")]);
        connection.batch_execute(&format!("BEGIN; {sql}\nINSERT INTO __diesel_schema_migrations(version) VALUES ('{version}'); COMMIT;")).await.unwrap();
    }
}

fn schema_dump(url: &str) -> String {
    let output = Command::new(std::env::var_os("PG_DUMP").unwrap_or_else(|| "pg_dump".into()))
        .args([
            "--dbname",
            url,
            "--schema-only",
            "--no-owner",
            "--exclude-table=__diesel_schema_migrations",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pg_dump 18+ required: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn data(connection: &mut AsyncPgConnection) -> BTreeMap<String, Value> {
    let tables = sql_query("SELECT tablename AS name FROM pg_tables WHERE schemaname='public' AND tablename <> '__diesel_schema_migrations' ORDER BY tablename")
        .load::<NameRow>(connection).await.unwrap();
    let mut snapshot = BTreeMap::new();
    for table in tables {
        snapshot.insert(table.name.clone(), json(connection, &format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)), '[]') AS value FROM public.{} AS t", table.name)).await);
    }
    snapshot
}

fn seed_facts(mut snapshot: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    // Only generated installation times and event UUIDs differ between empty installs.
    for (table, rows) in &mut snapshot {
        for row in rows.as_array_mut().unwrap().iter_mut() {
            let object = row.as_object_mut().unwrap();
            for timestamp in ["created_at", "updated_at", "occurred_at"] {
                object.remove(timestamp);
            }
            if table == "runtime_module_state_events" {
                object.remove("event_id");
            }
        }
        rows.as_array_mut()
            .unwrap()
            .sort_by_cached_key(Value::to_string);
    }
    snapshot
}

async fn identities(connection: &mut AsyncPgConnection) -> Value {
    json(connection, "SELECT jsonb_build_object(
        'relations', (SELECT jsonb_agg(jsonb_build_array(c.oid,c.relname,c.relowner,c.relacl,c.relfilenode) ORDER BY c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname NOT LIKE '__diesel_schema_migrations%'),
        'functions', (SELECT jsonb_agg(jsonb_build_array(p.oid,p.proowner,p.proacl,p.prosecdef,p.proconfig,pg_get_functiondef(p.oid)) ORDER BY p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),
        'constraints', (SELECT jsonb_agg(to_jsonb(c) ORDER BY c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' AND c.conname NOT LIKE '__diesel_schema_migrations%'),
        'triggers', (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
    ) AS value").await
}

async fn role_permissions(connection: &mut AsyncPgConnection, runtime: &str) {
    let access = json(connection, &format!("SELECT jsonb_build_array(
        has_table_privilege('{runtime}','public.users','SELECT,INSERT,UPDATE,DELETE'),
        has_table_privilege('{runtime}','public.security_audit_events','SELECT,INSERT,UPDATE,DELETE'),
        has_table_privilege('{runtime}','public.__diesel_schema_migrations','INSERT,UPDATE,DELETE'),
        has_function_privilege('{runtime}','public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)','EXECUTE'),
        has_function_privilege('{runtime}','public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)','EXECUTE'),
        has_function_privilege('{runtime}','public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)','EXECUTE')
    ) AS value")).await;
    assert_eq!(
        access,
        serde_json::json!([true, false, false, true, false, false])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn baseline_matches_release_and_adopts_populated_database_without_mutation() {
    let base = std::env::var("DATABASE_URL")
        .expect("baseline validation requires isolated PostgreSQL 18+");
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    let tag = uuid::Uuid::now_v7().simple().to_string();
    let owner = format!("baseline_owner_{tag}");
    let runtime = format!("baseline_runtime_{tag}");
    admin.batch_execute(&format!("CREATE ROLE {owner} LOGIN PASSWORD '{tag}' CREATEDB NOSUPERUSER; CREATE ROLE {runtime} LOGIN PASSWORD '{tag}' NOSUPERUSER NOINHERIT;")).await.unwrap();
    let mut owner_base = url::Url::parse(&base).unwrap();
    owner_base.set_username(&owner).unwrap();
    owner_base.set_password(Some(&tag)).unwrap();
    let released = database::create(owner_base.as_str()).await;
    let mut old = AsyncPgConnection::establish(&released).await.unwrap();
    released_schema(&mut old).await;
    let initial = seed_facts(data(&mut old).await);
    let fresh = database::migrate(owner_base.as_str()).await;
    let mut new = AsyncPgConnection::establish(&fresh).await.unwrap();
    assert_eq!(
        seed_facts(data(&mut new).await),
        initial,
        "all initial facts must match the release"
    );

    // PostgreSQL folds some ARRAY casts when re-parsing pg_dump's DDL. Restore
    // the released dump once to compare canonical definitions, not printer history.
    let canonical = database::create(owner_base.as_str()).await;
    let mut normalized = AsyncPgConnection::establish(&canonical).await.unwrap();
    normalized
        .batch_execute(&schema_dump(&released))
        .await
        .unwrap();
    // The old finalizer cutover copied implicit superuser capability into an
    // explicit EXECUTE grant. It changes no effective permission. Normalize
    // only that redundant grant in the disposable comparison database.
    normalized.batch_execute("DO $$ DECLARE role_name TEXT; BEGIN FOR role_name IN SELECT rolname FROM pg_roles WHERE rolsuper LOOP EXECUTE format('REVOKE EXECUTE ON FUNCTION public.nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer) FROM %I', role_name); END LOOP; END $$;").await.unwrap();
    let fresh_schema = schema_dump(&fresh);
    let expected_schema = schema_dump(&canonical);
    assert_eq!(
        fresh_schema.lines().count(),
        expected_schema.lines().count()
    );
    for (line, (actual, expected)) in fresh_schema
        .lines()
        .zip(expected_schema.lines())
        .enumerate()
    {
        assert_eq!(
            actual,
            expected,
            "schema/ACL difference on line {}",
            line + 1
        );
    }
    assert_eq!(initial.len(), 57);

    // The released security boundary also strips creation-time grants on the
    // internal proof helper and receiver authority, including default ACLs.
    let with_defaults = database::create(owner_base.as_str()).await;
    let mut default_connection = AsyncPgConnection::establish(&with_defaults).await.unwrap();
    default_connection
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO {runtime}"
        ))
        .await
        .unwrap();
    nazo_postgres::run_pending_migrations(&with_defaults)
        .await
        .unwrap();
    for function in [
        "nazo_stage_security_audit_chain(bigint,bytea,uuid[],bytea[])",
        "nazo_finalize_security_audit_claim(bigint,bytea,uuid[],bytea[],bigint,bigint,integer,bytea,integer)",
        "nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)",
        "nazo_record_security_audit_genesis(text,bytea)",
    ] {
        assert_eq!(json(&mut default_connection,&format!("SELECT to_jsonb(has_function_privilege('{runtime}','public.{function}','EXECUTE')) AS value")).await, false, "default grants must not confer {function}");
    }
    drop(default_connection);
    database::drop(&with_defaults).await;

    nazo_postgres::configure_runtime_role(&fresh, &runtime)
        .await
        .unwrap();
    nazo_postgres::configure_runtime_role(&released, &runtime)
        .await
        .unwrap();
    role_permissions(&mut new, &runtime).await;
    role_permissions(&mut old, &runtime).await;
    old.batch_execute(include_str!("support/fixtures/baseline_data.sql"))
        .await
        .unwrap();
    let audit = nazo_postgres::AuditLedgerRepository::new(
        nazo_postgres::create_pool(&released, 2).unwrap(),
    );
    let nazo_persistence::SecurityAuditBatchClaim::Claimed(batch) = audit
        .claim_batch("baseline-deployment", 256, 131072, 60)
        .await
        .unwrap()
    else {
        panic!("populated upgrade must include an in-flight audit batch");
    };
    let before_data = data(&mut old).await;
    let before_identity = identities(&mut old).await;
    let before_schema = schema_dump(&released);
    let before_ledger = json(
        &mut old,
        "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) AS value FROM __diesel_schema_migrations m",
    )
    .await;

    let (one, two) = tokio::join!(
        nazo_postgres::run_pending_migrations(&released),
        nazo_postgres::run_pending_migrations(&released)
    );
    assert_ne!(
        one.unwrap(),
        two.unwrap(),
        "concurrent upgrades record the baseline exactly once"
    );
    assert!(
        !nazo_postgres::run_pending_migrations(&released)
            .await
            .unwrap()
    );
    assert_eq!(
        data(&mut old).await,
        before_data,
        "upgrade must not modify any business row"
    );
    assert_eq!(
        identities(&mut old).await,
        before_identity,
        "upgrade must retain object identities, owners and permissions"
    );
    assert_eq!(schema_dump(&released), before_schema);
    assert_eq!(json(&mut old, &format!("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) AS value FROM __diesel_schema_migrations m WHERE version <> '{BASELINE}'")).await, before_ledger);
    assert_eq!(
        json(
            &mut old,
            "SELECT to_jsonb(count(*)) AS value FROM __diesel_schema_migrations"
        )
        .await,
        128
    );
    role_permissions(&mut old, &runtime).await;

    // Prove access under the actual LOGIN, not the owner or SET ROLE.
    let mut runtime_url = url::Url::parse(&released).unwrap();
    runtime_url.set_username(&runtime).unwrap();
    runtime_url.set_password(Some(&tag)).unwrap();
    let mut writer = AsyncPgConnection::establish(runtime_url.as_str())
        .await
        .unwrap();
    writer.batch_execute("UPDATE users SET display_name='after baseline' WHERE username='baseline-user'; SELECT public.nazo_persist_security_audit_event(uuidv7(),'baseline_after_upgrade','security','{}',CURRENT_TIMESTAMP)").await.unwrap();
    for forbidden in [
        "DELETE FROM public.security_audit_events",
        "DELETE FROM __diesel_schema_migrations",
        "SELECT public.nazo_ack_security_audit_batch(NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
    ] {
        assert!(
            writer.batch_execute(forbidden).await.is_err(),
            "runtime must be denied {forbidden}"
        );
    }
    audit
        .ack_batch(nazo_persistence::SecurityAuditBatchAck {
            generation: batch.generation,
            deployment_id: "baseline-deployment".into(),
            first_sequence: batch.first_sequence,
            last_sequence: batch.last_sequence,
            event_count: batch.event_count(),
            last_hash: batch.last_hash,
            batch_digest: batch.digest,
        })
        .await
        .unwrap();
    // Current tenant FKs and principal epochs survive both installation paths.
    new.batch_execute(include_str!("support/fixtures/baseline_data.sql"))
        .await
        .unwrap();
    for connection in [&mut old, &mut new] {
        connection.batch_execute("INSERT INTO tenants(id,slug,display_name,status) VALUES ('00000000-0000-0000-0000-000000000004','other','Other tenant','active')").await.unwrap();
        connection.batch_execute("UPDATE users SET is_active=FALSE; UPDATE users SET is_active=TRUE; UPDATE oauth_clients SET is_active=FALSE; UPDATE oauth_clients SET is_active=TRUE;").await.unwrap();
        assert_eq!(json(connection,"SELECT jsonb_build_array((SELECT access_token_epoch FROM users),(SELECT access_token_epoch FROM oauth_clients)) AS value").await, serde_json::json!([1,1]));
        assert!(connection.batch_execute("INSERT INTO oauth_subject_bindings(tenant_id,subject,user_id) SELECT '00000000-0000-0000-0000-000000000004','wrong-tenant',id FROM users").await.is_err());
        assert!(connection.batch_execute("INSERT INTO user_totp_credentials(tenant_id,user_id,secret_ciphertext,secret_key_id) SELECT '00000000-0000-0000-0000-000000000004',id,decode('01'||repeat('ab',44),'hex'),'fixture-root' FROM users").await.is_err());
    }
    drop(audit);
    drop(writer);
    drop(old);
    drop(new);
    drop(normalized);
    for url in [&released, &fresh, &canonical] {
        database::drop(url).await;
    }
    admin
        .batch_execute(&format!("DROP ROLE {runtime}, {owner}"))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn baseline_refuses_pre_cutoff_and_rolls_back_failed_installation() {
    let base =
        std::env::var("DATABASE_URL").expect("baseline validation requires isolated PostgreSQL");
    let url = database::create(&base).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    connection
        .batch_execute(CREATE_MIGRATIONS_TABLE)
        .await
        .unwrap();
    connection.batch_execute("INSERT INTO __diesel_schema_migrations(version) VALUES ('20261017000200'); CREATE TABLE preserved (value text); INSERT INTO preserved VALUES ('before baseline')").await.unwrap();
    let before = data(&mut connection).await;
    let error = nazo_postgres::run_pending_migrations(&url)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("upgrade with v0.3.2"));
    assert_eq!(data(&mut connection).await, before);
    assert_eq!(
        json(
            &mut connection,
            "SELECT to_jsonb(count(*)) AS value FROM __diesel_schema_migrations"
        )
        .await,
        1
    );

    connection
        .batch_execute(
            "DELETE FROM __diesel_schema_migrations; CREATE TABLE public.users (original integer)",
        )
        .await
        .unwrap();
    let before = identities(&mut connection).await;
    assert!(nazo_postgres::run_pending_migrations(&url).await.is_err());
    assert_eq!(
        identities(&mut connection).await,
        before,
        "a late DDL collision must roll back all baseline DDL and leave existing objects alone"
    );
    assert_eq!(
        json(
            &mut connection,
            "SELECT to_jsonb(count(*)) AS value FROM __diesel_schema_migrations"
        )
        .await,
        0
    );
    connection
        .batch_execute("DROP TABLE public.users")
        .await
        .unwrap();
    assert!(nazo_postgres::run_pending_migrations(&url).await.unwrap());
    assert!(!nazo_postgres::run_pending_migrations(&url).await.unwrap());
    assert!(
        connection
            .batch_execute(include_str!(
                "../../../migrations/20261017000400_v0_3_2_baseline/down.sql"
            ))
            .await
            .is_err()
    );
    drop(connection);
    database::drop(&url).await;
}
