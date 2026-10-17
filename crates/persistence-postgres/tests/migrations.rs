use chrono::{Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Bool, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_postgres::get_conn;
use uuid::Uuid;

mod support;

#[test]
fn migration_versions_are_unique_across_merged_branches() {
    let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut versions = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(migrations).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() || !entry.path().join("up.sql").is_file() {
            continue;
        }
        let name = entry.file_name().into_string().unwrap();
        let version = name.split('_').next().unwrap().to_owned();
        let previous = versions.insert(version.clone(), name.clone());
        assert!(
            previous.is_none(),
            "migration version {version} is shared by {previous:?} and {name}"
        );
    }
}

#[test]
fn embedded_migration_manifest_tracks_all_files() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let actual: std::collections::BTreeSet<_> = std::fs::read_dir(root.join("migrations"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .flat_map(|entry| std::fs::read_dir(entry.path()).unwrap())
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let recorded: std::collections::BTreeSet<_> =
        include_str!("../../../tests/contracts/migrations.sha256")
            .lines()
            .map(|line| line.split_once("  ").unwrap().1.to_owned())
            .collect();
    assert_eq!(
        recorded, actual,
        "every migration must invalidate the embedded artifact cache"
    );
}

#[derive(QueryableByName)]
struct RuntimeTable {
    #[diesel(sql_type = Text)]
    table_name: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct ExplainRow {
    #[diesel(sql_type = Text, column_name = "QUERY PLAN")]
    query_plan: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_cleanup_uses_expiry_as_an_index_bound() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    #[derive(QueryableByName)]
    struct FunctionBody {
        #[diesel(sql_type = Text)]
        body: String,
    }
    let body = sql_query(
        "SELECT prosrc AS body FROM pg_proc \
         WHERE oid = 'nazo_oauth_cleanup_expired_security_state(boolean)'::regprocedure",
    )
    .get_result::<FunctionBody>(&mut connection)
    .await
    .expect("installed cleanup definition should be readable")
    .body;
    // Explain the installed candidate query, not a second copy that could
    // keep passing after the production predicate regresses. The bind models
    // PL/pgSQL's one per-call cutoff variable.
    let candidate = body
        .split_once("WITH due AS (")
        .expect("issuance candidate CTE should exist")
        .1
        .split_once(")\n    DELETE FROM oauth_token_issuances")
        .expect("issuance candidate should feed the bounded delete")
        .0
        .replace("v_cutoff", "$1");
    connection
        .batch_execute("SET enable_seqscan = off; SET enable_bitmapscan = off")
        .await
        .expect("small fixtures should still expose usable index conditions");
    let plan = sql_query(format!("EXPLAIN (COSTS OFF) {candidate}"))
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .load::<ExplainRow>(&mut connection)
        .await
        .expect("installed expiry candidate should explain")
        .into_iter()
        .map(|row| row.query_plan)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan.contains("oauth_token_issuances_retention_idx")
            && plan.contains("Index Cond: (retain_until <="),
        "expiry must bound the index scan rather than filter retained rows:\n{plan}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vp_expiry_cleanup_query_is_indexable() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute("SET enable_seqscan = off")
        .await
        .expect("planner test should disable sequential scans");
    let plan = sql_query(
        "EXPLAIN (COSTS OFF) \
         SELECT id FROM openid4vp_transactions \
         WHERE expires_at <= CURRENT_TIMESTAMP \
         ORDER BY expires_at, id LIMIT 256",
    )
    .load::<ExplainRow>(&mut connection)
    .await
    .expect("cleanup EXPLAIN should succeed")
    .into_iter()
    .map(|row| row.query_plan)
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        plan.contains("ix_openid4vp_transaction_expiry"),
        "cleanup query must use the transaction expiry index:\n{plan}"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_migrations_create_all_runtime_module_state_tables() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let isolated_url = support::database::migrate(&database_url).await;
    let mut connection = AsyncPgConnection::establish(&isolated_url)
        .await
        .expect("isolated test database should connect");
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

    let explicit_desired = sql_query(
        "SELECT count(*) AS count FROM runtime_module_desired_states \
         WHERE desired_mode IN ('enabled', 'disabled')",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("explicit runtime baseline should be readable");
    assert_eq!(explicit_desired.count, 16);
    let genesis_audit = sql_query(
        "SELECT count(*) AS count FROM runtime_module_state_events \
         WHERE event_type = 'desired_state_changed' \
           AND revision = 1 AND reason = 'clean install baseline'",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("runtime genesis audit should be readable");
    assert_eq!(genesis_audit.count, 16);

    let catalog_probe = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection
                .batch_execute(
                    r#"
                    INSERT INTO runtime_module_desired_states
                        (tenant_id, module_id, desired_mode, revision)
                    VALUES ('00000000-0000-0000-0000-000000000001', 'scim_security_events', 'disabled', 1)
                    ON CONFLICT (tenant_id, module_id) DO NOTHING;
                    INSERT INTO runtime_module_instance_states
                        (tenant_id, instance_id, module_id, actual_state, transition_revision)
                    VALUES (
                        '00000000-0000-0000-0000-000000000001',
                        'migration-catalog-test-' || gen_random_uuid()::text,
                        'scim_security_events', 'disabled', 1
                    );
                    INSERT INTO runtime_module_state_events
                        (event_id, tenant_id, module_id, event_type, revision)
                    VALUES (
                        gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'scim_security_events',
                        'transition_completed', 1
                    );
                    "#,
                )
                .await?;
            Err(diesel::result::Error::RollbackTransaction)
        })
        .await;
    assert!(
        matches!(
            catalog_probe,
            Err(diesel::result::Error::RollbackTransaction)
        ),
        "SCIM security-events runtime module should be in every closed catalog: {catalog_probe:?}"
    );
    drop(connection);
    support::database::drop(&isolated_url).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_migrations_create_tenant_scoped_signing_keyset_storage() {
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
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = 'tenant_signing_keysets'",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("signing-key table catalog should be readable");
    assert_eq!(tables.len(), 1, "keysets must be database-authoritative");
}

/// RV-09 — the retention migration is pinned to the verifier's maximum
/// clock-skew constant and its downgrade can never shorten a stored fact.
/// RV-08 — real upgrade path: a schema sitting at the version before the
/// retention migration (the migration is data-only, so removing its ledger
/// row reproduces that state exactly) gains the new migration through the
/// real `run_pending_migrations` runner. Rows written under the old semantics
/// (expires_at = bare verified exp) gain exactly one skew window, only while
/// they can still fall inside a verifier's acceptance window, and a second
/// runner pass reports nothing pending and extends nothing further.
/// RV-09 — a full migration run on an empty schema succeeds and the ledger
/// records it, and the *actual* runtime role (a NOSUPERUSER role granted DML
/// through `configure_runtime_role`, activated via the connection `role`
/// option exactly like production) executes the revocation write path:
/// INSERT on a fresh authority key, then ON CONFLICT DO UPDATE with GREATEST
/// on the same `(tenant_id, access_token_jti_blake3)` key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_schema_migration_run_leaves_revocation_retention_applied_and_writable() {
    let Some(database_url) = database_url() else {
        return;
    };
    let isolated_url = support::database::migrate(&database_url).await;
    let mut connection = AsyncPgConnection::establish(&isolated_url)
        .await
        .expect("isolated test database should connect");
    let table = sql_query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = 'access_token_revocations'",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("table catalog should be readable");
    assert_eq!(
        table.len(),
        1,
        "an empty schema must reach the current revocation-table shape"
    );
    assert!(
        !nazo_postgres::run_pending_migrations(&isolated_url)
            .await
            .expect("the ledger re-check should succeed"),
        "a second migration run must report nothing pending"
    );
    drop(connection);
    let database_url = isolated_url;

    // Exercise the write path under the real runtime role, not the lifecycle
    // role: the session `role` option makes every statement run with the
    // runtime role's privileges on the migrated public schema.
    let runtime_role = format!("rv09_runtime_{}", Uuid::now_v7().simple());
    let mut lifecycle = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect for role preparation");
    lifecycle
        .batch_execute(&format!(
            "SELECT pg_advisory_lock(564196923451771043);\
             DO $$ BEGIN \
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{runtime_role}') THEN \
                 CREATE ROLE \"{runtime_role}\" NOSUPERUSER NOBYPASSRLS NOINHERIT; \
               END IF; \
             END $$;\
             SELECT pg_advisory_unlock(564196923451771043);"
        ))
        .await
        .expect("migration runtime role fixture should exist");
    nazo_postgres::configure_runtime_role(&database_url, &runtime_role)
        .await
        .expect("runtime role grants should configure");

    let separator = if database_url.contains('?') { '&' } else { '?' };
    let runtime_url = format!("{database_url}{separator}options=-crole%3D{runtime_role}");
    let runtime_pool =
        nazo_postgres::create_pool(runtime_url, 2).expect("runtime-role pool should build");

    #[derive(QueryableByName)]
    struct SessionRole {
        #[diesel(sql_type = Text)]
        role_name: String,
        #[diesel(sql_type = Bool)]
        superuser: bool,
    }
    #[derive(QueryableByName)]
    struct ExpiryDeadline {
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        expires_at: chrono::DateTime<chrono::Utc>,
    }

    // Prove the session really runs as the non-superuser runtime role.
    let mut runtime_connection = get_conn(&runtime_pool)
        .await
        .expect("runtime-role connection should come from the pool");
    let identity = sql_query(
        "SELECT current_user AS role_name, \
                (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser",
    )
    .get_result::<SessionRole>(&mut runtime_connection)
    .await
    .expect("session role should be readable");
    assert_eq!(identity.role_name, runtime_role);
    assert!(
        !identity.superuser,
        "the runtime role must not be a superuser"
    );

    let client_id = Uuid::now_v7();
    let protocol_client_id = format!("rv09-runtime-{}", Uuid::now_v7().simple());
    sql_query(format!(
        r#"
        INSERT INTO oauth_clients (
            id, client_id, client_name, client_type, redirect_uris, scopes, grant_types,
            token_endpoint_auth_method, security_policy
        ) VALUES (
            '{client_id}', '{protocol_client_id}', 'Retention Runtime Role Test',
            'confidential', '["https://client.example/callback"]'::jsonb,
            '["openid"]'::jsonb, '["authorization_code"]'::jsonb,
            'client_secret_basic',
            '{{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}}'::jsonb
        )
        "#
    ))
    .execute(&mut runtime_connection)
    .await
    .expect("the runtime role must hold INSERT on oauth_clients");
    drop(runtime_connection);

    // The production revocation path: the first call INSERTs the fact, the
    // second call on the same authority key takes ON CONFLICT DO UPDATE and
    // only GREATEST-extends the retention deadline.
    let repository = nazo_postgres::AuthorizationRepository::new(runtime_pool.clone());
    let tenant_id = Uuid::from_u128(1);
    let jti = format!("rv09-jti-{}", Uuid::now_v7());
    let first_exp = Utc::now() + Duration::minutes(30);
    let second_exp = Utc::now() + Duration::minutes(90);
    repository
        .revoke_issued_tokens(tenant_id, client_id, &jti, Some(first_exp), None)
        .await
        .expect("runtime role must execute the revocation insert");
    repository
        .revoke_issued_tokens(tenant_id, client_id, &jti, Some(second_exp), None)
        .await
        .expect("runtime role must execute the conflicting upsert");

    let rows = sql_query(
        "SELECT expires_at FROM access_token_revocations \
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<Text, _>(blake3::hash(jti.as_bytes()).to_hex().to_string())
    .load::<ExpiryDeadline>(&mut lifecycle)
    .await
    .expect("stored revocation should be readable");
    assert_eq!(rows.len(), 1, "one authority key must hold exactly one row");
    // timestamptz stores microseconds; the bound value truncates the
    // sub-microsecond part of `second_exp`.
    let skew = Duration::seconds(nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS);
    let stored_delta = rows[0].expires_at.signed_duration_since(second_exp);
    assert!(
        stored_delta >= skew - Duration::seconds(1) && stored_delta < skew + Duration::seconds(1),
        "the conflicting write must extend the deadline to the later exp + skew, got {stored_delta:?}"
    );

    drop(runtime_pool);
    lifecycle
        .batch_execute(&format!(
            "DELETE FROM access_token_revocations WHERE client_id = '{client_id}';\
             DELETE FROM oauth_clients WHERE id = '{client_id}';\
             DROP OWNED BY \"{runtime_role}\" CASCADE; DROP ROLE \"{runtime_role}\";"
        ))
        .await
        .expect("runtime-role fixtures should clean up");
    support::database::drop(&database_url).await;
}
