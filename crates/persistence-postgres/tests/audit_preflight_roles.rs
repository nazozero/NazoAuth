use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Bool, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const UP: &str =
    include_str!("../../../migrations/20261002000300_audit_reachable_role_privileges/up.sql");
const DOWN: &str =
    include_str!("../../../migrations/20261002000300_audit_reachable_role_privileges/down.sql");
const PREFLIGHT: &str =
    "public.nazo_security_audit_shared_privilege_preflight(boolean,boolean,boolean)";
const APPEND: &str = "public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz)";
const EXPORT_FUNCTIONS: [&str; 11] = [
    "public.nazo_security_audit_chain_head_for_update()",
    "public.nazo_security_audit_batch_members()",
    "public.nazo_claim_security_audit_pending(bigint)",
    "public.nazo_open_security_audit_batch(bigint,bigint,integer,bytea,integer)",
    "public.nazo_reclaim_security_audit_batch(bytea,integer)",
    "public.nazo_append_security_audit_chain(bigint,bytea,uuid[],bytea[])",
    "public.nazo_ack_security_audit_batch(bigint,bigint,bigint,integer,bytea,bytea,text)",
    "public.nazo_fail_security_audit_batch(bigint,timestamptz,text,boolean)",
    "public.nazo_observe_security_audit_anchor(text)",
    "public.nazo_record_security_audit_genesis(text,bytea)",
    "public.nazo_security_audit_shared_anchor_health()",
];

#[derive(QueryableByName)]
struct Allowed {
    #[diesel(sql_type = Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct Number {
    #[diesel(sql_type = BigInt)]
    value: i64,
}

#[derive(Debug, PartialEq, Eq, QueryableByName)]
struct FunctionIdentity {
    #[diesel(sql_type = BigInt)]
    oid: i64,
    #[diesel(sql_type = BigInt)]
    owner_oid: i64,
    #[diesel(sql_type = Text)]
    acl: String,
    #[diesel(sql_type = Bool)]
    security_definer: bool,
    #[diesel(sql_type = Text)]
    settings: String,
}

async fn identity(connection: &mut AsyncPgConnection) -> FunctionIdentity {
    sql_query(format!(
        "SELECT oid::bigint AS oid, proowner::bigint AS owner_oid,
                COALESCE(proacl::text, '') AS acl, prosecdef AS security_definer,
                COALESCE(proconfig::text, '') AS settings
         FROM pg_proc WHERE oid = '{PREFLIGHT}'::regprocedure"
    ))
    .get_result(connection)
    .await
    .unwrap()
}

async fn policy(
    runtime: &mut AsyncPgConnection,
    strict: bool,
    append: bool,
    exporter: bool,
    expected: bool,
    case: &str,
) {
    let allowed = sql_query(
        "SELECT policy_satisfied AS value
         FROM public.nazo_security_audit_shared_privilege_preflight($1, $2, $3)",
    )
    .bind::<Bool, _>(strict)
    .bind::<Bool, _>(append)
    .bind::<Bool, _>(exporter)
    .get_result::<Allowed>(runtime)
    .await
    .unwrap();
    assert_eq!(allowed.value, expected, "{case}");
}

#[tokio::test]
async fn strict_preflight_checks_real_login_reachable_roles_and_columns() {
    let Some(base) = std::env::var("NAZO_AUDIT_TEST_DATABASE_URL").ok() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI audit preflight regression requires isolated NAZO_AUDIT_TEST_DATABASE_URL"
        );
        return;
    };
    let tag = Uuid::now_v7().simple().to_string();
    let database = format!("audit_privileges_{tag}");
    let login = format!("audit_login_{tag}");
    let a = format!("audit_a_{tag}");
    let b = format!("audit_b_{tag}");
    let c = format!("audit_c_{tag}");
    let d = format!("audit_d_{tag}");
    let table_owner = format!("audit_owner_{tag}");
    let super_role = format!("audit_super_{tag}");

    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    let version = sql_query("SELECT current_setting('server_version_num')::bigint AS value")
        .get_result::<Number>(&mut admin)
        .await
        .unwrap();
    assert!(
        version.value >= 180000,
        "run this role-edge regression on PostgreSQL 18+"
    );
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut owner_url = url::Url::parse(&base).unwrap();
    owner_url.set_path(&database);
    nazo_postgres::run_pending_migrations(owner_url.as_str())
        .await
        .unwrap();
    let mut owner = AsyncPgConnection::establish(owner_url.as_str())
        .await
        .unwrap();
    owner
        .batch_execute(&format!(
            "CREATE ROLE {login} LOGIN PASSWORD '{tag}' NOSUPERUSER NOINHERIT;
         CREATE ROLE {a} NOLOGIN NOSUPERUSER NOINHERIT;
         CREATE ROLE {b} NOLOGIN NOSUPERUSER NOINHERIT;
         CREATE ROLE {c} NOLOGIN NOSUPERUSER NOINHERIT;
         CREATE ROLE {d} NOLOGIN NOSUPERUSER NOINHERIT;
         CREATE ROLE {table_owner} NOLOGIN NOSUPERUSER NOINHERIT;
         CREATE ROLE {super_role} NOLOGIN SUPERUSER NOINHERIT;
         GRANT CONNECT ON DATABASE {database} TO {login};
         GRANT USAGE ON SCHEMA public TO {login};
         GRANT EXECUTE ON FUNCTION {PREFLIGHT} TO {login};"
        ))
        .await
        .unwrap();

    // Authenticate a new connection as the runtime LOGIN. SET ROLE on the
    // administrator would leave its session_user and exercise another policy.
    let mut runtime_url = owner_url.clone();
    runtime_url.set_username(&login).unwrap();
    runtime_url.set_password(Some(&tag)).unwrap();
    let mut runtime = AsyncPgConnection::establish(runtime_url.as_str())
        .await
        .unwrap();
    let real_login = sql_query(
        "SELECT session_user::text = $1 AND current_user = session_user
                AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = session_user) AS value",
    )
    .bind::<Text, _>(&login)
    .get_result::<Allowed>(&mut runtime)
    .await
    .unwrap();
    assert!(
        real_login.value,
        "preflight must run under the real runtime login"
    );
    policy(
        &mut runtime,
        true,
        false,
        false,
        true,
        "least-privilege login",
    )
    .await;

    // Function capability requirements survive strict opt-out and replacement.
    policy(
        &mut runtime,
        false,
        true,
        false,
        false,
        "append EXECUTE still required",
    )
    .await;
    owner
        .batch_execute(&format!("GRANT EXECUTE ON FUNCTION {APPEND} TO {login}"))
        .await
        .unwrap();
    policy(&mut runtime, true, true, false, true, "writer API granted").await;
    owner
        .batch_execute(&format!("REVOKE EXECUTE ON FUNCTION {APPEND} FROM {login}"))
        .await
        .unwrap();
    policy(&mut runtime, true, true, false, false, "writer API revoked").await;
    policy(
        &mut runtime,
        false,
        false,
        true,
        false,
        "exporter APIs still required",
    )
    .await;
    let exports = EXPORT_FUNCTIONS.join(", ");
    owner
        .batch_execute(&format!("GRANT EXECUTE ON FUNCTION {exports} TO {login}"))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        true,
        true,
        "all exporter APIs granted",
    )
    .await;
    let one_export = EXPORT_FUNCTIONS[3];
    owner
        .batch_execute(&format!(
            "REVOKE EXECUTE ON FUNCTION {one_export} FROM {login}"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        false,
        false,
        true,
        false,
        "one missing exporter API",
    )
    .await;
    owner
        .batch_execute(&format!(
            "GRANT EXECUTE ON FUNCTION {one_export} TO {login};
         REVOKE EXECUTE ON FUNCTION {exports} FROM {login};"
        ))
        .await
        .unwrap();

    // Reproduce the old NOINHERIT/SET gap, then apply the append-only upgrade.
    owner
        .batch_execute(&format!(
            "GRANT SELECT ON TABLE public.security_audit_events TO {a};
         GRANT {a} TO {login} WITH INHERIT FALSE, SET TRUE;"
        ))
        .await
        .unwrap();
    let before = identity(&mut owner).await;
    assert!(before.security_definer);
    owner.batch_execute(DOWN).await.unwrap();
    assert_eq!(
        identity(&mut owner).await,
        before,
        "down preserves owner, ACL and OID"
    );
    policy(
        &mut runtime,
        true,
        false,
        false,
        true,
        "old body misses an assumable role",
    )
    .await;
    owner.batch_execute(UP).await.unwrap();
    assert_eq!(
        identity(&mut owner).await,
        before,
        "up preserves owner, ACL, OID and search path"
    );
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "NOINHERIT role can SET into ledger access",
    )
    .await;
    policy(
        &mut runtime,
        false,
        false,
        false,
        true,
        "strict opt-out remains available",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {a} FROM {login};
         REVOKE SELECT ON TABLE public.security_audit_events FROM {a};"
        ))
        .await
        .unwrap();

    // Every forbidden table privilege and all four column privileges on
    // each relation protected by the original preflight.
    for (table, column) in [
        ("security_audit_chain_state", "last_sequence"),
        ("security_audit_events", "event_id"),
        ("security_audit_chain_entries", "event_id"),
    ] {
        for privilege in [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            owner
                .batch_execute(&format!(
                    "GRANT {privilege} ON TABLE public.{table} TO {login}"
                ))
                .await
                .unwrap();
            policy(&mut runtime, true, false, false, false, privilege).await;
            policy(
                &mut runtime,
                false,
                false,
                false,
                true,
                "table privilege with opt-out",
            )
            .await;
            owner
                .batch_execute(&format!(
                    "REVOKE {privilege} ON TABLE public.{table} FROM {login}"
                ))
                .await
                .unwrap();
            policy(
                &mut runtime,
                true,
                false,
                false,
                true,
                "table grant revoked",
            )
            .await;
        }
        for privilege in ["SELECT", "INSERT", "UPDATE", "REFERENCES"] {
            owner
                .batch_execute(&format!(
                    "GRANT {privilege} ({column}) ON TABLE public.{table} TO {login}"
                ))
                .await
                .unwrap();
            let column_only = sql_query(format!(
                "SELECT NOT has_table_privilege('{login}', 'public.{table}',
                    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS value"
            ))
            .get_result::<Allowed>(&mut owner)
            .await
            .unwrap();
            assert!(column_only.value, "fixture must provide column-only access");
            policy(&mut runtime, true, false, false, false, privilege).await;
            owner
                .batch_execute(&format!(
                    "REVOKE {privilege} ({column}) ON TABLE public.{table} FROM {login}"
                ))
                .await
                .unwrap();
            policy(
                &mut runtime,
                true,
                false,
                false,
                true,
                "column grant revoked",
            )
            .await;
        }
    }

    // PUBLIC grants are effective even though PUBLIC has no membership edge.
    for privilege in ["SELECT", "UPDATE (event_id)"] {
        owner
            .batch_execute(&format!(
                "GRANT {privilege} ON TABLE public.security_audit_events TO PUBLIC"
            ))
            .await
            .unwrap();
        policy(
            &mut runtime,
            true,
            false,
            false,
            false,
            "PUBLIC ledger privilege",
        )
        .await;
        owner
            .batch_execute(&format!(
                "REVOKE {privilege} ON TABLE public.security_audit_events FROM PUBLIC"
            ))
            .await
            .unwrap();
    }
    policy(
        &mut runtime,
        true,
        false,
        false,
        true,
        "PUBLIC grants revoked",
    )
    .await;

    owner
        .batch_execute(&format!(
            "GRANT SELECT ON TABLE public.security_audit_events TO {a};
         GRANT {a} TO {login} WITH INHERIT FALSE, SET FALSE;"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        true,
        "SET FALSE and no inheritance is harmless",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {a} FROM {login};
         GRANT {a} TO {login} WITH INHERIT TRUE, SET FALSE;"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "inherited privilege without SET",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {a} FROM {login};
         REVOKE SELECT ON TABLE public.security_audit_events FROM {a};
         GRANT {a} TO {login} WITH INHERIT FALSE, SET TRUE;
         GRANT {b} TO {a} WITH INHERIT FALSE, SET TRUE;
         GRANT SELECT ON TABLE public.security_audit_events TO {b};"
        ))
        .await
        .unwrap();
    policy(&mut runtime, true, false, false, false, "indirect SET path").await;
    owner
        .batch_execute(&format!(
            "REVOKE {b} FROM {a};
         REVOKE {a} FROM {login};
         REVOKE SELECT ON TABLE public.security_audit_events FROM {b};
         GRANT {a}, {c} TO {login} WITH INHERIT FALSE, SET TRUE;
         GRANT {d} TO {a}, {c} WITH INHERIT FALSE, SET TRUE;
         GRANT SELECT ON TABLE public.security_audit_events TO {d};"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "diamond membership graph deduplicates",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {d} FROM {a}, {c};
         REVOKE {a}, {c} FROM {login};
         REVOKE SELECT ON TABLE public.security_audit_events FROM {d};
         GRANT {a} TO {login} WITH INHERIT FALSE, SET TRUE;
         GRANT {b} TO {a} WITH INHERIT TRUE, SET FALSE;
         GRANT SELECT ON TABLE public.security_audit_events TO {b};"
        ))
        .await
        .unwrap();
    let inherited_behind_set = sql_query(format!(
        "SELECT pg_has_role('{login}', '{a}', 'SET')
                AND NOT pg_has_role('{login}', '{b}', 'SET')
                AND has_table_privilege('{a}', 'public.security_audit_events', 'SELECT') AS value"
    ))
    .get_result::<Allowed>(&mut owner)
    .await
    .unwrap();
    assert!(
        inherited_behind_set.value,
        "A inherits B but login cannot SET B"
    );
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "SET A inherits non-SETtable B",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {b} FROM {a};
         REVOKE {a} FROM {login};
         REVOKE SELECT ON TABLE public.security_audit_events FROM {b};"
        ))
        .await
        .unwrap();

    // Preserve the broader MEMBER rejection for owners and superusers even
    // when those memberships confer neither SET nor inherited privileges.
    owner
        .batch_execute(&format!(
            "ALTER TABLE public.security_audit_chain_entries OWNER TO {table_owner};
         GRANT {table_owner} TO {login} WITH INHERIT FALSE, SET FALSE;"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "owner MEMBER still rejected",
    )
    .await;
    owner
        .batch_execute(&format!(
            "REVOKE {table_owner} FROM {login};
         GRANT {super_role} TO {login} WITH INHERIT FALSE, SET FALSE;"
        ))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        false,
        "superuser MEMBER still rejected",
    )
    .await;
    owner
        .batch_execute(&format!("REVOKE {super_role} FROM {login}"))
        .await
        .unwrap();
    policy(
        &mut runtime,
        true,
        false,
        false,
        true,
        "all forbidden memberships revoked",
    )
    .await;
    assert_eq!(
        identity(&mut owner).await,
        before,
        "role changes never alter function identity"
    );

    drop(runtime);
    drop(owner);
    // DROP DATABASE must be a standalone command, not a multi-command
    // simple-query message that PostgreSQL would treat as one transaction.
    admin
        .batch_execute(&format!("DROP DATABASE {database}"))
        .await
        .unwrap();
    admin
        .batch_execute(&format!(
            "DROP ROLE {login}, {a}, {b}, {c}, {d}, {table_owner}, {super_role}"
        ))
        .await
        .unwrap();
}
