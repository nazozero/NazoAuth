//! Contract coverage for the Fresh issuance commit path with no user and no
//! refresh token: one ownership row and one `token_issued` audit event
//! commit atomically, and every rejection leaves no partial writes. These
//! tests exercise the public repository contract; they must pass identically
//! on the serial and the combined-statement implementation.

use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, TokenIssuanceMode, TokenIssuedAuditFields,
    TokenPortError, TokenRepositoryPort,
};
use nazo_postgres::{TokenIssuanceRepository, TokenRepository, create_pool};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI token-issuance tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct FixtureIds {
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct IssuanceRow {
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    user_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    refresh_token_family_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    access_token_expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    retain_until: chrono::DateTime<chrono::Utc>,
}

async fn fixture(database_url: &str) -> FixtureIds {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let suffix = Uuid::now_v7().simple().to_string();
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    let security_policy = r#"{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}"#;
    sql_query(format!(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_name, client_type, redirect_uris, scopes, grant_types,
            token_endpoint_auth_method, security_policy
        ) VALUES (
            'fresh-{suffix}', 'Fresh Issuance Test', 'confidential',
            '["https://client.example/callback"]'::jsonb,
            '["openid", "profile"]'::jsonb,
            '["client_credentials"]'::jsonb,
            'client_secret_basic',
            '{security_policy}'::jsonb
        ) RETURNING id AS client_id, client_id AS client_public_id
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("fresh issuance fixture should insert")
}

/// The client-credentials grant shape: `Fresh` mode, no subject, no refresh
/// token, audit fields carrying the public client id.
fn fresh_issuance(fixture: &FixtureIds, tenant_id: Uuid) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        issuance_id,
        tenant_id,
        client_id: fixture.client_id,
        user_id: None,
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        refresh_token: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: fixture.client_public_id.clone(),
            subject_hash: blake3::hash(fixture.client_public_id.as_bytes())
                .to_hex()
                .to_string(),
            scope: "profile".to_owned(),
            audience: vec!["resource://default".to_owned()],
        },
    }
}

fn tagged_database_url(database_url: &str, application_name: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}application_name={application_name}")
}

async fn wait_for_lock_wait(connection: &mut AsyncPgConnection, application_name: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let blocked = sql_query(
            r#"
            SELECT COUNT(*)::bigint AS count
            FROM pg_stat_activity
            WHERE application_name = $1
              AND wait_event_type = 'Lock'
            "#,
        )
        .bind::<sql_types::Text, _>(application_name)
        .get_result::<CountRow>(connection)
        .await
        .expect("blocked PostgreSQL activity should be observable");
        if blocked.count > 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    let diagnostics = sql_query(
        "SELECT COALESCE(string_agg(pid || ':' || application_name || ':' || \
         COALESCE(wait_event_type, '-') || ':' || left(query, 60), '; '), '<none>') \
         AS count FROM pg_stat_activity WHERE datname = current_database()",
    );
    let dump = diagnostics
        .get_result::<DiagRow>(connection)
        .await
        .map(|row| row.count)
        .unwrap_or_else(|e| format!("diag query failed: {e}"));
    panic!("timed out waiting for lock wait from {application_name}; backends: {dump}");
}

#[derive(QueryableByName)]
struct DiagRow {
    #[diesel(sql_type = sql_types::Text)]
    count: String,
}

async fn wait_for_lock_wait_or_task<T: std::fmt::Debug>(
    connection: &mut AsyncPgConnection,
    application_name: &str,
    task: &mut tokio::task::JoinHandle<T>,
) {
    tokio::select! {
        () = wait_for_lock_wait(connection, application_name) => {}
        result = task => {
            let dump = sql_query(
                "SELECT COALESCE(string_agg(pid || ':' || application_name || ':' \
                 || COALESCE(wait_event_type, '-') || ':' || state, '; '), \
                 '<none>') AS count FROM pg_stat_activity \
                 WHERE datname = current_database()",
            )
            .get_result::<DiagRow>(connection)
            .await
            .map(|row| row.count)
            .unwrap_or_else(|e| format!("diag failed: {e}"));
            panic!(
                "task ended before reaching a PostgreSQL lock wait from \
                 {application_name}: {result:?}; backends: {dump}"
            );
        }
    }
}

async fn write_counts(connection: &mut AsyncPgConnection, issuance_id: Uuid) -> (i64, i64) {
    let issuances = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<sql_types::Uuid, _>(issuance_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("issuance count should load")
    .count;
    let audits = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type = 'token_issued' AND payload->>'issuance_id' = $1",
    )
    .bind::<sql_types::Text, _>(issuance_id.to_string())
    .get_result::<CountRow>(connection)
    .await
    .expect("audit count should load")
    .count;
    (issuances, audits)
}

async fn assert_no_writes(database_url: &str, issuance_id: Uuid) {
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("verification connection should connect");
    assert_eq!(
        write_counts(&mut connection, issuance_id).await,
        (0, 0),
        "a rejected issuance must leave no ownership or audit row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_commits_ownership_and_audit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let input = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .expect("fresh issuance should commit"),
        CommitTokenIssuanceResult::Committed
    );
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("verification connection should connect");
    assert_eq!(
        write_counts(&mut connection, input.issuance_id).await,
        (1, 1),
        "a committed fresh issuance owns one row and one audit event"
    );
    let row = sql_query(
        "SELECT user_id, refresh_token_family_id, access_token_expires_at, retain_until \
         FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<sql_types::Uuid, _>(input.issuance_id)
    .get_result::<IssuanceRow>(&mut connection)
    .await
    .expect("issuance row should load");
    assert!(
        row.user_id.is_none(),
        "client_credentials carries no subject"
    );
    assert!(
        row.refresh_token_family_id.is_none(),
        "client_credentials carries no refresh family"
    );
    assert_eq!(
        row.access_token_expires_at.timestamp(),
        input.access_token_expires_at
    );
    assert!(
        row.retain_until.timestamp()
            >= input.access_token_expires_at
                + nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
        "the durable fence retains the row through the verifier skew window"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_rejects_missing_or_inactive_client() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());

    let mut missing = fresh_issuance(&fixture, tenant_id);
    missing.client_id = Uuid::now_v7();
    assert_eq!(
        repository
            .commit_token_issuance(missing.clone())
            .await
            .expect("a missing client is a classified result"),
        CommitTokenIssuanceResult::ClientInactive
    );
    assert_no_writes(&database_url, missing.issuance_id).await;

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("fixture connection should connect");
    sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut connection)
        .await
        .expect("client deactivation should apply");
    let inactive = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(inactive.clone())
            .await
            .expect("an inactive client is a classified result"),
        CommitTokenIssuanceResult::ClientInactive
    );
    assert_no_writes(&database_url, inactive.issuance_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_never_crosses_tenant_boundary() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let wrong_tenant = Uuid::now_v7();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let input = fresh_issuance(&fixture, wrong_tenant);
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .expect("a foreign-tenant client is a classified result"),
        CommitTokenIssuanceResult::ClientInactive,
        "the client row must not be visible outside its tenant"
    );
    assert_no_writes(&database_url, input.issuance_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_id_conflict_stays_an_error() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let input = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .expect("first commit should succeed"),
        CommitTokenIssuanceResult::Committed
    );
    let second = repository.commit_token_issuance(input.clone()).await;
    assert!(
        matches!(
            second,
            Err(TokenPortError::Conflict) | Err(TokenPortError::Unexpected)
        ),
        "a duplicate issuance id must surface an error, got {second:?}"
    );
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("verification connection should connect");
    assert_eq!(
        write_counts(&mut connection, input.issuance_id).await,
        (1, 1),
        "the conflicting retry must not append a second audit or ownership row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_rejects_oversized_audit_payload() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let mut input = fresh_issuance(&fixture, tenant_id);
    input.audit_fields.scope = "x".repeat(128 * 1024);
    let result = repository.commit_token_issuance(input.clone()).await;
    assert!(
        matches!(result, Err(TokenPortError::Unexpected)),
        "an oversized audit payload must surface the shared validation error, got {result:?}"
    );
    assert_no_writes(&database_url, input.issuance_id).await;
}

/// A client row lock held by an uncommitted deactivation makes the issuance
/// wait; once the deactivation commits, the issuance re-checks the committed
/// state and refuses the inactive client without any partial write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_waits_for_client_deactivation_and_rechecks() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let input = fresh_issuance(&fixture, tenant_id);
    let application_name = format!("fresh-issuance-{}", Uuid::now_v7().simple());
    let repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &application_name), 1).unwrap(),
    );
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test coordinator should connect");
    let mut observer = AsyncPgConnection::establish(&database_url)
        .await
        .expect("lock observer should connect");
    coordinator
        .batch_execute("BEGIN")
        .await
        .expect("deactivation transaction should begin");
    let changed = sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut coordinator)
        .await
        .expect("client deactivation should hold its row lock");
    assert_eq!(changed, 1, "client fixture must start active");
    let issuance_id = input.issuance_id;
    let mut issuer = tokio::spawn(async move { repository.commit_token_issuance(input).await });
    wait_for_lock_wait_or_task(&mut observer, &application_name, &mut issuer).await;
    coordinator
        .batch_execute("COMMIT")
        .await
        .expect("client deactivation should commit");
    assert_eq!(
        issuer
            .await
            .expect("issuance task should join")
            .expect("issuance should classify a committed deactivation"),
        CommitTokenIssuanceResult::ClientInactive
    );
    assert_no_writes(&database_url, issuance_id).await;
}

/// The issuance's FOR SHARE lock makes a concurrent deactivation wait; the
/// committed credential is then revoked by the completed deactivation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_deactivation_waits_for_fresh_issuance_commit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let input = fresh_issuance(&fixture, tenant_id);
    let issuance_id = input.issuance_id;
    let access_token_jti = input.access_token_jti.clone();
    let gate_key: i64 = {
        let bytes = issuance_id.as_bytes();
        let high = i64::from_be_bytes(bytes[..8].try_into().unwrap());
        let low = i64::from_be_bytes(bytes[8..].try_into().unwrap());
        high ^ low
    };
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test coordinator should connect");
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_fresh_issuance_gate_{suffix}");
    let trigger = format!("test_fresh_issuance_gate_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.issuance_id = '{issuance_id}'::uuid THEN
                PERFORM pg_advisory_xact_lock({gate_key});
            END IF;
            RETURN NEW;
        END
        $$
        "#
    ))
    .execute(&mut coordinator)
    .await
    .expect("fresh issuance gate function should install");
    sql_query(format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON oauth_token_issuances \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&mut coordinator)
    .await
    .expect("fresh issuance gate should install");
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<sql_types::BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold the issuance gate");

    let issuance_application = format!("fresh-before-deactivation-{}", Uuid::now_v7().simple());
    let issuance = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &issuance_application), 1).unwrap(),
    );
    let mut issuer = tokio::spawn(async move { issuance.commit_token_issuance(input).await });
    wait_for_lock_wait_or_task(&mut coordinator, &issuance_application, &mut issuer).await;

    let deactivation_application = format!("deactivation-after-fresh-{}", Uuid::now_v7().simple());
    let deactivation_database_url = tagged_database_url(&database_url, &deactivation_application);
    let client_id = fixture.client_id;
    let mut deactivation = tokio::spawn(async move {
        let mut connection = AsyncPgConnection::establish(&deactivation_database_url)
            .await
            .expect("deactivation connection should establish");
        connection
            .transaction::<bool, diesel::result::Error, _>(async |connection| {
                nazo_postgres::deactivate_client_on_connection(connection, tenant_id, client_id)
                    .await
            })
            .await
    });
    wait_for_lock_wait_or_task(
        &mut coordinator,
        &deactivation_application,
        &mut deactivation,
    )
    .await;

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<sql_types::BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release the issuance gate");
    assert_eq!(
        issuer
            .await
            .expect("issuance task should join")
            .expect("issuance should commit before deactivation acquires its row lock"),
        CommitTokenIssuanceResult::Committed
    );
    assert!(
        deactivation
            .await
            .expect("deactivation task should join")
            .expect("deactivation should commit"),
        "the real deactivation path must run after issuance releases FOR SHARE"
    );
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    assert!(
        tokens
            .access_token_revoked(tenant_id, &access_token_jti)
            .await
            .expect("access-token revocation should load"),
        "deactivation must revoke the access token committed while it was blocked"
    );
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_token_issuances"))
        .execute(&mut coordinator)
        .await
        .expect("gate trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut coordinator)
        .await
        .expect("gate function should be removed");
}

/// A lock wait past the 2s `lock_timeout` aborts the commit: the error is a
/// classified port error, the connection is discarded rather than returned
/// with an unknown transaction state, and the pool serves the next commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_lock_timeout_discards_connection_cleanly() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let input = fresh_issuance(&fixture, tenant_id);
    let issuance_id = input.issuance_id;
    let application_name = format!("fresh-lock-timeout-{}", Uuid::now_v7().simple());
    let pool = create_pool(tagged_database_url(&database_url, &application_name), 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test coordinator should connect");
    coordinator
        .batch_execute("BEGIN")
        .await
        .expect("blocking transaction should begin");
    sql_query("SELECT id FROM oauth_clients WHERE id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold the client row lock");
    // A dedicated observer connection is required: pg_stat_activity is read
    // through the transaction-scoped stats cache when queried inside the
    // coordinator's open transaction, which would freeze the view.
    let mut observer = AsyncPgConnection::establish(&database_url)
        .await
        .expect("lock observer should connect");
    let issuer_repository = repository.clone();
    let mut issuer =
        tokio::spawn(async move { issuer_repository.commit_token_issuance(input).await });
    wait_for_lock_wait_or_task(&mut observer, &application_name, &mut issuer).await;
    // Keep the lock past the 2s lock_timeout; the issuer errors out while the
    // coordinator transaction stays open.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert!(
        issuer.await.expect("issuance task should join").is_err(),
        "a lock wait beyond lock_timeout must surface an error"
    );
    coordinator
        .batch_execute("ROLLBACK")
        .await
        .expect("coordinator should release the row lock");
    assert_no_writes(&database_url, issuance_id).await;
    // The timed-out connection was dropped mid-transaction; the pool must
    // replace it and serve a subsequent commit on a clean connection.
    let next = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(next.clone())
            .await
            .expect("the pool should recover after discarding the timed-out connection"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(pool.status().available, 1);
}

/// Aborting the task while it waits on the row lock drops the in-flight
/// connection instead of returning an unknown transaction state to the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_abort_during_lock_wait_discards_connection() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let input = fresh_issuance(&fixture, tenant_id);
    let application_name = format!("fresh-abort-{}", Uuid::now_v7().simple());
    let pool = create_pool(tagged_database_url(&database_url, &application_name), 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test coordinator should connect");
    coordinator
        .batch_execute("BEGIN")
        .await
        .expect("blocking transaction should begin");
    sql_query("SELECT id FROM oauth_clients WHERE id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold the client row lock");
    let mut observer = AsyncPgConnection::establish(&database_url)
        .await
        .expect("lock observer should connect");
    let issuer_repository = repository.clone();
    let mut issuer =
        tokio::spawn(async move { issuer_repository.commit_token_issuance(input).await });
    wait_for_lock_wait_or_task(&mut observer, &application_name, &mut issuer).await;
    issuer.abort();
    assert!(
        issuer.await.is_err(),
        "the aborted task must join cancelled"
    );
    coordinator
        .batch_execute("ROLLBACK")
        .await
        .expect("coordinator should release the row lock");
    let next = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(next)
            .await
            .expect("the pool should recover after the aborted connection was dropped"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(pool.status().available, 1);
}

/// The runtime role boundary is the real one: a least-privilege role created
/// and granted through `configure_runtime_role` commits the fresh path via
/// the audit function only, while direct ledger table access stays denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_runs_under_the_restricted_runtime_role() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let role = format!("nazotest_rt_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    let mut admin = AsyncPgConnection::establish(&database_url)
        .await
        .expect("admin connection should connect");
    sql_query(format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOINHERIT"
    ))
    .execute(&mut admin)
    .await
    .expect("restricted role should be creatable");
    sql_query(format!("GRANT CONNECT ON DATABASE oauth TO \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("connect grant should apply");
    nazo_postgres::configure_runtime_role(&database_url, &role)
        .await
        .expect("the production grant path should configure the role");

    let restricted_url = {
        let url = url::Url::parse(&database_url).expect("DATABASE_URL should parse");
        let mut url = url.clone();
        url.set_username(&role).expect("username should set");
        url.set_password(Some(&password))
            .expect("password should set");
        url.to_string()
    };
    let repository = TokenIssuanceRepository::new(create_pool(&restricted_url, 2).unwrap());
    let input = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .expect("the restricted runtime role must commit the fresh path"),
        CommitTokenIssuanceResult::Committed
    );
    let mut restricted = AsyncPgConnection::establish(&restricted_url)
        .await
        .expect("restricted connection should connect");
    let denied = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events")
        .get_result::<CountRow>(&mut restricted)
        .await;
    assert!(
        denied.is_err(),
        "the runtime role must keep no direct ledger table privilege"
    );
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("verification connection should connect");
    assert_eq!(
        write_counts(&mut connection, input.issuance_id).await,
        (1, 1),
        "the restricted role writes audit through the function boundary only"
    );
    // The role holds granted privileges (database CONNECT plus the
    // configure_runtime_role grant set); revoke the shared-object grant and
    // drop owned privileges before the role itself can go away.
    sql_query(format!("REVOKE ALL ON DATABASE oauth FROM \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("database grant should be revoked");
    sql_query(format!("DROP OWNED BY \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("owned privileges should be dropped");
    sql_query(format!("DROP ROLE \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("restricted role should be dropped");
}

/// Mid-run privilege revocation must fail the commit, not just the next
/// preflight: with EXECUTE on `nazo_persist_security_audit_event` revoked
/// after a healthy start, the same transaction that writes the ownership
/// row must roll back in full — no issuance row, no audit event — and the
/// pool must not retain an open transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_audit_append_execute_fails_the_fresh_commit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let role = format!("nazotest_revoke_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    let mut admin = AsyncPgConnection::establish(&database_url)
        .await
        .expect("admin connection should connect");
    sql_query(format!(
        "CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOINHERIT"
    ))
    .execute(&mut admin)
    .await
    .expect("restricted role should be creatable");
    sql_query(format!("GRANT CONNECT ON DATABASE oauth TO \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("connect grant should apply");
    nazo_postgres::configure_runtime_role(&database_url, &role)
        .await
        .expect("the production grant path should configure the role");

    let restricted_url = {
        let url = url::Url::parse(&database_url).expect("DATABASE_URL should parse");
        let mut url = url.clone();
        url.set_username(&role).expect("username should set");
        url.set_password(Some(&password))
            .expect("password should set");
        url.to_string()
    };
    let pool = create_pool(&restricted_url, 2).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let first = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(first)
            .await
            .expect("the granted runtime role must commit before the revoke"),
        CommitTokenIssuanceResult::Committed
    );

    sql_query(format!(
        "REVOKE EXECUTE ON FUNCTION \
         public.nazo_persist_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ) \
         FROM \"{role}\""
    ))
    .execute(&mut admin)
    .await
    .expect("EXECUTE revoke should apply");

    let revoked = fresh_issuance(&fixture, tenant_id);
    let result = repository.commit_token_issuance(revoked.clone()).await;
    assert!(
        result.is_err(),
        "revoking append EXECUTE mid-run must fail the commit, got {result:?}"
    );
    assert_no_writes(&database_url, revoked.issuance_id).await;
    let mut verify = AsyncPgConnection::establish(&database_url)
        .await
        .expect("verification connection should connect");
    let open_transactions = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity \
         WHERE usename = $1 AND state = 'idle in transaction'",
    )
    .bind::<sql_types::Text, _>(role.clone())
    .get_result::<CountRow>(&mut verify)
    .await
    .expect("open-transaction count should load")
    .count;
    assert_eq!(
        open_transactions, 0,
        "the failed commit must not return an open transaction to the pool"
    );

    // Recovery: the capability returns and the same pool commits again.
    sql_query(format!(
        "GRANT EXECUTE ON FUNCTION \
         public.nazo_persist_security_audit_event(UUID, TEXT, TEXT, JSONB, TIMESTAMPTZ) \
         TO \"{role}\""
    ))
    .execute(&mut admin)
    .await
    .expect("EXECUTE grant should reapply");
    let recovered = fresh_issuance(&fixture, tenant_id);
    assert_eq!(
        repository
            .commit_token_issuance(recovered.clone())
            .await
            .expect("the pool must recover once the capability is restored"),
        CommitTokenIssuanceResult::Committed
    );
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("verification connection should connect");
    assert_eq!(
        write_counts(&mut connection, recovered.issuance_id).await,
        (1, 1)
    );

    drop(pool);
    sql_query(format!("REVOKE ALL ON DATABASE oauth FROM \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("database grant should be revoked");
    sql_query(format!("DROP OWNED BY \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("owned privileges should be dropped");
    sql_query(format!("DROP ROLE \"{role}\""))
        .execute(&mut admin)
        .await
        .expect("restricted role should be dropped");
}

/// Same-statement audit failure keeps the ownership insert uncommitted:
/// a conflicting pre-existing event id makes the persist function raise,
/// and the issuance row must not survive the rollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_issuance_audit_function_failure_rolls_back_ownership() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let mut admin = AsyncPgConnection::establish(&database_url)
        .await
        .expect("admin connection should connect");
    // A trigger raises for this client's issuance inserts; the trigger runs
    // inside the audit function's INSERT, so the persist call fails after the
    // ownership row was written by the same statement family. Both roll back.
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_fresh_audit_failure_{suffix}");
    let trigger = format!("test_fresh_audit_failure_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'injected audit append failure';
        END
        $$
        "#
    ))
    .execute(&mut admin)
    .await
    .expect("failure function should install");
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 1).unwrap());
    let input = fresh_issuance(&fixture, tenant_id);
    // The trigger must be scoped to this test's issuance: an unguarded
    // blanket trigger would break every concurrent fresh issuance in the
    // shared test database.
    let issuance_id = input.issuance_id;
    sql_query(format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON security_audit_events \
         FOR EACH ROW \
         WHEN (NEW.payload->>'issuance_id' = '{issuance_id}') \
         EXECUTE FUNCTION {function}()"
    ))
    .execute(&mut admin)
    .await
    .expect("failure trigger should install");
    let result = repository.commit_token_issuance(input.clone()).await;
    assert!(
        result.is_err(),
        "an audit append failure must surface an error, got {result:?}"
    );
    sql_query(format!("DROP TRIGGER {trigger} ON security_audit_events"))
        .execute(&mut admin)
        .await
        .expect("failure trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut admin)
        .await
        .expect("failure function should be removed");
    assert_no_writes(&database_url, input.issuance_id).await;
}
