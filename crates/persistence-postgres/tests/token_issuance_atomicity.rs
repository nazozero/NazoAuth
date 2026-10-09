//! Atomic token-issuance commit coverage for the final issuance schema.
//!
//! Fresh creates no issuance row; SingleUse keeps its durable grant receipt
//! under the partial unique index and rechecks the deadline in the commit.
//! A refresh conflict commits family compromise and reuse audit, with no
//! token-issued event or receipt for the losing request.

#[path = "support/refresh_fixture.rs"]
mod refresh_fixture;
use refresh_fixture::RefreshFixture;

use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, RefreshTokenAuthenticationContext,
    TokenIssuanceMode, TokenIssuedAuditFields, TokenRepositoryPort,
};
use nazo_postgres::{TokenIssuanceRepository, TokenRepository, create_pool};
use serde_json::json;
use uuid::Uuid;

const UP: &str = include_str!("../../../migrations/20260805000500_token_issuance_saga/up.sql");
const DOWN: &str = include_str!("../../../migrations/20260805000500_token_issuance_saga/down.sql");

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
    user_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_public_id: String,
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
        WITH inserted_user AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('issuance-{suffix}', 'issuance-{suffix}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method, security_policy
            ) VALUES (
                'issuance-{suffix}', 'Issuance Atomicity Test', 'confidential',
                '["https://client.example/callback"]'::jsonb,
                '["openid", "offline_access"]'::jsonb,
                '["authorization_code", "refresh_token"]'::jsonb,
                'client_secret_basic',
                '{security_policy}'::jsonb
            ) RETURNING id, client_id
        )
        SELECT inserted_user.id AS user_id, inserted_client.id AS client_id,
               inserted_client.client_id AS client_public_id
        FROM inserted_user CROSS JOIN inserted_client
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("issuance fixture should insert")
}

fn refresh_token_fixture(
    fixture: &FixtureIds,
    tenant_id: Uuid,
    family_id: Uuid,
    raw_token: String,
    rotated_from_id: Option<Uuid>,
) -> RefreshFixture {
    let issued_at = chrono::Utc::now();
    let authentication_time = chrono::DateTime::from_timestamp(1_700_000_000, 0)
        .expect("fixed authentication time should be valid");
    RefreshFixture::new(
        nazo_auth::NewRefreshToken {
            raw_token,
            member_id: Uuid::now_v7(),
            tenant_id,
            family_id,
            rotated_from_id,
            lost_response_retry: None,
            client_id: fixture.client_id,
            user_id: Some(fixture.user_id),
            audiences: vec!["resource://default".to_owned()],
            issued_at,
            expires_at: issued_at + chrono::Duration::hours(1),
            dpop_jkt: None,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
            id_token_sid: None,
        },
        nazo_auth::RefreshContract {
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            audiences: vec!["resource://default".to_owned()],
            authorization_details: json!([]),
            subject: fixture.user_id.to_string(),
            authentication_context: RefreshTokenAuthenticationContext {
                version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
                issuer: "https://issuer.example".to_owned(),
                audience: fixture.client_public_id.clone(),
                auth_time: authentication_time.timestamp(),
                amr: vec!["pwd".to_owned()],
                oidc_sid: None,

                acr: None,

                userinfo_claim_requests: (Vec::new()).into(),
                id_token_claim_requests: (Vec::new()).into(),
            },
        }
        .clone(),
    )
}

async fn issuance(
    fixture: &FixtureIds,
    tenant_id: Uuid,
    mode: TokenIssuanceMode,
    refresh_token: Option<RefreshFixture>,
) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        authorization_id: None,
        native_sso_source: None,
        principal_state: nazo_auth::TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: fixture.user_id.to_string(),
        issuance_id,
        tenant_id,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        mode,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        refresh_token: match refresh_token {
            Some(token) => Some(token.into_commit().await),
            None => None,
        },
        audit_fields: TokenIssuedAuditFields {
            client_id: fixture.client_public_id.clone(),
            subject_hash: blake3::hash(fixture.user_id.to_string().as_bytes())
                .to_hex()
                .to_string(),
            scope: "openid offline_access".to_owned(),
            audience: vec!["resource://default".to_owned()],
        },
    }
}

#[test]
fn final_issuance_schema_is_created_directly_without_legacy_state() {
    for column in [
        "issuance_id UUID PRIMARY KEY",
        "tenant_id UUID NOT NULL REFERENCES tenants(id)",
        "client_id UUID NOT NULL",
        "user_id UUID",
        "single_use_key_blake3 BYTEA",
        "access_token_jti VARCHAR(128) NOT NULL",
        "access_token_expires_at TIMESTAMPTZ NOT NULL",
        "retain_until TIMESTAMPTZ NOT NULL",
    ] {
        assert!(UP.contains(column), "missing column {column}");
    }
    for removed in [
        "grant_key_blake3",
        "request_digest",
        "response_ciphertext",
        "response_digest",
        "response_envelope_version",
        "response_key_id",
        "phase",
        "claim_owner_id",
        "claim_started_at",
    ] {
        assert!(
            !UP.contains(removed),
            "legacy issuance column {removed} must not exist"
        );
    }
    let table_block = UP
        .split("CREATE TABLE")
        .find(|block| block.starts_with(" oauth_token_issuances"))
        .expect("the issuance table must be created directly")
        .split(
            "
);",
        )
        .next()
        .expect("the issuance table definition must terminate");
    for legacy in ["created_at", "updated_at"] {
        assert!(
            !table_block.contains(legacy),
            "legacy issuance column {legacy} must not exist"
        );
    }
    assert!(UP.contains("octet_length(single_use_key_blake3) = 32"));
    assert!(UP.contains("retain_until >= access_token_expires_at"));
    assert!(UP.contains("WHERE single_use_key_blake3 IS NOT NULL"));
    assert!(UP.contains("(retain_until, issuance_id)"));
    assert!(UP.contains("WHERE user_id IS NOT NULL"));
    assert!(UP.contains("nazo_oauth_cleanup_expired_security_state"));
    assert!(UP.contains("FOR UPDATE SKIP LOCKED"));
    assert!(UP.contains("LIMIT 256"));
    assert!(DOWN.contains("cannot roll back"));
    assert!(DOWN.contains("DROP TABLE oauth_token_issuances"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_single_use_grant_rolls_back_everything() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    // A single-connection pool proves the rolled-back transaction's healthy
    // connection returns: a discarded connection would leave `available` at
    // zero, and the follow-up commit could not run on a poisoned one.
    let pool = create_pool(&database_url, 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let raw_token = format!("expired-grant-{}", Uuid::now_v7());
    let token = refresh_token_fixture(&fixture, tenant_id, Uuid::now_v7(), raw_token, None);
    let input = issuance(
        &fixture,
        tenant_id,
        TokenIssuanceMode::SingleUse {
            grant_key: format!("expired-{}", Uuid::now_v7()),
            // The verified grant deadline already elapsed before the commit.
            grant_expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
        },
        Some(token),
    )
    .await;
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::GrantExpired
    );
    assert_eq!(
        pool.status().available,
        1,
        "controlled GrantExpired rollback must return the connection to the pool"
    );
    assert_eq!(
        repository
            .commit_token_issuance(
                issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, None).await
            )
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed,
        "the pooled connection must still serve commits after the controlled rollback"
    );
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    for (table, clause) in [
        (
            "oauth_token_issuances",
            format!("issuance_id = '{}'", input.issuance_id),
        ),
        (
            "security_audit_events",
            format!("payload->>'issuance_id' = '{}'", input.issuance_id),
        ),
    ] {
        let count = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE {clause}"
        ))
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
        assert_eq!(count.count, 0, "{table} must roll back");
    }
    let tokens = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE client_id = $1",
    )
    .bind::<sql_types::Uuid, _>(fixture.client_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(tokens.count, 0, "the refresh token must roll back too");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_single_use_commits_commit_exactly_once() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let grant_key = format!("raced-grant-{}", Uuid::now_v7());
    let repository = std::sync::Arc::new(TokenIssuanceRepository::new(
        create_pool(&database_url, 4).unwrap(),
    ));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let repository = repository.clone();
        let fixture_client = fixture.client_id;
        let fixture_user = fixture.user_id;
        let fixture_public = fixture.client_public_id.clone();
        let grant_key = grant_key.clone();
        handles.push(tokio::spawn(async move {
            let ids = FixtureIds {
                user_id: fixture_user,
                client_id: fixture_client,
                client_public_id: fixture_public,
            };
            repository
                .commit_token_issuance(
                    issuance(
                        &ids,
                        tenant_id,
                        TokenIssuanceMode::SingleUse {
                            grant_key,
                            grant_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                        },
                        None,
                    )
                    .await,
                )
                .await
        }));
    }
    let mut committed = 0_usize;
    let mut already_used = 0_usize;
    for handle in handles {
        match handle.await.unwrap().unwrap() {
            CommitTokenIssuanceResult::Committed => committed += 1,
            CommitTokenIssuanceResult::AlreadyUsed => already_used += 1,
            other => panic!("unexpected single-use commit result {other:?}"),
        }
    }
    assert_eq!(committed, 1, "exactly one request may commit");
    assert_eq!(already_used, 3, "every loser must see AlreadyUsed");
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(fixture.client_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(rows.count, 1);
    let audits = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE payload->>'event_category' = 'token_lifecycle' AND payload->>'tenant_id' = $1 AND payload->>'client_id' = $2")
        .bind::<sql_types::Text, _>(tenant_id.to_string())
        .bind::<sql_types::Text, _>(fixture.client_public_id.clone())
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
    assert_eq!(audits.count, 1, "only the winner writes token_issued");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_conflict_keeps_family_compromise_and_only_reuse_audit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    let family_id = Uuid::now_v7();
    let root_raw = format!("rotation-root-{}", Uuid::now_v7());
    let root = refresh_token_fixture(&fixture, tenant_id, family_id, root_raw.clone(), None);
    assert_eq!(
        repository
            .commit_token_issuance(
                issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, Some(root)).await
            )
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let root_id = tokens
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap()
        .id;
    let child_raw = format!("rotation-child-{}", Uuid::now_v7());
    let child = refresh_token_fixture(&fixture, tenant_id, family_id, child_raw, Some(root_id));
    let child_issuance = issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, Some(child)).await;
    assert_eq!(
        repository
            .commit_token_issuance(child_issuance.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    // A second claimant rotating from the same consumed parent loses: its
    // Fresh path creates no receipt, the family compromise commits, and only the
    // reuse audit for this issuance is written.
    let loser_raw = format!("rotation-loser-{}", Uuid::now_v7());
    let loser = refresh_token_fixture(&fixture, tenant_id, family_id, loser_raw, Some(root_id));
    let loser_issuance = issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, Some(loser)).await;
    assert_eq!(
        repository
            .commit_token_issuance(loser_issuance.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::RotationConflict
    );
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<sql_types::Uuid, _>(loser_issuance.issuance_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(rows.count, 0, "Fresh rotation must create no issuance row");
    let kept = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type = 'token_issued' AND payload->>'issuance_id' = $1",
    )
    .bind::<sql_types::Text, _>(child_issuance.issuance_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(kept.count, 1, "the committed rotation audit stays");
    let reuse_audit = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE event_type = 'refresh_reuse_detected' AND payload->>'issuance_id' = $1",
    )
    .bind::<sql_types::Text, _>(loser_issuance.issuance_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(reuse_audit.count, 1);
    let issued_audit = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE event_type = 'token_issued' AND payload->>'issuance_id' = $1",
    )
    .bind::<sql_types::Text, _>(loser_issuance.issuance_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        issued_audit.count, 0,
        "the loser must not audit a token issue"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_transaction_executes_on_the_connection_pool_runtime() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let pool = create_pool(&database_url, 1).unwrap();
    let owner = tokio::runtime::Handle::current().id();
    let runtimes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observations = runtimes.clone();
    let mut connection = nazo_postgres::get_conn(&pool).await.unwrap();
    connection.set_instrumentation(move |event: diesel::connection::InstrumentationEvent<'_>| {
        if matches!(
            event,
            diesel::connection::InstrumentationEvent::StartQuery { .. }
        ) {
            observations
                .lock()
                .unwrap()
                .push(tokio::runtime::Handle::current().id());
        }
    });
    drop(connection);
    let input = issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, None).await;
    let repository = TokenIssuanceRepository::new(pool);
    let result = tokio::task::spawn_blocking(move || {
        let borrower = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_ne!(borrower.handle().id(), owner);
        borrower.block_on(repository.commit_token_issuance(input))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let observed = runtimes.lock().unwrap();
    assert!(
        observed.len() >= 3,
        "must observe the transaction, principal checks and audit"
    );
    assert!(
        observed.iter().all(|runtime| *runtime == owner),
        "every statement must execute on the pool runtime: {observed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_issuance_on_pool_runtime_discards_the_blocked_connection() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let pool = create_pool(&database_url, 1).unwrap();
    let repository = TokenIssuanceRepository::new(pool.clone());
    let input = issuance(
        &fixture,
        tenant_id,
        TokenIssuanceMode::SingleUse {
            grant_key: format!("cancelled-{}", Uuid::now_v7()),
            grant_expires_at: chrono::Utc::now() + chrono::Duration::minutes(1),
        },
        None,
    )
    .await;
    let retry = input.clone();
    let mut locker = AsyncPgConnection::establish(&database_url).await.unwrap();
    let backend = sql_query("SELECT pg_backend_pid()::bigint AS count")
        .get_result::<CountRow>(&mut locker)
        .await
        .unwrap()
        .count;
    sql_query("BEGIN").execute(&mut locker).await.unwrap();
    sql_query("SELECT id FROM oauth_clients WHERE id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut locker)
        .await
        .unwrap();
    // Observe outside the lock-holding transaction: PostgreSQL caches its
    // statistics snapshot until that transaction ends.
    let mut observer = AsyncPgConnection::establish(&database_url).await.unwrap();
    let issuer = repository.clone();
    let operation = tokio::spawn(async move { issuer.commit_token_issuance(input).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let blocked = sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))")
                .bind::<sql_types::BigInt, _>(backend).get_result::<CountRow>(&mut observer).await.unwrap().count;
            if blocked > 0 { break; }
            assert!(!operation.is_finished(), "issuance must wait for the principal lock");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("issuance must reach the blocked transaction");
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while pool.status().size != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled transaction must discard its physical connection");
    sql_query("ROLLBACK").execute(&mut locker).await.unwrap();
    assert_eq!(
        repository.commit_token_issuance(retry).await.unwrap(),
        CommitTokenIssuanceResult::Committed,
        "cancellation must not leave a receipt or poison the next checkout"
    );
}

async fn native_source_fixture(url: &str) -> (FixtureIds, RefreshFixture, TokenIssuanceRepository) {
    let owner = fixture(url).await;
    let tenant = nazo_identity::TenantContext::default_system()
        .tenant_id
        .as_uuid();
    let mut source = refresh_token_fixture(
        &owner,
        tenant,
        Uuid::now_v7(),
        format!("native-source-{}", Uuid::now_v7()),
        None,
    );
    source.issued_at -= chrono::Duration::minutes(20);
    let repo = TokenIssuanceRepository::new(create_pool(url, 8).unwrap());
    assert_eq!(
        repo.commit_token_issuance(
            issuance(
                &owner,
                tenant,
                TokenIssuanceMode::Fresh,
                Some(source.clone())
            )
            .await
        )
        .await
        .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    (owner, source, repo)
}

async fn native_destination(
    source: &FixtureIds,
    token: &RefreshFixture,
    destination: &FixtureIds,
) -> CommitTokenIssuance {
    let mut fresh = refresh_token_fixture(
        destination,
        token.tenant_id,
        Uuid::now_v7(),
        format!("native-destination-{}", Uuid::now_v7()),
        None,
    );
    // Exercise rollback of a newly inserted private subject binding too.
    fresh.contract.subject = format!("native-private-{}", destination.client_id);
    let mut input = issuance(
        destination,
        token.tenant_id,
        TokenIssuanceMode::Fresh,
        Some(fresh),
    )
    .await;
    input.subject = format!("native-private-{}", destination.client_id);
    input.native_sso_source = Some(nazo_auth::NativeSsoSourceFence {
        tenant_id: token.tenant_id,
        user_id: source.user_id,
        source_client_id: source.client_public_id.clone(),
        family_id: token.family_id,
        device_secret_expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    });
    input
}

async fn assert_native_destination_rolled_back(url: &str, input: &CommitTokenIssuance) {
    let mut conn = AsyncPgConnection::establish(url).await.unwrap();
    let family = input.refresh_token.as_ref().unwrap().family_id();
    for (table, clause) in [
        (
            "oauth_refresh_families",
            format!("token_family_id='{family}'"),
        ),
        (
            "security_audit_events",
            format!("payload->>'issuance_id'='{}'", input.issuance_id),
        ),
        (
            "oauth_subject_bindings",
            format!("subject='{}'", input.subject),
        ),
    ] {
        let count = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE {clause}"
        ))
        .get_result::<CountRow>(&mut conn)
        .await
        .unwrap()
        .count;
        assert_eq!(
            count, 0,
            "{table} must roll back on invalid Native SSO authority"
        );
    }
}

async fn fill_native_capacity(
    owner: &FixtureIds,
    tenant: Uuid,
    repo: &TokenIssuanceRepository,
    count: usize,
) {
    for index in 0..count {
        let mut sibling = refresh_token_fixture(
            owner,
            tenant,
            Uuid::now_v7(),
            format!("native-sibling-{index}-{}", Uuid::now_v7()),
            None,
        );
        sibling.issued_at -= chrono::Duration::minutes(10 - index as i64);
        assert_eq!(
            repo.commit_token_issuance(
                issuance(owner, tenant, TokenIssuanceMode::Fresh, Some(sibling)).await
            )
            .await
            .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
    }
}

async fn native_active_count(url: &str, client: Uuid) -> i64 {
    let mut conn = AsyncPgConnection::establish(url).await.unwrap();
    sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE client_id=$1 AND revoked_at IS NULL AND reuse_detected_at IS NULL")
        .bind::<sql_types::Uuid,_>(client).get_result::<CountRow>(&mut conn).await.unwrap().count
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_revoked_after_preparation_rolls_back_destination() {
    let Some(url) = database_url() else {
        return;
    };
    let (source, token, repo) = native_source_fixture(&url).await;
    let mut target = fixture(&url).await;
    target.user_id = source.user_id;
    fill_native_capacity(&target, token.tenant_id, &repo, 10).await;
    let mut conn = AsyncPgConnection::establish(&url).await.unwrap();
    let before_audit = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE payload->>'client_id'=$1")
        .bind::<sql_types::Text,_>(&target.client_public_id).get_result::<CountRow>(&mut conn).await.unwrap().count;
    let input = native_destination(&source, &token, &target).await;
    assert!(
        repo.refresh_family_active(token.tenant_id, token.family_id, source.user_id)
            .await
            .unwrap()
    );
    assert_eq!(
        repo.revoke_token(nazo_auth::TokenRevocation {
            tenant_id: token.tenant_id,
            client_id: source.client_id,
            raw_token: &token.raw_token,
            access_token: None
        })
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        repo.commit_token_issuance(input.clone()).await.unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert_native_destination_rolled_back(&url, &input).await;
    assert_eq!(
        native_active_count(&url, target.client_id).await,
        10,
        "destination capacity retirement must roll back"
    );
    let after_audit = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE payload->>'client_id'=$1")
        .bind::<sql_types::Text,_>(&target.client_public_id).get_result::<CountRow>(&mut conn).await.unwrap().count;
    assert_eq!(
        after_audit, before_audit,
        "capacity retirement audit must roll back too"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_normal_member_rotation_does_not_invalidate_family_authority() {
    let Some(url) = database_url() else {
        return;
    };
    let (source, token, repo) = native_source_fixture(&url).await;
    let mut target = fixture(&url).await;
    target.user_id = source.user_id;
    let input = native_destination(&source, &token, &target).await;
    let rotation = refresh_token_fixture(
        &source,
        token.tenant_id,
        token.family_id,
        format!("native-rotated-{}", Uuid::now_v7()),
        Some(token.member_id),
    );
    assert_eq!(
        repo.commit_token_issuance(
            issuance(
                &source,
                token.tenant_id,
                TokenIssuanceMode::Fresh,
                Some(rotation)
            )
            .await
        )
        .await
        .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(
        repo.commit_token_issuance(input).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_busy_nowait_rolls_back_and_returns_retryable_dependency_failure() {
    let Some(url) = database_url() else {
        return;
    };
    let (source, token, repo) = native_source_fixture(&url).await;
    let mut target = fixture(&url).await;
    target.user_id = source.user_id;
    let input = native_destination(&source, &token, &target).await;
    let mut locker = AsyncPgConnection::establish(&url).await.unwrap();
    sql_query("BEGIN").execute(&mut locker).await.unwrap();
    sql_query(
        "SELECT token_family_id FROM oauth_refresh_families WHERE token_family_id=$1 FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(token.family_id)
    .execute(&mut locker)
    .await
    .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        repo.commit_token_issuance(input.clone()),
    )
    .await
    .expect("NOWAIT must not await source lock release");
    sql_query("ROLLBACK").execute(&mut locker).await.unwrap();
    assert_eq!(result, Err(nazo_auth::TokenPortError::Unavailable));
    assert_native_destination_rolled_back(&url, &input).await;
    assert_eq!(
        repo.commit_token_issuance(input).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_same_client_capacity_transfer_requires_own_live_retirement() {
    let Some(url) = database_url() else {
        return;
    };
    for pre_revoked in [false, true] {
        let (source, token, repo) = native_source_fixture(&url).await;
        for index in 0..9 {
            let mut sibling = refresh_token_fixture(
                &source,
                token.tenant_id,
                Uuid::now_v7(),
                format!("native-cap-{index}-{}", Uuid::now_v7()),
                None,
            );
            sibling.issued_at -= chrono::Duration::minutes(10 - index);
            assert_eq!(
                repo.commit_token_issuance(
                    issuance(
                        &source,
                        token.tenant_id,
                        TokenIssuanceMode::Fresh,
                        Some(sibling)
                    )
                    .await
                )
                .await
                .unwrap(),
                CommitTokenIssuanceResult::Committed
            );
        }
        if pre_revoked {
            repo.revoke_token(nazo_auth::TokenRevocation {
                tenant_id: token.tenant_id,
                client_id: source.client_id,
                raw_token: &token.raw_token,
                access_token: None,
            })
            .await
            .unwrap();
        }
        let input = native_destination(&source, &token, &source).await;
        let result = repo.commit_token_issuance(input.clone()).await.unwrap();
        if pre_revoked {
            assert_eq!(result, CommitTokenIssuanceResult::RefreshGrantUnavailable);
            assert_native_destination_rolled_back(&url, &input).await;
        } else {
            assert_eq!(result, CommitTokenIssuanceResult::Committed);
            assert!(
                !repo
                    .refresh_family_active(token.tenant_id, token.family_id, source.user_id)
                    .await
                    .unwrap(),
                "the original oldest-first capacity policy must still retire the source"
            );
            let mut conn = AsyncPgConnection::establish(&url).await.unwrap();
            let active = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE client_id=$1 AND revoked_at IS NULL AND reuse_detected_at IS NULL")
                .bind::<sql_types::Uuid,_>(source.client_id).get_result::<CountRow>(&mut conn).await.unwrap().count;
            assert_eq!(active, 10);
        }
    }
}

async fn wait_for_fixture_blocker(conn: &mut AsyncPgConnection, backend: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))")
                .bind::<sql_types::BigInt,_>(backend).get_result::<CountRow>(conn).await.unwrap().count > 0 { return; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.expect("fixture operation must reach the held lock");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_and_device_secret_expiry_are_rechecked_after_destination_wait() {
    let Some(url) = database_url() else {
        return;
    };
    for source_expires in [false, true] {
        let (source, token, repo) = native_source_fixture(&url).await;
        let mut target = fixture(&url).await;
        target.user_id = source.user_id;
        let mut input = native_destination(&source, &token, &target).await;
        let deadline = chrono::Utc::now() + chrono::Duration::milliseconds(300);
        let mut locker = AsyncPgConnection::establish(&url).await.unwrap();
        if source_expires {
            sql_query(
                "UPDATE oauth_refresh_families SET current_expires_at=$1 WHERE token_family_id=$2",
            )
            .bind::<sql_types::Timestamptz, _>(deadline)
            .bind::<sql_types::Uuid, _>(token.family_id)
            .execute(&mut locker)
            .await
            .unwrap();
        } else {
            input
                .native_sso_source
                .as_mut()
                .unwrap()
                .device_secret_expires_at = deadline;
        }
        let backend = sql_query("SELECT pg_backend_pid()::bigint AS count")
            .get_result::<CountRow>(&mut locker)
            .await
            .unwrap()
            .count;
        sql_query("BEGIN").execute(&mut locker).await.unwrap();
        sql_query("SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE")
            .bind::<sql_types::Uuid, _>(target.client_id)
            .execute(&mut locker)
            .await
            .unwrap();
        let issuer = repo.clone();
        let candidate = input.clone();
        let operation = tokio::spawn(async move { issuer.commit_token_issuance(candidate).await });
        let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
        wait_for_fixture_blocker(&mut observer, backend).await;
        let remaining = deadline
            .signed_duration_since(chrono::Utc::now())
            .num_milliseconds()
            .max(0) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(remaining + 20)).await;
        sql_query("ROLLBACK").execute(&mut locker).await.unwrap();
        assert_eq!(
            operation.await.unwrap().unwrap(),
            CommitTokenIssuanceResult::RefreshGrantUnavailable
        );
        assert_native_destination_rolled_back(&url, &input).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_share_lock_holds_through_required_audit_and_commit() {
    let Some(url) = database_url() else {
        return;
    };
    let (source, token, repo) = native_source_fixture(&url).await;
    let mut target = fixture(&url).await;
    target.user_id = source.user_id;
    let input = native_destination(&source, &token, &target).await;
    let name = format!("native_commit_gate_{}", Uuid::now_v7().simple());
    let gate = input.issuance_id.as_u128() as i64;
    let mut locker = AsyncPgConnection::establish(&url).await.unwrap();
    let backend = sql_query("SELECT pg_backend_pid()::bigint AS count")
        .get_result::<CountRow>(&mut locker)
        .await
        .unwrap()
        .count;
    sql_query(format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NEW; END $$"))
        .execute(&mut locker).await.unwrap();
    sql_query(format!("CREATE TRIGGER {name} BEFORE INSERT ON security_audit_events FOR EACH ROW WHEN (NEW.payload->>'issuance_id'='{}') EXECUTE FUNCTION {name}()", input.issuance_id))
        .execute(&mut locker).await.unwrap();
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<sql_types::BigInt, _>(gate)
        .execute(&mut locker)
        .await
        .unwrap();
    let issuer = repo.clone();
    let candidate = input.clone();
    let operation = tokio::spawn(async move { issuer.commit_token_issuance(candidate).await });
    let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
    wait_for_fixture_blocker(&mut observer, backend).await;
    let issuer = repo.clone();
    let raw = token.raw_token.clone();
    let tenant = token.tenant_id;
    let client = source.client_id;
    let revocation = tokio::spawn(async move {
        issuer
            .revoke_token(nazo_auth::TokenRevocation {
                tenant_id: tenant,
                client_id: client,
                raw_token: &raw,
                access_token: None,
            })
            .await
    });
    // The audit gate has one waiter; source UPDATE must add a second blocked
    // operation rather than finish while the source SHARE lock is held.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let blocked = sql_query("SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid))>0")
                .get_result::<CountRow>(&mut observer).await.unwrap().count;
            if blocked >= 2 { break; }
            assert!(!revocation.is_finished(), "source revocation must wait until destination commits");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.expect("source revocation must block behind final fence");
    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<sql_types::BigInt, _>(gate)
        .execute(&mut locker)
        .await
        .unwrap();
    let committed = operation.await.unwrap();
    let revoked = revocation.await.unwrap();
    sql_query(format!("DROP TRIGGER {name} ON security_audit_events"))
        .execute(&mut locker)
        .await
        .unwrap();
    sql_query(format!("DROP FUNCTION {name}()"))
        .execute(&mut locker)
        .await
        .unwrap();
    assert_eq!(committed.unwrap(), CommitTokenIssuanceResult::Committed);
    assert_eq!(revoked.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_source_cross_client_capacity_and_maintenance_complete_without_deadlock() {
    use nazo_persistence::SecurityStateMaintenancePort;
    let Some(url) = database_url() else {
        return;
    };
    let (one, token_one, repo) = native_source_fixture(&url).await;
    let mut two = fixture(&url).await;
    two.user_id = one.user_id;
    let mut token_two = refresh_token_fixture(
        &two,
        token_one.tenant_id,
        Uuid::now_v7(),
        format!("native-opposing-source-{}", Uuid::now_v7()),
        None,
    );
    token_two.issued_at -= chrono::Duration::minutes(20);
    assert_eq!(
        repo.commit_token_issuance(
            issuance(
                &two,
                token_one.tenant_id,
                TokenIssuanceMode::Fresh,
                Some(token_two.clone())
            )
            .await
        )
        .await
        .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    fill_native_capacity(&one, token_one.tenant_id, &repo, 9).await;
    fill_native_capacity(&two, token_one.tenant_id, &repo, 9).await;
    let into_two = native_destination(&one, &token_one, &two).await;
    let into_one = native_destination(&two, &token_two, &one).await;
    let maintenance =
        nazo_postgres::SecurityStateMaintenanceRepository::new(create_pool(&url, 2).unwrap());
    let (a, b, cleanup) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            repo.commit_token_issuance(into_two.clone()),
            repo.commit_token_issuance(into_one.clone()),
            maintenance.cleanup_batch()
        )
    })
    .await
    .expect("opposing capacity exchanges and bounded maintenance must not deadlock");
    cleanup.expect("isolated maintenance should complete");
    let mut successes = 0;
    for (result, input) in [(a, &into_two), (b, &into_one)] {
        match result {
            Ok(CommitTokenIssuanceResult::Committed) => successes += 1,
            Ok(CommitTokenIssuanceResult::RefreshGrantUnavailable)
            | Err(nazo_auth::TokenPortError::Unavailable) => {
                assert_native_destination_rolled_back(&url, input).await
            }
            other => panic!("unexpected opposing exchange result: {other:?}"),
        }
    }
    assert!(
        successes <= 1,
        "retiring a source must prevent the opposing exchange"
    );
    assert_eq!(native_active_count(&url, one.client_id).await, 10);
    assert_eq!(native_active_count(&url, two.client_id).await, 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorization_code_identity_fences_concurrent_holders_and_refresh_families() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let code_identity = format!("authorization_code:v2:fixture-{}", Uuid::now_v7());
    let repository = std::sync::Arc::new(TokenIssuanceRepository::new(
        create_pool(&database_url, 4).unwrap(),
    ));
    let mut handles = Vec::new();
    for index in 0..4 {
        let repository = repository.clone();
        let ids = FixtureIds {
            user_id: fixture.user_id,
            client_id: fixture.client_id,
            client_public_id: fixture.client_public_id.clone(),
        };
        let code_identity = code_identity.clone();
        handles.push(tokio::spawn(async move {
            let refresh = refresh_token_fixture(
                &ids,
                tenant_id,
                Uuid::now_v7(),
                Uuid::now_v7().to_string(),
                None,
            );
            let holder = nazo_auth::AuthorizationCodeHolderEvidence::from_verified_requirements(
                nazo_auth::AuthorizationCodeClientAuthentication::Authenticated,
                Some("original-verified-pkce".to_owned()),
                Some(format!("validated-key-{index}")),
                None,
                None,
            )
            .unwrap();
            let mut input = issuance(
                &ids,
                tenant_id,
                TokenIssuanceMode::AuthorizationCode {
                    code_identity,
                    grant_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                    holder: holder.clone(),
                },
                Some(refresh),
            )
            .await;
            input.audit_fields.audience = vec![format!("resource://subset-{index}")];
            let result = repository.commit_token_issuance(input).await.unwrap();
            (result, holder)
        }));
    }
    let mut winner = None;
    let mut rejected = 0;
    for handle in handles {
        let (result, holder) = handle.await.unwrap();
        match result {
            CommitTokenIssuanceResult::Committed => {
                assert!(winner.replace(holder).is_none());
            }
            CommitTokenIssuanceResult::AlreadyUsed => rejected += 1,
            other => panic!("unexpected code commit result {other:?}"),
        }
    }
    assert_eq!(rejected, 3);
    let receipt = repository
        .single_use_redemption(tenant_id, fixture.client_id, &code_identity)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.authorization_code_holder, winner);
    assert!(receipt.refresh_token_family_id.is_some());
    assert!(
        repository
            .single_use_redemption(Uuid::now_v7(), fixture.client_id, &code_identity)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .single_use_redemption(tenant_id, Uuid::now_v7(), &code_identity)
            .await
            .unwrap()
            .is_none()
    );
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    for table in ["oauth_token_issuances", "oauth_refresh_families"] {
        let count = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE tenant_id=$1 AND client_id=$2"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(fixture.client_id)
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
        assert_eq!(
            count.count, 1,
            "a losing holder must not create another {table} row"
        );
    }
    let audits = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE event_type='token_issued' AND payload->>'client_id'=$1",
    )
    .bind::<sql_types::Text, _>(&fixture.client_public_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(audits.count, 1);
}

#[tokio::test]
async fn authorization_code_receipt_migration_preserves_legacy_and_rejects_old_writers() {
    use diesel_async::SimpleAsyncConnection;
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let schema = format!("code_receipt_{}", Uuid::now_v7().simple());
    // This transaction owns the whole copied schema. Public tables are read
    // only; rollback removes every fixture object even if the test is aborted.
    connection
        .batch_execute(&format!(
            "BEGIN; CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}, public; \
             CREATE TABLE oauth_token_issuances (LIKE public.oauth_token_issuances INCLUDING ALL); \
             ALTER TABLE oauth_token_issuances DROP CONSTRAINT oauth_token_issuances_receipt_contract_check, \
             DROP COLUMN authorization_code_holder, DROP COLUMN receipt_contract_version;"
        ))
        .await
        .unwrap();
    let legacy_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    let client = Uuid::now_v7();
    let legacy_digest = blake3::hash(b"historical-request-digest-not-invertible");
    let legacy_insert = "INSERT INTO oauth_token_issuances \
        (issuance_id,tenant_id,client_id,single_use_key_blake3,access_token_jti,access_token_expires_at,retain_until) \
        VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '1 hour')";
    sql_query(legacy_insert)
        .bind::<sql_types::Uuid, _>(legacy_id)
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Binary, _>(legacy_digest.as_bytes().as_slice())
        .bind::<sql_types::Text, _>("historical-jti")
        .execute(&mut connection)
        .await
        .unwrap();
    let up = include_str!("../../../migrations/20261003000100_authorization_code_identity/up.sql");
    let down =
        include_str!("../../../migrations/20261003000100_authorization_code_identity/down.sql");
    connection.batch_execute(up).await.unwrap();
    #[derive(QueryableByName)]
    struct LegacyReceipt {
        #[diesel(sql_type = sql_types::Binary)]
        single_use_key_blake3: Vec<u8>,
        #[diesel(sql_type = sql_types::SmallInt)]
        receipt_contract_version: i16,
        #[diesel(sql_type = sql_types::Nullable<sql_types::Jsonb>)]
        authorization_code_holder: Option<serde_json::Value>,
    }
    let legacy = sql_query("SELECT single_use_key_blake3, receipt_contract_version, authorization_code_holder FROM oauth_token_issuances WHERE issuance_id=$1")
        .bind::<sql_types::Uuid, _>(legacy_id)
        .get_result::<LegacyReceipt>(&mut connection)
        .await
        .unwrap();
    assert_eq!(legacy.single_use_key_blake3, legacy_digest.as_bytes());
    assert_eq!(legacy.receipt_contract_version, 0);
    assert!(
        legacy.authorization_code_holder.is_none(),
        "never guess a legacy code or proof mask"
    );
    connection
        .batch_execute("SAVEPOINT legacy_writer")
        .await
        .unwrap();
    let old_writer = sql_query(legacy_insert)
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Binary, _>(
            blake3::hash(b"second-old-request-key")
                .as_bytes()
                .as_slice(),
        )
        .bind::<sql_types::Text, _>("forbidden-old-writer-jti")
        .execute(&mut connection)
        .await;
    assert!(matches!(
        old_writer,
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::CheckViolation,
            _
        ))
    ));
    connection
        .batch_execute("ROLLBACK TO SAVEPOINT legacy_writer")
        .await
        .unwrap();
    let current_id = Uuid::now_v7();
    sql_query("INSERT INTO oauth_token_issuances (issuance_id,tenant_id,client_id,single_use_key_blake3,access_token_jti,access_token_expires_at,retain_until,receipt_contract_version) VALUES ($1,$2,$3,$4,'current-jti',clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '1 hour',2)")
        .bind::<sql_types::Uuid, _>(current_id)
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Binary, _>(blake3::hash(b"current-code-identity").as_bytes().as_slice())
        .execute(&mut connection)
        .await
        .unwrap();
    connection
        .batch_execute("SAVEPOINT rollback_guard")
        .await
        .unwrap();
    assert!(
        connection.batch_execute(down).await.is_err(),
        "a live v2 fence blocks schema rollback"
    );
    connection
        .batch_execute("ROLLBACK TO SAVEPOINT rollback_guard")
        .await
        .unwrap();
    let rows = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances")
        .get_result::<CountRow>(&mut connection)
        .await
        .unwrap();
    assert_eq!(rows.count, 2);
    sql_query("DELETE FROM oauth_token_issuances WHERE issuance_id=$1")
        .bind::<sql_types::Uuid, _>(current_id)
        .execute(&mut connection)
        .await
        .unwrap();
    connection.batch_execute(down).await.unwrap();
    connection.batch_execute(up).await.unwrap();
    let legacy = sql_query("SELECT single_use_key_blake3, receipt_contract_version, authorization_code_holder FROM oauth_token_issuances WHERE issuance_id=$1")
        .bind::<sql_types::Uuid, _>(legacy_id)
        .get_result::<LegacyReceipt>(&mut connection)
        .await
        .unwrap();
    assert_eq!(legacy.single_use_key_blake3, legacy_digest.as_bytes());
    assert_eq!(legacy.receipt_contract_version, 0);
    assert!(legacy.authorization_code_holder.is_none());
    connection.batch_execute("ROLLBACK").await.unwrap();
}
