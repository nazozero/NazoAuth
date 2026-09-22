//! Atomic token-issuance commit coverage for the final issuance schema.
//!
//! The `oauth_token_issuances` table is the single durable fence: `Fresh`
//! inserts unconditionally, `SingleUse` inserts under the partial unique
//! index and re-checks the verified grant deadline inside the commit.  A
//! refresh rotation conflict deletes only the current issuance row while the
//! family compromise and the reuse audit commit.

use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken,
    RefreshTokenAuthenticationContext, TokenIssuanceMode, TokenIssuedAuditFields,
    TokenRepositoryPort,
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
) -> NewRefreshToken {
    let issued_at = chrono::Utc::now();
    let authentication_time = chrono::DateTime::from_timestamp(1_700_000_000, 0)
        .expect("fixed authentication time should be valid");
    NewRefreshToken {
        raw_token,
        member_id: Uuid::now_v7(),
        tenant_id,
        family_id,
        rotated_from_id,
        lost_response_retry: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        issued_at,
        expires_at: issued_at + chrono::Duration::hours(1),
        subject: fixture.user_id.to_string(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: RefreshTokenAuthenticationContext {
            version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
            issuer: "https://issuer.example".to_owned(),
            audience: fixture.client_public_id.clone(),
            auth_time: authentication_time.timestamp(),
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
            id_token_sid: None,
            acr: None,
            nonce: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
        },
    }
}

fn issuance(
    fixture: &FixtureIds,
    tenant_id: Uuid,
    mode: TokenIssuanceMode,
    refresh_token: Option<NewRefreshToken>,
) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        issuance_id,
        tenant_id,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        mode,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
        refresh_token,
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
    );
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
            .commit_token_issuance(issuance(
                &fixture,
                tenant_id,
                TokenIssuanceMode::Fresh,
                None
            ))
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
                .commit_token_issuance(issuance(
                    &ids,
                    tenant_id,
                    TokenIssuanceMode::SingleUse {
                        grant_key,
                        grant_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                    },
                    None,
                ))
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
async fn rotation_conflict_deletes_only_the_losing_issuance() {
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
            .commit_token_issuance(issuance(
                &fixture,
                tenant_id,
                TokenIssuanceMode::Fresh,
                Some(root)
            ))
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
    let child_issuance = issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, Some(child));
    assert_eq!(
        repository
            .commit_token_issuance(child_issuance.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    // A second claimant rotating from the same consumed parent loses: its
    // issuance row is deleted, the family compromise commits, and only the
    // reuse audit for this issuance is written.
    let loser_raw = format!("rotation-loser-{}", Uuid::now_v7());
    let loser = refresh_token_fixture(&fixture, tenant_id, family_id, loser_raw, Some(root_id));
    let loser_issuance = issuance(&fixture, tenant_id, TokenIssuanceMode::Fresh, Some(loser));
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
    assert_eq!(rows.count, 0, "the losing issuance row must be deleted");
    let kept = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<sql_types::Uuid, _>(child_issuance.issuance_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(kept.count, 1, "the committed rotation stays");
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
