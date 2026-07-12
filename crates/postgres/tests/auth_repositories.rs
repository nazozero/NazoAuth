use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{NewRefreshToken, RefreshTokenPersistResult};
use nazo_postgres::{
    AuditRepository, AuthorizationRepository, GrantRepository, TokenRepository, create_pool,
};
use serde_json::json;
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI auth repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct FixtureIds {
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn fixture(database_url: &str) -> FixtureIds {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let suffix = Uuid::now_v7().simple().to_string();
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    sql_query(format!(
        r#"
        WITH inserted_user AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('auth-repo-{suffix}', 'auth-repo-{suffix}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method
            ) VALUES (
                'auth-repo-{suffix}', 'Auth Repository Test', 'confidential',
                '["https://client.example/callback"]'::jsonb,
                '["openid", "offline_access"]'::jsonb,
                '["authorization_code", "refresh_token"]'::jsonb,
                'client_secret_basic'
            ) RETURNING id
        )
        SELECT inserted_user.id AS user_id, inserted_client.id AS client_id
        FROM inserted_user CROSS JOIN inserted_client
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("auth repository fixture should insert")
}

#[tokio::test]
async fn grants_upsert_cover_and_revoke_tokens_atomically() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let repository = GrantRepository::new(create_pool(&database_url, 4).unwrap());
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    repository
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("grant should insert");
    repository
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("grant should update");
    let stored = repository
        .authorization(fixture.user_id, fixture.client_id)
        .await
        .expect("grant should load")
        .expect("grant should exist");
    assert_eq!(stored.authorization_count, 2);

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            issued_at, expires_at, subject
        ) VALUES (
            '{token_hash}', '{}', '{}', '{}', '["openid", "offline_access"]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}'
        )
        "#,
        Uuid::now_v7(),
        fixture.client_id,
        fixture.user_id,
        fixture.user_id
    ))
    .execute(&mut connection)
    .await
    .expect("active refresh token fixture should insert");
    let revoked = repository
        .revoke(fixture.user_id, fixture.client_id)
        .await
        .expect("grant revocation should commit");
    assert_eq!(revoked.revoked_refresh_tokens, 1);
    assert_eq!(revoked.removed_grants, 1);
}

#[tokio::test]
async fn refresh_rotation_reuse_compromises_the_whole_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();
    let repository = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    let make = |label: &str, rotated_from_id| NewRefreshToken {
        raw_token: format!("auth-repo-{label}-{suffix}"),
        tenant_id,
        family_id,
        rotated_from_id,
        lost_response_retry: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        subject: fixture.user_id.to_string(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };
    assert_eq!(
        repository
            .persist_refresh_token(make("original", None))
            .await
            .expect("original token should persist"),
        RefreshTokenPersistResult::Inserted
    );
    let original = repository
        .by_raw_refresh_token(tenant_id, &format!("auth-repo-original-{suffix}"))
        .await
        .expect("original token should load")
        .expect("original token should exist");
    assert_eq!(
        repository
            .persist_refresh_token(make("successor", Some(original.id)))
            .await
            .expect("successor should rotate"),
        RefreshTokenPersistResult::Inserted
    );
    assert_eq!(
        repository
            .persist_refresh_token(make("reuse", Some(original.id)))
            .await
            .expect("reuse should be classified"),
        RefreshTokenPersistResult::RotationConflict
    );
    assert!(
        !repository
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("family state should load")
    );
}

#[tokio::test]
async fn authorization_code_replay_compensation_revokes_both_token_kinds() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    let access_jti = format!("authorization-replay-{}", Uuid::now_v7());
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            issued_at, expires_at, subject
        ) VALUES (
            '{token_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}'
        )
        "#,
        fixture.client_id, fixture.user_id, fixture.user_id
    ))
    .execute(&mut connection)
    .await
    .expect("authorization replay refresh fixture should insert");

    AuthorizationRepository::new(create_pool(&database_url, 4).unwrap())
        .revoke_issued_tokens(
            tenant_id,
            fixture.client_id,
            &access_jti,
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            Some(family_id),
        )
        .await
        .expect("authorization replay compensation should commit");
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert!(
        tokens
            .access_token_revoked(tenant_id, &access_jti)
            .await
            .unwrap()
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn audit_repository_records_scim_use_and_drives_logout_outbox() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(format!(
        "INSERT INTO scim_tokens (tenant_id, token_hash, label, scopes) VALUES ('{tenant_id}', '{token_hash}', 'audit repository test', '[\"scim:read\"]'::jsonb)"
    ))
    .execute(&mut connection)
    .await
    .expect("SCIM token fixture should insert");
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let credential = repository
        .active_scim_credential(&token_hash)
        .await
        .expect("SCIM credential should load")
        .expect("SCIM credential should exist");
    repository
        .record_scim_token_use(
            credential.id,
            credential.tenant_id,
            &["scim:read".to_owned()],
            Some("a".repeat(64)),
            Some("b".repeat(64)),
        )
        .await
        .expect("SCIM use audit should commit");
    let count =
        sql_query("SELECT COUNT(*) AS count FROM scim_audit_events WHERE scim_token_id = $1")
            .bind::<SqlUuid, _>(credential.id)
            .get_result::<CountRow>(&mut connection)
            .await
            .expect("SCIM audit count should load");
    assert_eq!(count.count, 1);

    repository
        .enqueue_backchannel_logout(
            tenant_id,
            fixture.client_id,
            "audit-repository-client",
            "https://client.example/backchannel-logout",
            "logout-token-test",
            chrono::Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("backchannel delivery should enqueue");
    let claimed = repository
        .claim_due_backchannel_logout(10, 300)
        .await
        .expect("backchannel delivery should claim");
    assert_eq!(claimed.len(), 1);
    repository
        .complete_backchannel_logout(claimed[0].id, claimed[0].attempts)
        .await
        .expect("backchannel delivery should complete");
    assert!(
        repository
            .claim_due_backchannel_logout(10, 300)
            .await
            .expect("completed delivery should not reclaim")
            .is_empty()
    );
}

#[test]
fn server_auth_callers_do_not_query_diesel_or_auth_tables() {
    let server = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../server/src");
    for relative in [
        "domain/rows.rs",
        "http/admin/grants.rs",
        "http/authorization/request/prompt_none.rs",
        "http/fapi_resource.rs",
        "http/profile/oidc_logout.rs",
        "http/scim/auth.rs",
        "http/token/introspect.rs",
        "http/token/issue/authorization_code_state.rs",
        "http/token/issue/refresh_persistence.rs",
        "http/token/native_sso.rs",
        "http/token/refresh.rs",
        "http/token/revoke.rs",
        "http/token/token_exchange.rs",
        "http/token/userinfo.rs",
        "support/oauth.rs",
        "support/views.rs",
    ] {
        let source = std::fs::read_to_string(server.join(relative))
            .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"));
        for forbidden in [
            "diesel::",
            "diesel_async",
            "oauth_tokens::",
            "user_client_grants::",
            "access_token_revocations::",
            "scim_tokens::",
            "scim_audit_events::",
            "backchannel_logout_deliveries::",
        ] {
            assert!(
                !source.contains(forbidden),
                "{relative} retained forbidden persistence token {forbidden}"
            );
        }
    }
    let schema = std::fs::read_to_string(server.join("schema.rs")).expect("server schema reads");
    assert_eq!(
        schema.matches("diesel::table!").count(),
        0,
        "server production schema must not define persistence tables"
    );
}
#[tokio::test]
async fn stale_logout_worker_cannot_complete_or_fail_a_reclaimed_delivery() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let logout_token = format!("logout-reclaim-token-{}", Uuid::now_v7());
    repository
        .enqueue_backchannel_logout(
            tenant_id,
            fixture.client_id,
            &format!("logout-reclaim-{}", Uuid::now_v7()),
            "https://client.example/backchannel-logout",
            &logout_token,
            chrono::Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("delivery should enqueue");
    let first = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("first worker should claim")
        .into_iter()
        .find(|delivery| delivery.logout_token == logout_token)
        .expect("delivery should be due");
    assert_eq!(first.attempts, 1);

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(
        "UPDATE backchannel_logout_deliveries SET locked_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind::<SqlUuid, _>(first.id)
    .execute(&mut connection)
    .await
    .expect("test should expire first claim");
    let second = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("second worker should reclaim")
        .into_iter()
        .find(|delivery| delivery.id == first.id)
        .expect("expired delivery should reclaim");
    assert_eq!(second.id, first.id);
    assert_eq!(second.attempts, 2);

    let stale_complete = repository
        .complete_backchannel_logout(first.id, first.attempts)
        .await;
    assert!(
        matches!(
            stale_complete,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "first worker completion must be rejected after reclaim"
    );
    let stale_fail = repository
        .fail_backchannel_logout(
            first.id,
            first.attempts,
            Some(chrono::Utc::now() + chrono::Duration::seconds(5)),
            "stale failure",
        )
        .await;
    assert!(
        matches!(
            stale_fail,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "first worker failure must be rejected after reclaim"
    );

    repository
        .complete_backchannel_logout(second.id, second.attempts)
        .await
        .expect("current worker should complete");
    let stale_after_terminal = repository
        .fail_backchannel_logout(first.id, first.attempts, None, "late stale failure")
        .await;
    assert!(
        matches!(
            stale_after_terminal,
            Err(nazo_identity::ports::RepositoryError::Consistency(_))
        ),
        "stale worker must not overwrite terminal state"
    );
}

