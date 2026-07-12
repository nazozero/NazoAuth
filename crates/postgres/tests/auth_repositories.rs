use diesel::{QueryableByName, sql_query, sql_types::Uuid as SqlUuid};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_postgres::{GrantRepository, create_pool};
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
