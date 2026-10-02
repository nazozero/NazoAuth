//! Real PostgreSQL restore coverage and append-only receipt regressions.
use chrono::{Duration, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_identity::ports::RepositoryError;
use nazo_postgres::{TokenRepository, create_pool};
use uuid::Uuid;

mod support;

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

async fn isolated() -> Option<(String, String)> {
    let base = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL")).ok();
    let Some(base) = base else {
        assert!(std::env::var_os("CI").is_none(), "CI restore coverage requires PostgreSQL");
        return None;
    };
    let schema = format!("restore_coverage_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&base).await.unwrap();
    connection.batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
    let url = support::schema_database_url(&base, &schema);
    support::run_isolated_application_migrations(&url).await;
    Some((url, schema))
}

async fn count(connection: &mut AsyncPgConnection, sql: &str) -> i64 {
    sql_query(sql).get_result::<Count>(connection).await.unwrap().count
}

// Seed the actual migrated tables, including tenant/client/user composite FKs.
// Client-subject families have no user. No active-directory filter may hide them.
async fn family(connection: &mut AsyncPgConnection, tenant: Uuid, client_subject: bool) {
    let realm = Uuid::now_v7();
    let organization = Uuid::now_v7();
    let client = Uuid::now_v7();
    let user = Uuid::now_v7();
    let family = Uuid::now_v7();
    connection.batch_execute(&format!(
        "INSERT INTO tenants (id, slug, display_name)
         VALUES ('{tenant}', '{tenant}', 'restore fixture') ON CONFLICT (id) DO NOTHING;
         INSERT INTO realms (id, tenant_id, slug, display_name)
         VALUES ('{realm}', '{tenant}', '{realm}', 'restore fixture');
         INSERT INTO organizations (id, tenant_id, slug, display_name)
         VALUES ('{organization}', '{tenant}', '{organization}', 'restore fixture');
         INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, password_hash)
         VALUES ('{user}', '{tenant}', '{realm}', '{organization}', '{user}', '{user}@example.test', 'fixture');
         INSERT INTO oauth_clients (id, tenant_id, realm_id, organization_id, client_id, client_name,
           client_type, redirect_uris, scopes, grant_types, token_endpoint_auth_method, security_policy)
         VALUES ('{client}', '{tenant}', '{realm}', '{organization}', '{client}', 'restore fixture',
           'confidential', '[\"https://client.example/callback\"]', '[\"openid\",\"offline_access\"]',
           '[\"authorization_code\",\"refresh_token\"]', 'client_secret_basic',
           '{{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,
             \"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,
             \"session_management\":false,\"allow_cross_device_flows\":false,
             \"allow_confidential_oidc_without_pkce\":false}}');"
    )).await.unwrap();
    let contract = serde_json::json!({
        "subject": if client_subject { client.to_string() } else { user.to_string() },
        "scopes": ["openid", "offline_access"], "audiences": ["resource://restore"],
        "authorization_details": [],
        "authentication_context": {"version": 1, "issuer": "https://issuer.example",
            "audience": client.to_string(), "auth_time": 1_700_000_000, "amr": ["pwd"],
            "userinfo_claims": [], "id_token_claims": []}
    });
    let digest = blake3::hash(client.as_bytes()).as_bytes().to_vec();
    sql_query("INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract) VALUES ($1,$2,$3)")
        .bind::<sql_types::Uuid,_>(tenant).bind::<sql_types::Binary,_>(&digest)
        .bind::<sql_types::Jsonb,_>(contract).execute(connection).await.unwrap();
    sql_query("INSERT INTO oauth_refresh_families (tenant_id, token_family_id, client_id, user_id,
        contract_blake3, current_member_id, current_token_blake3, current_audience,
        current_issued_at, current_expires_at)
        VALUES ($1,$2,$3,$4,$5,$2,$5,'[\"resource://restore\"]',NOW()-INTERVAL '2 hours',NOW()-INTERVAL '1 hour')")
        .bind::<sql_types::Uuid,_>(tenant).bind::<sql_types::Uuid,_>(family)
        .bind::<sql_types::Uuid,_>(client)
        .bind::<sql_types::Nullable<sql_types::Uuid>,_>(if client_subject { None } else { Some(user) })
        .bind::<sql_types::Binary,_>(&digest).execute(connection).await.unwrap();
    connection.batch_execute(&format!(
        "UPDATE oauth_clients SET is_active = FALSE WHERE id = '{client}';
         UPDATE users SET is_active = FALSE WHERE id = '{user}'"
    )).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_covers_all_tenants_and_exact_receipt_never_revokes_new_families() {
    let Some((url, schema)) = isolated().await else { return };
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let system = nazo_identity::TenantContext::default_system().tenant_id.as_uuid();
    let other = Uuid::now_v7();
    family(&mut connection, system, false).await;
    family(&mut connection, other, false).await;
    family(&mut connection, other, true).await;
    connection.batch_execute(&format!("UPDATE tenants SET status='suspended' WHERE id='{other}'")).await.unwrap();
    let repository = TokenRepository::new(create_pool(url.clone(), 2).unwrap());
    let operation = Uuid::now_v7();
    let epoch = Uuid::now_v7();
    let hash = "a".repeat(64);
    let completed = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
    let deadline = completed + Duration::minutes(10);
    let first = repository.invalidate_after_restore(operation, &hash, epoch, deadline, completed).await.unwrap();
    assert_eq!(first.revoked_refresh_tokens, 3);
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE revoked_at IS NULL").await, 0);
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM recovery_invalidations WHERE coverage_version=1 AND tenant_id='00000000-0000-0000-0000-000000000001'").await, 1);
    family(&mut connection, system, true).await;
    let replay = repository.invalidate_after_restore(operation, &hash, epoch,
        deadline + Duration::hours(1), completed + Duration::seconds(1)).await.unwrap();
    assert_eq!(replay, first, "the original absolute deadline and count own replay");
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE revoked_at IS NULL").await, 1);
    assert!(matches!(repository.invalidate_after_restore(Uuid::now_v7(), &hash, epoch, deadline, completed).await, Err(RepositoryError::Conflict)));

    // An actual old writer omits the added field and remains version 0.
    let old_operation = Uuid::now_v7();
    let old_epoch = Uuid::now_v7();
    sql_query("INSERT INTO recovery_invalidations (operation_id, request_hash, tenant_id, state_epoch,
        not_before, revoked_refresh_tokens, completed_at) VALUES ($1,$2,$3,$4,$5,2,$6)")
        .bind::<sql_types::Uuid,_>(old_operation).bind::<sql_types::Text,_>(&hash)
        .bind::<sql_types::Uuid,_>(system).bind::<sql_types::Uuid,_>(old_epoch)
        .bind::<sql_types::Timestamptz,_>(deadline).bind::<sql_types::Timestamptz,_>(completed)
        .execute(&mut connection).await.unwrap();
    assert!(matches!(repository.invalidate_after_restore(old_operation, &hash, old_epoch, deadline, completed).await, Err(RepositoryError::Consistency(_))));
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM recovery_invalidations WHERE coverage_version=0").await, 1);
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE revoked_at IS NULL").await, 1);

    // A receipt failure rolls back every tenant update, and consumes no epoch.
    connection.batch_execute("ALTER TABLE recovery_invalidations ADD CONSTRAINT injected_receipt_failure CHECK(false) NOT VALID").await.unwrap();
    let repair = Uuid::now_v7();
    let repair_epoch = Uuid::now_v7();
    assert!(repository.invalidate_after_restore(repair, &hash, repair_epoch, deadline, completed).await.is_err());
    assert_eq!(count(&mut connection, "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families WHERE revoked_at IS NULL").await, 1);
    connection.batch_execute("ALTER TABLE recovery_invalidations DROP CONSTRAINT injected_receipt_failure").await.unwrap();
    assert_eq!(repository.invalidate_after_restore(repair, &hash, repair_epoch, deadline, completed).await.unwrap().revoked_refresh_tokens, 1);
    connection.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_global_epoch_has_one_operation_winner() {
    let Some((url, schema)) = isolated().await else { return };
    let repository = TokenRepository::new(create_pool(url.clone(), 2).unwrap());
    let now = Utc::now();
    let epoch = Uuid::now_v7();
    let hash = "b".repeat(64);
    let (left, right) = tokio::join!(
        repository.invalidate_after_restore(Uuid::now_v7(), &hash, epoch, now + Duration::minutes(10), now),
        repository.invalidate_after_restore(Uuid::now_v7(), &hash, epoch, now + Duration::minutes(10), now)
    );
    assert!(matches!((left, right), (Ok(_), Err(RepositoryError::Conflict)) | (Err(RepositoryError::Conflict), Ok(_))));
    AsyncPgConnection::establish(&url).await.unwrap().batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await.unwrap();
}
