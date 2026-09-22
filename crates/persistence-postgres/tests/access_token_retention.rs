//! End-to-end retention coverage for `access_token_revocations` (DB-002).
//!
//! Every revocation writer stores the fact under
//! `expires_at = verified exp + MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS` so the
//! fact outlives the token's maximum verifier acceptance window. The stored
//! deadline is monotonic across writer orderings, conflicting ownership inside
//! one owner batch aborts the whole transaction, and the bounded maintenance
//! cleanup reclaims a fact only after its padded deadline passes.

use chrono::{DateTime, Duration, Utc};
use diesel::{
    OptionalExtension, QueryableByName, sql_query,
    sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{AccessTokenRevocation, TokenRepositoryPort, TokenRevocation};
use nazo_identity::{TenantId, UserId};
use nazo_persistence::SecurityStateMaintenancePort;
use nazo_postgres::{
    SecurityStateMaintenanceRepository, TokenIssuanceRepository, TokenRepository, create_pool,
    deactivate_client_on_connection, disable_user_on_connection,
};
use nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS;
use uuid::Uuid;

const SYSTEM_TENANT: Uuid = Uuid::from_u128(1);

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI revocation-retention tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

/// timestamptz stores microseconds; truncating fixture timestamps keeps
/// equality assertions exact.
fn micros(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros()).expect("in-range timestamp")
}

const SECURITY_POLICY: &str = r#"{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}"#;

#[derive(QueryableByName)]
struct FixtureIds {
    #[diesel(sql_type = SqlUuid)]
    user_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct ClientIds {
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct RevocationRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    client_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    revoked_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct FlagRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    flag: bool,
}

/// One active user plus one active client under the default tenant.
async fn fixture(database_url: &str, tag: &str) -> FixtureIds {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    sql_query(format!(
        r#"
        WITH inserted_user AS (
            INSERT INTO users (username, email, password_hash)
            VALUES ('{tag}', '{tag}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method, security_policy
            ) VALUES (
                '{tag}', 'Retention Test', 'confidential',
                '["https://client.example/callback"]'::jsonb,
                '["openid", "offline_access"]'::jsonb,
                '["authorization_code", "refresh_token"]'::jsonb,
                'client_secret_basic',
                '{SECURITY_POLICY}'::jsonb
            ) RETURNING id, client_id
        )
        SELECT inserted_user.id AS user_id, inserted_client.id AS client_id,
               inserted_client.client_id AS client_public_id
        FROM inserted_user CROSS JOIN inserted_client
        "#
    ))
    .get_result::<FixtureIds>(&mut connection)
    .await
    .expect("retention fixture should insert")
}

/// One additional active client under the default tenant.
async fn insert_client(connection: &mut AsyncPgConnection, tag: &str) -> ClientIds {
    sql_query(format!(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_name, client_type, redirect_uris, scopes, grant_types,
            token_endpoint_auth_method, security_policy
        ) VALUES (
            '{tag}', 'Retention Test Client', 'confidential',
            '["https://client.example/callback"]'::jsonb,
            '["openid"]'::jsonb,
            '["authorization_code"]'::jsonb,
            'client_secret_basic',
            '{SECURITY_POLICY}'::jsonb
        ) RETURNING id AS client_id, client_id AS client_public_id
        "#
    ))
    .get_result::<ClientIds>(connection)
    .await
    .expect("client fixture should insert")
}

/// A second tenant boundary with its realm, organization, and one client.
async fn insert_tenant_client(connection: &mut AsyncPgConnection, tag: &str) -> (Uuid, ClientIds) {
    let tenant = Uuid::now_v7();
    let realm = Uuid::now_v7();
    let organization = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, 'Retention Tenant');")
        .bind::<SqlUuid, _>(tenant)
        .bind::<Text, _>(format!("{tag}-{tenant}"))
        .execute(connection)
        .await
        .expect("tenant fixture should insert");
    sql_query("INSERT INTO realms (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'Default realm');")
        .bind::<SqlUuid, _>(realm)
        .bind::<SqlUuid, _>(tenant)
        .execute(&mut *connection)
        .await
        .expect("realm fixture should insert");
    sql_query("INSERT INTO organizations (id, tenant_id, slug, display_name) VALUES ($1, $2, 'default', 'Default organization');")
        .bind::<SqlUuid, _>(organization)
        .bind::<SqlUuid, _>(tenant)
        .execute(&mut *connection)
        .await
        .expect("organization fixture should insert");
    let client = sql_query(format!(
        r#"
        INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id,
            client_id, client_name, client_type, redirect_uris, scopes, grant_types,
            token_endpoint_auth_method, security_policy
        ) VALUES (
            $1, $2, $3, $4,
            '{tag}-client', 'Retention Test Client', 'confidential',
            '["https://client.example/callback"]'::jsonb,
            '["openid"]'::jsonb,
            '["authorization_code"]'::jsonb,
            'client_secret_basic',
            '{SECURITY_POLICY}'::jsonb
        ) RETURNING id AS client_id, client_id AS client_public_id
        "#
    ))
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(tenant)
    .bind::<SqlUuid, _>(realm)
    .bind::<SqlUuid, _>(organization)
    .get_result::<ClientIds>(connection)
    .await
    .expect("foreign-tenant client fixture should insert");
    (tenant, client)
}

/// A generic OAuth access-token issuance row; `retain_until` satisfies the
/// `retain_until >= access_token_expires_at` contract.
async fn insert_issuance(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Option<Uuid>,
    jti: &str,
    expires_at: DateTime<Utc>,
) {
    sql_query(
        "INSERT INTO oauth_token_issuances (\
             issuance_id, tenant_id, client_id, user_id, access_token_jti, \
             access_token_expires_at, retain_until) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(client_id)
    .bind::<Nullable<SqlUuid>, _>(user_id)
    .bind::<Text, _>(jti.to_owned())
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Timestamptz, _>(expires_at + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS))
    .execute(connection)
    .await
    .expect("issuance fixture should insert");
}

/// A VCI access grant; `token_id` is what the owner-revocation cursor exposes
/// as the access-token JTI (`token_id::text`). `created_at` is backdated so
/// past-but-in-skew expiries satisfy `expires_at > created_at`.
async fn insert_vci_grant(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    subject_id: Uuid,
    client_public_id: &str,
    token_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
) {
    sql_query(
        "INSERT INTO openid4vci_access_grants (\
             token_id, token_hash, tenant_id, subject_id, client_id, \
             credential_configuration_ids, credential_identifiers, \
             expires_at, revoked_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, '[\"pid\"]'::jsonb, '[]'::jsonb, $6, $7, $8)",
    )
    .bind::<SqlUuid, _>(token_id)
    .bind::<Text, _>(Uuid::now_v7().simple().to_string().repeat(2))
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .bind::<Text, _>(client_public_id.to_owned())
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Nullable<Timestamptz>, _>(revoked_at)
    .bind::<Timestamptz, _>(expires_at - Duration::hours(1))
    .execute(connection)
    .await
    .expect("vci grant fixture should insert");
}

/// One active refresh family for the owner; used to prove transaction
/// boundaries in the owner-revocation tests.
async fn insert_refresh(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    family_id: Uuid,
) {
    let contract = nazo_auth::RefreshContract {
        subject: user_id.to_string(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        authorization_details: serde_json::json!([]),
        authentication_context: nazo_auth::RefreshTokenAuthenticationContext {
            version: nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION,
            issuer: "https://issuer.example".to_owned(),
            audience: "retention-client".to_owned(),
            auth_time: Utc::now().timestamp() - 1,
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
    };
    let persisted = contract.persisted();
    let contract_blake3 = persisted.blake3_digest().to_vec();
    let contract_json = serde_json::to_value(&persisted).expect("contract should serialize");
    let member_id = Uuid::now_v7();
    sql_query(
        "WITH c AS (\
             INSERT INTO oauth_refresh_contracts (tenant_id, contract_blake3, contract) \
             VALUES ($2, $3, $4::jsonb) \
             ON CONFLICT (tenant_id, contract_blake3) DO NOTHING \
         ) \
         INSERT INTO oauth_refresh_families (\
             tenant_id, token_family_id, contract_blake3, client_id, user_id, \
             current_member_id, current_token_blake3, current_audience, \
             current_issued_at, current_expires_at) \
         VALUES ($2, $5, $3, $6, $7, $1, $8, '[\"resource://default\"]'::jsonb, $9, $10)",
    )
    .bind::<SqlUuid, _>(member_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<diesel::sql_types::Binary, _>(&contract_blake3)
    .bind::<diesel::sql_types::Jsonb, _>(&contract_json)
    .bind::<SqlUuid, _>(family_id)
    .bind::<SqlUuid, _>(client_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<diesel::sql_types::Binary, _>(
        blake3::hash(Uuid::now_v7().simple().to_string().as_bytes())
            .as_bytes()
            .to_vec(),
    )
    .bind::<Timestamptz, _>(Utc::now())
    .bind::<Timestamptz, _>(Utc::now() + Duration::hours(1))
    .execute(connection)
    .await
    .expect("refresh fixture should insert");
}

async fn tagged_revocation_count(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    jtis: &[String],
) -> i64 {
    let digests: Vec<String> = jtis.iter().map(|jti| blake3_hex(jti)).collect();
    sql_query(
        "SELECT count(*)::bigint AS count FROM access_token_revocations \
         WHERE tenant_id = $1 AND access_token_jti_blake3 = ANY($2)",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<diesel::sql_types::Array<Text>, _>(digests)
    .get_result::<CountRow>(connection)
    .await
    .expect("tagged revocation count should query")
    .count
}

async fn revocation_row(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    jti: &str,
) -> Option<RevocationRow> {
    sql_query(
        "SELECT id, client_id, tenant_id, revoked_at, expires_at \
         FROM access_token_revocations \
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<Text, _>(blake3_hex(jti))
    .get_result::<RevocationRow>(connection)
    .await
    .optional()
    .expect("revocation row should be readable")
}

/// The explicit-revocation writer: token-management revocation stores the
/// access-token fact under the padded deadline.
async fn explicit_revoke(
    repository: &TokenIssuanceRepository,
    tenant_id: Uuid,
    client_id: Uuid,
    jti: &str,
    expires_at: DateTime<Utc>,
) {
    let raw_token = format!("retention-refresh-{}", Uuid::now_v7());
    repository
        .revoke_token(TokenRevocation {
            tenant_id,
            client_id,
            raw_token: &raw_token,
            access_token: Some(AccessTokenRevocation {
                jti: jti.to_owned(),
                expires_at,
            }),
        })
        .await
        .expect("explicit access-token revocation should commit");
}

/// RV-02 — a token whose verified exp already passed but still sits inside
/// the skew window stays rejected through the real verifier lookup, and the
/// real cleanup leaves the row alone until the padded deadline passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_access_token_within_skew_survives_cleanup_until_its_padded_deadline() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv02-{}", Uuid::now_v7().simple())).await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let issuance = TokenIssuanceRepository::new(pool.clone());
    let tokens = TokenRepository::new(pool.clone());

    let jti = format!("rv02-{}", Uuid::now_v7());
    let exp = micros(Utc::now() - Duration::seconds(30));
    explicit_revoke(&issuance, SYSTEM_TENANT, fixture.client_id, &jti, exp).await;

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti)
        .await
        .expect("the revocation fact should be stored");
    assert_eq!(
        stored.expires_at,
        exp + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
        "the stored deadline must cover exp plus the full verifier skew"
    );
    assert_eq!(stored.client_id, fixture.client_id);
    assert_eq!(stored.tenant_id, SYSTEM_TENANT);
    assert!(
        tokens
            .access_token_revoked(SYSTEM_TENANT, &jti)
            .await
            .expect("revocation lookup should succeed"),
        "the verifier read path must still reject the token inside the skew window"
    );

    // The real maintenance batch must not reclaim a row whose padded deadline
    // is still open.
    SecurityStateMaintenanceRepository::new(pool.clone())
        .cleanup_batch()
        .await
        .expect("cleanup batch should succeed");
    let after = revocation_row(&mut connection, SYSTEM_TENANT, &jti)
        .await
        .expect("an open deadline must survive cleanup");
    assert_eq!(after.id, stored.id);
    assert_eq!(after.expires_at, stored.expires_at);
    assert!(
        tokens
            .access_token_revoked(SYSTEM_TENANT, &jti)
            .await
            .expect("revocation lookup should succeed"),
        "the row must still reject the token after a cleanup pass"
    );
}

/// RV-03 — the authorization-code replay compensation entry
/// (`TokenRepositoryPort::revoke_issued_tokens` →
/// `AuthorizationRepository::revoke_issued_tokens`) writes the same padded
/// deadline. A record without a verified token expiry cannot bound a
/// revocation window, so the access-token fact is skipped while the refresh
/// family is still revoked atomically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_compensation_writes_padded_deadline_and_missing_expiry_skips_the_access_fact() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv03-{}", Uuid::now_v7().simple())).await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let issuance = TokenIssuanceRepository::new(pool.clone());
    let tokens = TokenRepository::new(pool.clone());

    let jti = format!("rv03-{}", Uuid::now_v7());
    let exp = micros(Utc::now() - Duration::seconds(15));
    issuance
        .revoke_issued_tokens(SYSTEM_TENANT, fixture.client_id, &jti, Some(exp), None)
        .await
        .expect("replay compensation should commit");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti)
        .await
        .expect("compensation should store the revocation fact");
    assert_eq!(
        stored.expires_at,
        exp + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
        "the compensation writer stores exp plus the skew window"
    );
    assert!(
        tokens
            .access_token_revoked(SYSTEM_TENANT, &jti)
            .await
            .expect("revocation lookup should succeed")
    );

    // `None` expiry keeps its prior semantics: no access-token fact is
    // written at all, but the refresh family is still revoked atomically.
    let family_id = Uuid::now_v7();
    insert_refresh(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        family_id,
    )
    .await;
    let jti_none = format!("rv03-none-{}", Uuid::now_v7());
    issuance
        .revoke_issued_tokens(
            SYSTEM_TENANT,
            fixture.client_id,
            &jti_none,
            None,
            Some(family_id),
        )
        .await
        .expect("expiry-less compensation should still commit");
    assert!(
        revocation_row(&mut connection, SYSTEM_TENANT, &jti_none)
            .await
            .is_none(),
        "a missing verified exp must not fabricate a revocation window"
    );
    assert!(
        !tokens
            .access_token_revoked(SYSTEM_TENANT, &jti_none)
            .await
            .expect("revocation lookup should succeed")
    );
    let unrevoked = sql_query(
        "SELECT count(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("family row count should query");
    assert_eq!(
        unrevoked.count, 0,
        "the refresh family is still revoked inside the same transaction"
    );
}

/// RV-04 — the owner-batch revocation entry
/// (`deactivate_client_on_connection` →
/// `revoke_access_tokens_for_owner_on_connection`) selects both the generic
/// `oauth_token_issuances` rows and the `openid4vci_access_grants` rows whose
/// exp differs but still sits inside the skew window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_revocation_covers_oauth_and_vci_sources_inside_the_skew_window() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv04-{}", Uuid::now_v7().simple())).await;
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let other_client = insert_client(
        &mut connection,
        &format!("rv04-other-{}", Uuid::now_v7().simple()),
    )
    .await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let tokens = TokenRepository::new(pool.clone());
    let now = Utc::now();

    // Generic issuance rows at different in-skew offsets.
    let oauth_a = format!("rv04-oauth-a-{}", Uuid::now_v7());
    let oauth_a_exp = micros(now - Duration::seconds(10));
    let oauth_b = format!("rv04-oauth-b-{}", Uuid::now_v7());
    let oauth_b_exp = micros(now - Duration::seconds(45));
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        Some(fixture.user_id),
        &oauth_a,
        oauth_a_exp,
    )
    .await;
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        Some(fixture.user_id),
        &oauth_b,
        oauth_b_exp,
    )
    .await;
    // Already outside the acceptance window — no longer selectable.
    let oauth_expired = format!("rv04-oauth-old-{}", Uuid::now_v7());
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        Some(fixture.user_id),
        &oauth_expired,
        micros(now - Duration::seconds(90)),
    )
    .await;
    // Same owner, different client — outside the client-scoped batch.
    let oauth_other = format!("rv04-oauth-other-{}", Uuid::now_v7());
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        other_client.client_id,
        Some(fixture.user_id),
        &oauth_other,
        micros(now - Duration::seconds(10)),
    )
    .await;

    // VCI access grants owned by the same client through its public id.
    let vci_a = Uuid::now_v7();
    let vci_a_exp = micros(now - Duration::seconds(20));
    let vci_b = Uuid::now_v7();
    let vci_b_exp = micros(now - Duration::seconds(55));
    let vci_expired = Uuid::now_v7();
    let vci_revoked = Uuid::now_v7();
    insert_vci_grant(
        &mut connection,
        SYSTEM_TENANT,
        fixture.user_id,
        &fixture.client_public_id,
        vci_a,
        vci_a_exp,
        None,
    )
    .await;
    insert_vci_grant(
        &mut connection,
        SYSTEM_TENANT,
        fixture.user_id,
        &fixture.client_public_id,
        vci_b,
        vci_b_exp,
        None,
    )
    .await;
    insert_vci_grant(
        &mut connection,
        SYSTEM_TENANT,
        fixture.user_id,
        &fixture.client_public_id,
        vci_expired,
        micros(now - Duration::seconds(80)),
        None,
    )
    .await;
    let vci_revoked_at = micros(now - Duration::seconds(10));
    insert_vci_grant(
        &mut connection,
        SYSTEM_TENANT,
        fixture.user_id,
        &fixture.client_public_id,
        vci_revoked,
        micros(now - Duration::seconds(20)),
        Some(vci_revoked_at),
    )
    .await;

    let deactivated = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            deactivate_client_on_connection(connection, SYSTEM_TENANT, fixture.client_id).await
        })
        .await
        .expect("owner deactivation should commit");
    assert!(deactivated, "the active client should deactivate");

    let vci_a_jti = vci_a.to_string();
    let vci_b_jti = vci_b.to_string();
    let vci_expired_jti = vci_expired.to_string();
    let vci_revoked_jti = vci_revoked.to_string();
    for (jti, exp) in [
        (oauth_a.as_str(), oauth_a_exp),
        (oauth_b.as_str(), oauth_b_exp),
        (vci_a_jti.as_str(), vci_a_exp),
        (vci_b_jti.as_str(), vci_b_exp),
    ] {
        let stored = revocation_row(&mut connection, SYSTEM_TENANT, jti)
            .await
            .unwrap_or_else(|| panic!("owner batch must cover {jti}"));
        assert_eq!(
            stored.expires_at,
            exp + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
            "every selected source stores its own exp plus one skew window"
        );
        assert_eq!(stored.client_id, fixture.client_id);
        assert!(
            tokens
                .access_token_revoked(SYSTEM_TENANT, jti)
                .await
                .expect("revocation lookup should succeed"),
            "{jti} must reject through the verifier read path"
        );
    }
    for jti in [
        oauth_expired.as_str(),
        oauth_other.as_str(),
        vci_expired_jti.as_str(),
        vci_revoked_jti.as_str(),
    ] {
        assert!(
            !tokens
                .access_token_revoked(SYSTEM_TENANT, jti)
                .await
                .expect("revocation lookup should succeed"),
            "{jti} must not be selected by the owner batch"
        );
    }

    // The grants table itself is still fully revoked for the owner — the
    // expiry predicate only bounds the revocation-fact projection.
    let active_grants = sql_query(
        "SELECT count(*)::bigint AS count FROM openid4vci_access_grants \
         WHERE tenant_id = $1 AND subject_id = $2 AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(fixture.user_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("active grant count should query");
    assert_eq!(active_grants.count, 0);
}

/// RV-05 — writer ordering matrix. Whichever writer runs second can only
/// extend the stored deadline; the fact's id, client, tenant, and first
/// `revoked_at` are never rewritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_deadline_is_monotonic_across_writer_orderings() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv05-{}", Uuid::now_v7().simple())).await;
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let issuance = TokenIssuanceRepository::new(pool.clone());
    let tokens = TokenRepository::new(pool.clone());
    let short_exp = micros(Utc::now() + Duration::seconds(300));
    let long_exp = micros(Utc::now() + Duration::seconds(600));
    let window = Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS);

    // explicit revoke, then an owner batch carrying the longer deadline.
    let jti_a = format!("rv05-a-{}", Uuid::now_v7());
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_a,
        short_exp,
    )
    .await;
    let first = revocation_row(&mut connection, SYSTEM_TENANT, &jti_a)
        .await
        .expect("explicit revocation should store the fact");
    assert_eq!(first.expires_at, short_exp + window);
    let batch_client = insert_client(
        &mut connection,
        &format!("rv05-batch-a-{}", Uuid::now_v7().simple()),
    )
    .await;
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        batch_client.client_id,
        Some(fixture.user_id),
        &jti_a,
        long_exp,
    )
    .await;
    let deactivated = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            deactivate_client_on_connection(connection, SYSTEM_TENANT, batch_client.client_id).await
        })
        .await
        .expect("owner batch should commit");
    assert!(deactivated);
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti_a)
        .await
        .expect("the fact should remain");
    assert_eq!(
        stored.expires_at,
        long_exp + window,
        "the later writer may only extend the deadline"
    );
    assert_eq!(stored.id, first.id, "the fact id is stable");
    assert_eq!(
        stored.client_id, fixture.client_id,
        "the batch writer's client must not rewrite recorded ownership"
    );
    assert_eq!(stored.tenant_id, SYSTEM_TENANT);
    assert_eq!(
        stored.revoked_at, first.revoked_at,
        "the first revoked_at is authoritative"
    );

    // Owner batch first, then an explicit revoke carrying the shorter
    // deadline: nothing changes.
    let jti_b = format!("rv05-b-{}", Uuid::now_v7());
    let batch_client_b = insert_client(
        &mut connection,
        &format!("rv05-batch-b-{}", Uuid::now_v7().simple()),
    )
    .await;
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        batch_client_b.client_id,
        Some(fixture.user_id),
        &jti_b,
        long_exp,
    )
    .await;
    let deactivated = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            deactivate_client_on_connection(connection, SYSTEM_TENANT, batch_client_b.client_id)
                .await
        })
        .await
        .expect("owner batch should commit");
    assert!(deactivated);
    let first = revocation_row(&mut connection, SYSTEM_TENANT, &jti_b)
        .await
        .expect("owner batch should store the fact");
    assert_eq!(first.expires_at, long_exp + window);
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_b,
        short_exp,
    )
    .await;
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti_b)
        .await
        .expect("the fact should remain");
    assert_eq!(
        stored.expires_at,
        long_exp + window,
        "a shorter later deadline must not shrink the stored window"
    );
    assert_eq!(stored.id, first.id);
    assert_eq!(stored.client_id, batch_client_b.client_id);
    assert_eq!(stored.revoked_at, first.revoked_at);

    // Replay compensation first, then an explicit revoke with the longer
    // deadline.
    let jti_c = format!("rv05-c-{}", Uuid::now_v7());
    issuance
        .revoke_issued_tokens(
            SYSTEM_TENANT,
            fixture.client_id,
            &jti_c,
            Some(short_exp),
            None,
        )
        .await
        .expect("compensation should commit");
    let first = revocation_row(&mut connection, SYSTEM_TENANT, &jti_c)
        .await
        .expect("compensation should store the fact");
    assert_eq!(first.expires_at, short_exp + window);
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_c,
        long_exp,
    )
    .await;
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti_c)
        .await
        .expect("the fact should remain");
    assert_eq!(stored.expires_at, long_exp + window);
    assert_eq!(stored.id, first.id);
    assert_eq!(stored.revoked_at, first.revoked_at);

    // Longer deadline then shorter deadline — the stored window never shrinks.
    let jti_d = format!("rv05-d-{}", Uuid::now_v7());
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_d,
        long_exp,
    )
    .await;
    let first = revocation_row(&mut connection, SYSTEM_TENANT, &jti_d)
        .await
        .expect("explicit revocation should store the fact");
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_d,
        short_exp,
    )
    .await;
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti_d)
        .await
        .expect("the fact should remain");
    assert_eq!(stored.expires_at, long_exp + window);
    assert_eq!(stored.id, first.id);
    assert_eq!(stored.revoked_at, first.revoked_at);

    // Shorter deadline then longer deadline — the window extends forward.
    let jti_e = format!("rv05-e-{}", Uuid::now_v7());
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_e,
        short_exp,
    )
    .await;
    explicit_revoke(
        &issuance,
        SYSTEM_TENANT,
        fixture.client_id,
        &jti_e,
        long_exp,
    )
    .await;
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &jti_e)
        .await
        .expect("the fact should remain");
    assert_eq!(stored.expires_at, long_exp + window);

    for jti in [&jti_a, &jti_b, &jti_c, &jti_d, &jti_e] {
        assert!(
            tokens
                .access_token_revoked(SYSTEM_TENANT, jti)
                .await
                .expect("revocation lookup should succeed"),
            "{jti} must reject through the verifier read path"
        );
    }
}

/// RV-06 — two sources surfacing the same (tenant, jti) under contradictory
/// clients abort the whole revocation transaction. Another tenant holding the
/// same JTI is an independent authority key and is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_owner_revocation_rolls_back_and_other_tenants_are_unaffected() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv06-{}", Uuid::now_v7().simple())).await;
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let other_client = insert_client(
        &mut connection,
        &format!("rv06-b-{}", Uuid::now_v7().simple()),
    )
    .await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let issuance = TokenIssuanceRepository::new(pool.clone());
    let tokens = TokenRepository::new(pool.clone());

    // The generic issuance records one owner; the VCI grant's token id text
    // collides with the JTI but resolves to a different client.
    let shared_token_id = Uuid::now_v7();
    let shared_jti = shared_token_id.to_string();
    let exp = micros(Utc::now() + Duration::seconds(300));
    insert_issuance(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        Some(fixture.user_id),
        &shared_jti,
        exp,
    )
    .await;
    insert_vci_grant(
        &mut connection,
        SYSTEM_TENANT,
        fixture.user_id,
        &other_client.client_public_id,
        shared_token_id,
        exp,
        None,
    )
    .await;
    let family_id = Uuid::now_v7();
    insert_refresh(
        &mut connection,
        SYSTEM_TENANT,
        fixture.client_id,
        fixture.user_id,
        family_id,
    )
    .await;

    let tenant_id = TenantId::new(SYSTEM_TENANT).expect("tenant id should be valid");
    let user_id = UserId::new(fixture.user_id).expect("user id should be valid");
    let outcome = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            disable_user_on_connection(connection, tenant_id, user_id).await
        })
        .await;
    let error = outcome.expect_err("contradictory ownership must abort the owner batch");
    assert!(
        matches!(error, diesel::result::Error::DeserializationError(_))
            && error
                .to_string()
                .contains("conflicting access-token revocation ownership"),
        "the conflict must surface as a typed failure: {error:?}"
    );

    // The whole transaction rolled back: user still active, refresh family
    // still active, grant still unrevoked, and no revocation fact stored.
    let still_active = sql_query("SELECT is_active AS flag FROM users WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.user_id)
        .get_result::<FlagRow>(&mut connection)
        .await
        .expect("user state should be readable");
    assert!(
        still_active.flag,
        "a failed owner batch must not leave the user disabled"
    );
    assert!(
        !tokens
            .access_token_revoked(SYSTEM_TENANT, &shared_jti)
            .await
            .expect("revocation lookup should succeed"),
        "the rolled-back batch must not leave a partial revocation fact"
    );
    let unrevoked = sql_query(
        "SELECT count(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("family row count should query");
    assert_eq!(unrevoked.count, 1, "the refresh family must roll back too");
    let grant_active = sql_query(
        "SELECT revoked_at IS NULL AS flag FROM openid4vci_access_grants WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(shared_token_id)
    .get_result::<FlagRow>(&mut connection)
    .await
    .expect("grant state should be readable");
    assert!(grant_active.flag, "the grant must not be marked revoked");

    // A different tenant holding the same JTI is a separate authority key.
    let (foreign_tenant, foreign_client) =
        insert_tenant_client(&mut connection, "rv06-foreign").await;
    explicit_revoke(
        &issuance,
        foreign_tenant,
        foreign_client.client_id,
        &shared_jti,
        exp,
    )
    .await;
    assert!(
        tokens
            .access_token_revoked(foreign_tenant, &shared_jti)
            .await
            .expect("revocation lookup should succeed"),
        "the foreign tenant's same-JTI fact is independent"
    );
    assert!(
        !tokens
            .access_token_revoked(SYSTEM_TENANT, &shared_jti)
            .await
            .expect("revocation lookup should succeed"),
        "the foreign write must not fabricate a fact in the first tenant"
    );

    // With the contradiction removed the owner batch commits normally, and
    // the foreign tenant's row is untouched.
    sql_query("DELETE FROM openid4vci_access_grants WHERE token_id = $1")
        .bind::<SqlUuid, _>(shared_token_id)
        .execute(&mut connection)
        .await
        .expect("conflicting grant fixture should be removable");
    let disabled = connection
        .transaction::<bool, diesel::result::Error, _>(async |connection| {
            disable_user_on_connection(connection, tenant_id, user_id).await
        })
        .await
        .expect("owner batch without the conflict should commit");
    assert!(disabled);
    let stored = revocation_row(&mut connection, SYSTEM_TENANT, &shared_jti)
        .await
        .expect("the revocation fact should now exist");
    assert_eq!(stored.client_id, fixture.client_id);
    assert_eq!(
        stored.expires_at,
        exp + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
    );
    let foreign = revocation_row(&mut connection, foreign_tenant, &shared_jti)
        .await
        .expect("the foreign fact should be untouched");
    assert_eq!(foreign.client_id, foreign_client.client_id);
    assert_eq!(
        foreign.expires_at,
        exp + Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
    );
}

/// RV-07 — once the padded deadline passes, the real maintenance cleanup
/// reclaims the row; facts stored under the old bare-exp semantics are not
/// retained indefinitely either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_reclaims_revocation_facts_once_the_padded_deadline_passes() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url, &format!("rv07-{}", Uuid::now_v7().simple())).await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let tokens = TokenRepository::new(pool.clone());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    // The shared test database accumulates expired revocations from other
    // suites; clear the queue so the bounded rounds below provably reach this
    // fixture's rows.
    sql_query("DELETE FROM access_token_revocations WHERE expires_at <= clock_timestamp()")
        .execute(&mut connection)
        .await
        .expect("stale expired revocations should clear");

    let tag = Uuid::now_v7().simple().to_string();
    // A fact whose padded deadline already passed.
    let passed_jti = format!("rv07-passed-{tag}");
    // A fact written under the pre-DB-002 semantics: expires_at held the bare
    // exp with zero additional skew — still reclaimable once it passed.
    let bare_jti = format!("rv07-bare-{tag}");
    // A fact whose deadline is still open.
    let open_jti = format!("rv07-open-{tag}");
    sql_query(
        "INSERT INTO access_token_revocations \
             (id, access_token_jti_blake3, client_id, tenant_id, revoked_at, expires_at) \
         VALUES \
             (gen_random_uuid(), $2, $1, $3, CURRENT_TIMESTAMP - INTERVAL '2 minutes', \
              CURRENT_TIMESTAMP - INTERVAL '5 seconds'), \
             (gen_random_uuid(), $4, $1, $3, CURRENT_TIMESTAMP - INTERVAL '2 minutes', \
              CURRENT_TIMESTAMP - INTERVAL '90 seconds'), \
             (gen_random_uuid(), $5, $1, $3, CURRENT_TIMESTAMP - INTERVAL '2 minutes', \
              CURRENT_TIMESTAMP + INTERVAL '1 hour')",
    )
    .bind::<SqlUuid, _>(fixture.client_id)
    .bind::<Text, _>(blake3_hex(&passed_jti))
    .bind::<SqlUuid, _>(SYSTEM_TENANT)
    .bind::<Text, _>(blake3_hex(&bare_jti))
    .bind::<Text, _>(blake3_hex(&open_jti))
    .execute(&mut connection)
    .await
    .expect("revocation fixtures should insert");

    let maintenance = SecurityStateMaintenanceRepository::new(pool.clone());
    let expired_jtis = [passed_jti.clone(), bare_jti.clone()];
    for round in 0..8 {
        let result = maintenance
            .cleanup_batch()
            .await
            .expect("cleanup batch should succeed");
        assert!(result.revocations <= 256, "one batch stays bounded");
        if tagged_revocation_count(&mut connection, SYSTEM_TENANT, &expired_jtis).await == 0 {
            break;
        }
        assert_ne!(
            round, 7,
            "expired-deadline facts must drain within the bounded rounds"
        );
    }
    assert_eq!(
        tagged_revocation_count(&mut connection, SYSTEM_TENANT, &expired_jtis).await,
        0
    );
    assert!(
        !tokens
            .access_token_revoked(SYSTEM_TENANT, &passed_jti)
            .await
            .expect("revocation lookup should succeed")
            && !tokens
                .access_token_revoked(SYSTEM_TENANT, &bare_jti)
                .await
                .expect("revocation lookup should succeed"),
        "reclaimed facts no longer reject — the acceptance window has closed"
    );
    assert!(
        tokens
            .access_token_revoked(SYSTEM_TENANT, &open_jti)
            .await
            .expect("revocation lookup should succeed"),
        "a fact inside its retention window is kept"
    );
}
