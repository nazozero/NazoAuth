use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::{
    AccessTokenRevocation, AdminGrantRepositoryPort, CommitTokenIssuance,
    CommitTokenIssuanceResult, NewRefreshToken, PendingBackchannelLogoutDelivery,
    RefreshTokenAuthenticationContext, TokenIssuanceMode, TokenIssuedAuditFields,
    TokenRepositoryPort, TokenRevocation,
};
use nazo_postgres::{
    AuditRepository, AuthorizationRepository, GrantRepository, TokenIssuanceRepository,
    TokenRepository, create_pool,
};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

// These tests exercise a deliberately global worker claim. Serialize only the
// claim-based cases so one test worker cannot consume the other's delivery.
static BACKCHANNEL_CLAIM_TEST_LOCK: Mutex<()> = Mutex::const_new(());

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
    #[diesel(sql_type = Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
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
        .bind::<Text, _>(application_name)
        .get_result::<CountRow>(connection)
        .await
        .expect("blocked PostgreSQL activity should be observable");
        if blocked.count > 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for lock wait from {application_name}");
}

async fn wait_for_lock_wait_or_task<T: std::fmt::Debug>(
    connection: &mut AsyncPgConnection,
    application_name: &str,
    task: &mut tokio::task::JoinHandle<T>,
) {
    tokio::select! {
        () = wait_for_lock_wait(connection, application_name) => {}
        result = task => panic!(
            "task ended before reaching a PostgreSQL lock wait from {application_name}: {result:?}"
        ),
    }
}

fn family_lock_key(family_id: Uuid) -> i64 {
    let bytes = family_id.as_bytes();
    let high = i64::from_be_bytes(bytes[..8].try_into().expect("UUID has 16 bytes"));
    let low = i64::from_be_bytes(bytes[8..].try_into().expect("UUID has 16 bytes"));
    high ^ low
}

fn refresh_authentication_context(
    client_public_id: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> RefreshTokenAuthenticationContext {
    RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: client_public_id.to_owned(),
        auth_time: issued_at.timestamp() - 1,
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        id_token_sid: None,
        acr: None,
        nonce: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
    }
}

fn refresh_context_json(
    client_public_id: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> String {
    serde_json::to_string(&refresh_authentication_context(client_public_id, issued_at))
        .expect("refresh authentication context should serialize")
}

async fn install_rotation_insert_gate(
    connection: &mut AsyncPgConnection,
    family_id: Uuid,
    gate_key: i64,
) -> (String, String) {
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_refresh_rotation_gate_{suffix}");
    let trigger = format!("test_refresh_rotation_gate_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.token_family_id = '{family_id}'::uuid
               AND NEW.rotated_from_id IS NOT NULL THEN
                PERFORM pg_advisory_xact_lock({gate_key});
            END IF;
            RETURN NEW;
        END
        $$
        "#
    ))
    .execute(&mut *connection)
    .await
    .expect("rotation insert gate function should install");
    sql_query(format!(
        r#"
        CREATE TRIGGER {trigger}
        BEFORE INSERT ON oauth_tokens
        FOR EACH ROW EXECUTE FUNCTION {function}()
        "#
    ))
    .execute(connection)
    .await
    .expect("rotation insert gate should install");
    (trigger, function)
}

async fn remove_rotation_insert_gate(
    connection: &mut AsyncPgConnection,
    trigger: &str,
    function: &str,
) {
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_tokens"))
        .execute(&mut *connection)
        .await
        .expect("rotation insert gate trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut *connection)
        .await
        .expect("rotation insert gate should be removed");
}

async fn install_issuance_insert_gate(
    connection: &mut AsyncPgConnection,
    client_id: Uuid,
    gate_key: i64,
) -> (String, String) {
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_token_issuance_gate_{suffix}");
    let trigger = format!("test_token_issuance_gate_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.client_id = '{client_id}'::uuid THEN
                PERFORM pg_advisory_xact_lock({gate_key});
            END IF;
            RETURN NEW;
        END
        $$
        "#
    ))
    .execute(&mut *connection)
    .await
    .expect("token issuance gate function should install");
    sql_query(format!(
        r#"
        CREATE TRIGGER {trigger}
        BEFORE INSERT ON oauth_token_issuances
        FOR EACH ROW EXECUTE FUNCTION {function}()
        "#
    ))
    .execute(connection)
    .await
    .expect("token issuance gate should install");
    (trigger, function)
}

async fn remove_issuance_insert_gate(
    connection: &mut AsyncPgConnection,
    trigger: &str,
    function: &str,
) {
    sql_query(format!("DROP TRIGGER {trigger} ON oauth_token_issuances"))
        .execute(&mut *connection)
        .await
        .expect("token issuance gate trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(connection)
        .await
        .expect("token issuance gate function should be removed");
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
        authentication_context: refresh_authentication_context(
            &fixture.client_public_id,
            authentication_time,
        ),
    }
}

fn refresh_issuance(token: NewRefreshToken) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        issuance_id,
        tenant_id: token.tenant_id,
        client_id: token.client_id,
        user_id: token.user_id,
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (token.issued_at + chrono::Duration::minutes(5)).timestamp(),
        audit_fields: TokenIssuedAuditFields {
            client_id: token.authentication_context.audience.clone(),
            subject_hash: blake3::hash(token.subject.as_bytes()).to_hex().to_string(),
            scope: token.scopes.join(" "),
            audience: token.audiences.clone(),
        },
        refresh_token: Some(token),
    }
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
            VALUES ('auth-repo-{suffix}', 'auth-repo-{suffix}@example.test', 'test-only-hash')
            RETURNING id
        ), inserted_client AS (
            INSERT INTO oauth_clients (
                client_id, client_name, client_type, redirect_uris, scopes, grant_types,
                token_endpoint_auth_method, security_policy
            ) VALUES (
                'auth-repo-{suffix}', 'Auth Repository Test', 'confidential',
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
    .expect("auth repository fixture should insert")
}

async fn seed_deactivation(database_url: &str, fixture: &FixtureIds, count: usize) {
    let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(database_url, 1).unwrap());
    let token = refresh_token_fixture(
        fixture,
        tenant,
        Uuid::now_v7(),
        Uuid::now_v7().to_string(),
        None,
    );
    assert_eq!(
        repository
            .commit_token_issuance(refresh_issuance(token))
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let mut connection = AsyncPgConnection::establish(database_url).await.unwrap();
    let client = fixture.client_id;
    let user = fixture.user_id;
    let public_id = &fixture.client_public_id;
    connection.batch_execute(&format!(
        "INSERT INTO oauth_token_issuances (issuance_id, tenant_id, client_id, user_id, access_token_jti, access_token_expires_at, retain_until) \
         SELECT gen_random_uuid(), '{tenant}', '{client}', '{user}', '{client}-' || n::text, NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 hour' FROM generate_series(1,{count}) n; \
         INSERT INTO openid4vci_access_grants (token_id, token_hash, tenant_id, subject_id, client_id, credential_configuration_ids, credential_identifiers, expires_at) \
         VALUES (gen_random_uuid(), repeat(md5('{client}'),2), '{tenant}', '{user}', '{public_id}', '[\"pid\"]', '[]', NOW() + INTERVAL '1 hour'); \
         INSERT INTO user_client_grants (tenant_id, user_id, client_id, first_authorized_at, last_authorized_at, last_scopes) \
         VALUES ('{tenant}', '{user}', '{client}', NOW(), NOW(), '[\"openid\"]');"
    )).await.unwrap();
}

async fn deactivation_state(
    connection: &mut AsyncPgConnection,
    fixture: &FixtureIds,
) -> serde_json::Value {
    #[derive(QueryableByName)]
    struct State {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    sql_query("SELECT jsonb_build_object( \
        'client', (SELECT to_jsonb(c) FROM oauth_clients c WHERE id = $1), \
        'issuances', (SELECT count(*) FROM oauth_token_issuances WHERE client_id = $1), \
        'revocations', (SELECT count(*) FROM access_token_revocations WHERE client_id = $1), \
        'active_vci', (SELECT count(*) FROM openid4vci_access_grants WHERE client_id = $2 AND revoked_at IS NULL), \
        'active_refresh', (SELECT count(*) FROM oauth_tokens WHERE client_id = $1 AND revoked_at IS NULL), \
        'grants', (SELECT count(*) FROM user_client_grants WHERE client_id = $1)) AS value")
        .bind::<SqlUuid, _>(fixture.client_id).bind::<Text, _>(&fixture.client_public_id)
        .get_result::<State>(connection).await.unwrap().value
}

#[tokio::test]
async fn client_deactivation_is_atomic_across_real_batches_and_repeated_owners() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let large = fixture(&database_url).await;
    let second = fixture(&database_url).await;
    let untouched = fixture(&database_url).await;
    seed_deactivation(&database_url, &large, 100_000).await;
    seed_deactivation(&database_url, &second, 513).await;
    seed_deactivation(&database_url, &untouched, 2).await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let before = deactivation_state(&mut connection, &large).await;
    let untouched_before = deactivation_state(&mut connection, &untouched).await;
    let suffix = Uuid::now_v7().simple().to_string();
    let sequence = format!("deactivate_count_{suffix}");
    let gate = format!("deactivate_failure_{suffix}");
    connection.batch_execute(&format!(
        "CREATE SEQUENCE {sequence}; \
         CREATE FUNCTION {gate}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF NEW.client_id = '{}'::uuid AND nextval('{sequence}') = 513 THEN RAISE EXCEPTION 'injected 513th revocation'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER {gate} BEFORE INSERT ON access_token_revocations FOR EACH ROW EXECUTE FUNCTION {gate}();", large.client_id
    )).await.unwrap();
    let failed = connection
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            nazo_postgres::deactivate_client_on_connection(connection, tenant, large.client_id)
                .await
        })
        .await;
    assert!(
        failed
            .unwrap_err()
            .to_string()
            .contains("injected 513th revocation")
    );
    let attempts = sql_query(format!(
        "SELECT last_value::bigint AS count FROM {sequence}"
    ))
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        attempts.count, 513,
        "failure must occur after the first complete batch"
    );
    assert_eq!(
        deactivation_state(&mut connection, &large).await,
        before,
        "client, first batch, VCI, refresh and grants must all roll back"
    );
    connection.batch_execute(&format!("DROP TRIGGER {gate} ON access_token_revocations; DROP FUNCTION {gate}(); DROP SEQUENCE {sequence}")).await.unwrap();

    connection
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            assert!(
                nazo_postgres::deactivate_client_on_connection(connection, tenant, large.client_id)
                    .await?
            );
            // A second owner in the same transaction catches an unclosed cursor.
            assert!(
                nazo_postgres::deactivate_client_on_connection(
                    connection,
                    tenant,
                    second.client_id
                )
                .await?
            );
            Ok(())
        })
        .await
        .unwrap();
    for (owner, count) in [(&large, 100_002), (&second, 515)] {
        let state = deactivation_state(&mut connection, owner).await;
        assert_eq!(state["client"]["is_active"], false);
        assert_eq!(state["revocations"], count);
        for key in ["active_vci", "active_refresh", "grants"] {
            assert_eq!(state[key], 0, "{key}");
        }
    }
    assert_eq!(
        deactivation_state(&mut connection, &untouched).await,
        untouched_before
    );

    let concurrent = fixture(&database_url).await;
    seed_deactivation(&database_url, &concurrent, 513).await;
    let mut left = AsyncPgConnection::establish(&database_url).await.unwrap();
    let mut right = AsyncPgConnection::establish(&database_url).await.unwrap();
    let (left, right) = tokio::join!(
        left.transaction::<_, diesel::result::Error, _>(async |c| {
            nazo_postgres::deactivate_client_on_connection(c, tenant, concurrent.client_id).await
        }),
        right.transaction::<_, diesel::result::Error, _>(async |c| {
            nazo_postgres::deactivate_client_on_connection(c, tenant, concurrent.client_id).await
        })
    );
    assert_ne!(
        left.unwrap(),
        right.unwrap(),
        "exactly one concurrent deactivation may change the owner"
    );
    let state = deactivation_state(&mut connection, &concurrent).await;
    assert_eq!(state["client"]["is_active"], false);
    assert_eq!(state["revocations"], 515);
    for key in ["active_vci", "active_refresh", "grants"] {
        assert_eq!(state[key], 0, "{key}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_use_grant_retry_is_rejected_without_reissuing_or_duplicating_audit() {
    let database_url =
        database_url().expect("single-use regression requires a live PostgreSQL database");
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let token = refresh_token_fixture(
        &fixture,
        tenant_id,
        Uuid::now_v7(),
        format!("single-use-{}", Uuid::now_v7()),
        None,
    );
    let family_id = token.family_id;
    let mut input = refresh_issuance(token);
    input.mode = TokenIssuanceMode::SingleUse {
        grant_key: format!("grant-{}", input.issuance_id),
        grant_expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    // A second commit of the same grant key must lose the fence race without
    // minting another refresh token or writing another token_issued audit.
    let mut retry = input.clone();
    retry.issuance_id = Uuid::now_v7();
    retry.access_token_jti = retry.issuance_id.to_string();
    retry.refresh_token.as_mut().unwrap().raw_token = format!("loser-{}", retry.issuance_id);
    assert_eq!(
        repository.commit_token_issuance(retry).await.unwrap(),
        CommitTokenIssuanceResult::AlreadyUsed
    );
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(fixture.client_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(rows.count, 1);
    let family = sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_tokens WHERE token_family_id = $1 AND revoked_at IS NULL")
        .bind::<SqlUuid, _>(family_id).get_result::<CountRow>(&mut connection).await.unwrap();
    assert_eq!(
        family.count, 1,
        "retry must not mint another refresh token or revoke the existing family"
    );
    let audit = sql_query("SELECT COUNT(*)::bigint AS count FROM security_audit_events WHERE payload->>'issuance_id' = $1")
        .bind::<Text, _>(input.issuance_id.to_string()).get_result::<CountRow>(&mut connection).await.unwrap();
    assert_eq!(audit.count, 1);
}

#[derive(QueryableByName)]
struct IssuanceAuditRow {
    #[diesel(sql_type = Text)]
    event_type: String,
    #[diesel(sql_type = Text)]
    event_category: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    payload: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pending_outbox: bool,
}

async fn assert_issuance_audit(
    connection: &mut AsyncPgConnection,
    input: &CommitTokenIssuance,
    expected: &[(&str, &str, serde_json::Value)],
) {
    let rows = sql_query("SELECT e.event_type::text AS event_type, e.event_category::text AS event_category, e.payload, (o.attempts = 0 AND o.exported_at IS NULL) AS pending_outbox FROM security_audit_events e JOIN security_audit_event_outbox o USING(event_id) WHERE e.payload->>'issuance_id' = $1 ORDER BY e.occurred_at, e.event_id")
        .bind::<Text, _>(input.issuance_id.to_string()).load::<IssuanceAuditRow>(connection).await.unwrap();
    assert_eq!(rows.len(), expected.len());
    for (row, (event_type, category, fields)) in rows.iter().zip(expected) {
        assert_eq!(row.event_type, *event_type);
        assert_eq!(row.event_category, *category);
        assert!(row.pending_outbox);
        let mut payload = json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "event_category": category,
            "tenant_id": input.tenant_id,
            "issuance_id": input.issuance_id,
            "client_id": input.audit_fields.client_id,
        });
        payload
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        assert_eq!(row.payload, payload);
    }
}

fn issued_audit_fields(input: &CommitTokenIssuance) -> serde_json::Value {
    json!({
        "user_id": input.user_id,
        "subject_hash": input.audit_fields.subject_hash,
        "scope": input.audit_fields.scope,
        "audience": input.audit_fields.audience,
        "access_token_jti": input.access_token_jti,
        "refresh_token_family_id": input.refresh_token.as_ref().map(|token| token.family_id),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_commits_complete_audit_payloads_and_outbox_for_users_rotation_and_reuse() {
    let database_url =
        database_url().expect("audit regression requires a live PostgreSQL database");
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let make = || {
        refresh_issuance(refresh_token_fixture(
            &fixture,
            tenant_id,
            Uuid::now_v7(),
            format!("audit-{}", Uuid::now_v7()),
            None,
        ))
    };
    for user_id in [None, Some(fixture.user_id)] {
        let mut input = make();
        input.user_id = user_id;
        input.refresh_token = None;
        assert_eq!(
            repository
                .commit_token_issuance(input.clone())
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        assert_issuance_audit(
            &mut connection,
            &input,
            &[(
                "token_issued",
                "token_lifecycle",
                issued_audit_fields(&input),
            )],
        )
        .await;
    }
    let original = make();
    assert_eq!(
        repository
            .commit_token_issuance(original.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    assert_issuance_audit(
        &mut connection,
        &original,
        &[(
            "token_issued",
            "token_lifecycle",
            issued_audit_fields(&original),
        )],
    )
    .await;
    let source = original.refresh_token.as_ref().unwrap();
    let source_id = tokens
        .by_raw_refresh_token(tenant_id, &source.raw_token)
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut rotated = make();
    let refresh = rotated.refresh_token.as_mut().unwrap();
    refresh.family_id = source.family_id;
    refresh.rotated_from_id = Some(source_id);
    assert_eq!(
        repository
            .commit_token_issuance(rotated.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    assert_issuance_audit(
        &mut connection,
        &rotated,
        &[
            (
                "token_issued",
                "token_lifecycle",
                issued_audit_fields(&rotated),
            ),
            (
                "refresh_rotated",
                "token_lifecycle",
                json!({"token_family_id": source.family_id, "rotated_from_id": source_id}),
            ),
        ],
    )
    .await;
    let mut reuse = rotated;
    reuse.issuance_id = Uuid::now_v7();
    reuse.access_token_jti = reuse.issuance_id.to_string();
    reuse.refresh_token.as_mut().unwrap().raw_token = format!("reuse-{}", reuse.issuance_id);
    assert_eq!(
        repository
            .commit_token_issuance(reuse.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::RotationConflict
    );
    assert_issuance_audit(&mut connection, &reuse, &[
        ("refresh_reuse_detected", "token_replay", json!({"token_family_id": source.family_id, "rotated_from_id": source_id, "source_token_id": null})),
    ]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_token_client_attestation_binding_round_trips() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let raw_token = format!("attested-refresh-{}", Uuid::now_v7());
    let mut token =
        refresh_token_fixture(&fixture, tenant_id, Uuid::now_v7(), raw_token.clone(), None);
    token.client_attestation_jkt = Some("client-instance-jkt-thumbprint".to_owned());
    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());

    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(token))
            .await
            .expect("attested refresh token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let loaded = repository
        .by_raw_refresh_token(tenant_id, &raw_token)
        .await
        .expect("attested refresh token should load")
        .expect("attested refresh token should exist");

    assert_eq!(
        loaded.client_attestation_jkt.as_deref(),
        Some("client-instance-jkt-thumbprint")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_token_authentication_context_round_trips_and_rejects_invalid_values() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let raw_token = format!("context-refresh-{}", Uuid::now_v7());
    let token = refresh_token_fixture(&fixture, tenant_id, Uuid::now_v7(), raw_token.clone(), None);
    let expected_context = token.authentication_context.clone();
    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(token))
            .await
            .expect("refresh token with a complete authentication context should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let loaded = repository
        .by_raw_refresh_token(tenant_id, &raw_token)
        .await
        .expect("refresh token should load with its authentication context")
        .expect("the persisted refresh token should exist");
    assert_eq!(loaded.authentication_context, expected_context);

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let invalid_values = [
        json!("not-an-authentication-context"),
        json!({
            "version": 2,
            "issuer": "https://issuer.example",
            "audience": fixture.client_public_id,
            "auth_time": 1_700_000_000_i64,
            "amr": ["pwd"],
            "oidc_sid": null,
            "id_token_sid": null,
            "acr": null,
            "nonce": null,
            "userinfo_claims": [],
            "userinfo_claim_requests": [],
            "id_token_claims": [],
            "id_token_claim_requests": []
        }),
    ];
    for invalid_value in invalid_values {
        let result = sql_query("UPDATE oauth_tokens SET oidc_auth_context = $2 WHERE id = $1")
            .bind::<SqlUuid, _>(loaded.id)
            .bind::<diesel::sql_types::Jsonb, _>(invalid_value)
            .execute(&mut connection)
            .await;
        assert!(
            result.is_err(),
            "the database must reject an invalid refresh authentication context"
        );
    }
    let null_result = sql_query("UPDATE oauth_tokens SET oidc_auth_context = NULL WHERE id = $1")
        .bind::<SqlUuid, _>(loaded.id)
        .execute(&mut connection)
        .await;
    assert!(
        null_result.is_err(),
        "the database must reject a missing refresh authentication context"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_family_requires_one_root_and_matching_direct_parent_context() {
    let database_url =
        database_url().expect("refresh-family regression requires a live PostgreSQL database");
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let issuance = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());

    let chain_family = Uuid::now_v7();
    let root_raw = format!("direct-parent-root-{}", Uuid::now_v7());
    let root = refresh_token_fixture(&fixture, tenant_id, chain_family, root_raw.clone(), None);
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(root))
            .await
            .expect("root refresh token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let root_id = tokens
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .expect("root refresh token should load")
        .expect("root refresh token should exist")
        .id;
    let child_raw = format!("direct-parent-child-{}", Uuid::now_v7());
    let child = refresh_token_fixture(
        &fixture,
        tenant_id,
        chain_family,
        child_raw.clone(),
        Some(root_id),
    );
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(child))
            .await
            .expect("direct child should rotate"),
        CommitTokenIssuanceResult::Committed
    );
    let child_id = tokens
        .by_raw_refresh_token(tenant_id, &child_raw)
        .await
        .expect("child refresh token should load")
        .expect("child refresh token should exist")
        .id;
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                chain_family,
                format!("direct-parent-grandchild-{}", Uuid::now_v7()),
                Some(child_id),
            )))
            .await
            .expect("grandchild should rotate from its direct parent"),
        CommitTokenIssuanceResult::Committed
    );

    let duplicate_root_family = Uuid::now_v7();
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                duplicate_root_family,
                format!("duplicate-root-first-{}", Uuid::now_v7()),
                None,
            )))
            .await
            .expect("first root refresh token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                duplicate_root_family,
                format!("duplicate-root-second-{}", Uuid::now_v7()),
                None,
            )))
            .await
            .expect("duplicate root should be classified"),
        CommitTokenIssuanceResult::RotationConflict
    );
    assert!(
        !tokens
            .family_active(tenant_id, duplicate_root_family, fixture.user_id)
            .await
            .expect("duplicate-root family state should load")
    );

    let context_mismatch_family = Uuid::now_v7();
    let context_root_raw = format!("context-parent-root-{}", Uuid::now_v7());
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                context_mismatch_family,
                context_root_raw.clone(),
                None,
            )))
            .await
            .expect("context root should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let context_root_id = tokens
        .by_raw_refresh_token(tenant_id, &context_root_raw)
        .await
        .expect("context root should load")
        .expect("context root should exist")
        .id;
    let mut mismatched_context = refresh_token_fixture(
        &fixture,
        tenant_id,
        context_mismatch_family,
        format!("context-parent-child-{}", Uuid::now_v7()),
        Some(context_root_id),
    );
    mismatched_context.authentication_context.nonce = Some("different-authentication".to_owned());
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(mismatched_context))
            .await
            .expect("context mismatch should be classified"),
        CommitTokenIssuanceResult::RotationConflict
    );
    assert!(
        !tokens
            .family_active(tenant_id, context_mismatch_family, fixture.user_id)
            .await
            .expect("context-mismatch family state should load")
    );

    let owner_mismatch_family = Uuid::now_v7();
    let owner_root_raw = format!("owner-parent-root-{}", Uuid::now_v7());
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                owner_mismatch_family,
                owner_root_raw.clone(),
                None,
            )))
            .await
            .expect("owner root should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let owner_root_id = tokens
        .by_raw_refresh_token(tenant_id, &owner_root_raw)
        .await
        .expect("owner root should load")
        .expect("owner root should exist")
        .id;
    let mut wrong_subject = refresh_token_fixture(
        &fixture,
        tenant_id,
        owner_mismatch_family,
        format!("owner-parent-child-{}", Uuid::now_v7()),
        Some(owner_root_id),
    );
    wrong_subject.user_id = None;
    wrong_subject.subject = fixture.client_public_id.clone();
    assert_eq!(
        issuance
            .commit_token_issuance(refresh_issuance(wrong_subject))
            .await
            .expect("a parent owned by another subject should be classified"),
        CommitTokenIssuanceResult::RotationConflict
    );
    assert!(
        !tokens
            .family_active(tenant_id, owner_mismatch_family, fixture.user_id)
            .await
            .expect("owner-mismatch family state should load")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_waits_for_principal_deactivation_and_rechecks_the_committed_state() {
    let database_url = database_url()
        .expect("principal-deactivation regression requires a live PostgreSQL database");
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    for (principal_table, expected) in [
        ("oauth_clients", CommitTokenIssuanceResult::ClientInactive),
        ("users", CommitTokenIssuanceResult::SubjectInactive),
    ] {
        let fixture = fixture(&database_url).await;
        let principal_id = if principal_table == "oauth_clients" {
            fixture.client_id
        } else {
            fixture.user_id
        };
        let raw_token = format!(
            "principal-deactivation-{principal_table}-{}",
            Uuid::now_v7()
        );
        let input = refresh_issuance(refresh_token_fixture(
            &fixture,
            tenant_id,
            Uuid::now_v7(),
            raw_token.clone(),
            None,
        ));
        let application_name = format!("issuance-{principal_table}-{}", Uuid::now_v7().simple());
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
            .expect("principal deactivation transaction should begin");
        let changed = match principal_table {
            "oauth_clients" => {
                sql_query("UPDATE oauth_clients SET is_active = FALSE WHERE id = $1")
                    .bind::<SqlUuid, _>(principal_id)
                    .execute(&mut coordinator)
                    .await
            }
            "users" => {
                sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
                    .bind::<SqlUuid, _>(principal_id)
                    .execute(&mut coordinator)
                    .await
            }
            _ => unreachable!("test principal table is fixed"),
        }
        .expect("principal deactivation should hold its row lock");
        assert_eq!(changed, 1, "principal fixture must be active");
        let mut issuer = tokio::spawn(async move { repository.commit_token_issuance(input).await });
        wait_for_lock_wait_or_task(&mut observer, &application_name, &mut issuer).await;
        coordinator
            .batch_execute("COMMIT")
            .await
            .expect("principal deactivation should commit");
        assert_eq!(
            issuer
                .await
                .expect("issuance task should join")
                .expect("issuance should classify a committed deactivation"),
            expected
        );
        assert!(
            TokenRepository::new(create_pool(&database_url, 1).unwrap())
                .by_raw_refresh_token(tenant_id, &raw_token)
                .await
                .expect("refresh lookup should succeed")
                .is_none(),
            "issuance must not persist a refresh token after {principal_table} deactivation"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_deactivation_waits_for_issuance_and_revokes_committed_credentials() {
    let database_url = database_url()
        .expect("issuance/deactivation regression requires a live PostgreSQL database");
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url).await;
    let family_id = Uuid::now_v7();
    let raw_token = format!("issuance-before-deactivation-{}", Uuid::now_v7());
    let input = refresh_issuance(refresh_token_fixture(
        &fixture, tenant_id, family_id, raw_token, None,
    ));
    let access_token_jti = input.access_token_jti.clone();
    let gate_key = family_lock_key(family_id).wrapping_add(1);
    let mut coordinator = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test coordinator should connect");
    let (trigger, function) =
        install_issuance_insert_gate(&mut coordinator, fixture.client_id, gate_key).await;
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold token issuance gate");

    let issuance_application = format!("issuance-before-deactivation-{}", Uuid::now_v7().simple());
    let issuance = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &issuance_application), 1).unwrap(),
    );
    let mut issuer = tokio::spawn(async move { issuance.commit_token_issuance(input).await });
    wait_for_lock_wait_or_task(&mut coordinator, &issuance_application, &mut issuer).await;

    let deactivation_application =
        format!("deactivation-after-issuance-{}", Uuid::now_v7().simple());
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
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release token issuance gate");
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
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("refresh family state should load"),
        "deactivation must revoke the refresh token committed while it was blocked"
    );
    remove_issuance_insert_gate(&mut coordinator, &trigger, &function).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    repository
        .ensure(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("device grant retry should be idempotent");
    repository
        .ensure(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &["resource://default".to_owned()],
            &json!([]),
        )
        .await
        .expect("duplicate device grant retry should remain idempotent");
    let stored = repository
        .authorization(tenant_id, fixture.user_id, fixture.client_id)
        .await
        .expect("grant should load")
        .expect("grant should exist");
    assert_eq!(stored.authorization_count, 2);

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let token_hash = Uuid::now_v7().simple().to_string().repeat(2);
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            audience, authorization_details, issued_at, expires_at, subject,
            oidc_auth_context
        ) VALUES (
            '{token_hash}', '{}', '{}', '{}', '["openid", "offline_access"]'::jsonb,
            '["resource://default"]'::jsonb, '[]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}',
            '{context}'::jsonb
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
        .revoke_by_client_id(tenant_id, fixture.user_id, &fixture.client_public_id)
        .await
        .expect("grant revocation should commit");
    assert_eq!(revoked.revoked_refresh_tokens, 1);
    assert_eq!(revoked.removed_grants, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_revoke_waits_for_concurrent_refresh_rotation_before_revoking_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let original_raw = format!("grant-race-original-{}", Uuid::now_v7());
    let successor_raw = format!("grant-race-successor-{}", Uuid::now_v7());
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                family_id,
                original_raw.clone(),
                None,
            )))
            .await
            .expect("original refresh token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let original = tokens
        .by_raw_refresh_token(tenant_id, &original_raw)
        .await
        .expect("original refresh token should load")
        .expect("original refresh token should exist");

    let grants = GrantRepository::new(create_pool(&database_url, 4).unwrap());
    grants
        .upsert(
            tenant_id,
            fixture.user_id,
            fixture.client_id,
            &["openid".to_owned(), "offline_access".to_owned()],
            &[],
            &json!([]),
        )
        .await
        .expect("grant should insert");

    let gate_key = family_lock_key(family_id).wrapping_add(1);
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    let (trigger, function) =
        install_rotation_insert_gate(&mut coordinator, family_id, gate_key).await;
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold rotation insert gate");

    let rotation_application = format!("grant-rotation-{}", Uuid::now_v7().simple());
    let rotation_repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &rotation_application), 1).unwrap(),
    );
    let successor = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        successor_raw,
        Some(original.id),
    );
    let rotation = tokio::spawn(async move {
        rotation_repository
            .commit_token_issuance(refresh_issuance(successor))
            .await
    });
    wait_for_lock_wait(&mut coordinator, &rotation_application).await;

    let revoke_application = format!("grant-revoke-{}", Uuid::now_v7().simple());
    let revoke_repository = GrantRepository::new(
        create_pool(tagged_database_url(&database_url, &revoke_application), 1).unwrap(),
    );
    let user_id = fixture.user_id;
    let client_public_id = fixture.client_public_id.clone();
    let revoke = tokio::spawn(async move {
        revoke_repository
            .revoke_by_client_id(tenant_id, user_id, &client_public_id)
            .await
    });
    wait_for_lock_wait(&mut coordinator, &revoke_application).await;

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release rotation insert gate");
    assert_eq!(
        rotation
            .await
            .expect("rotation task should join")
            .expect("rotation should commit"),
        CommitTokenIssuanceResult::Committed
    );
    let revoked = revoke
        .await
        .expect("grant revoke task should join")
        .expect("grant revoke should commit");
    assert_eq!(revoked.removed_grants, 1);
    assert!(
        grants
            .authorization(tenant_id, fixture.user_id, fixture.client_id)
            .await
            .expect("grant state should load")
            .is_none()
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("refresh family state should load"),
        "grant revoke returned while a concurrently rotated successor remained active"
    );
    remove_rotation_insert_gate(&mut coordinator, &trigger, &function).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_rotation_reuse_compromises_the_whole_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();
    let repository = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    let make = |label: &str, rotated_from_id| {
        refresh_token_fixture(
            &fixture,
            tenant_id,
            family_id,
            format!("auth-repo-{label}-{suffix}"),
            rotated_from_id,
        )
    };
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(make("original", None)))
            .await
            .expect("original token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let original = repository
        .by_raw_refresh_token(tenant_id, &format!("auth-repo-original-{suffix}"))
        .await
        .expect("original token should load")
        .expect("original token should exist");
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(make("successor", Some(original.id))))
            .await
            .expect("successor should rotate"),
        CommitTokenIssuanceResult::Committed
    );
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(make("reuse", Some(original.id))))
            .await
            .expect("reuse should be classified"),
        CommitTokenIssuanceResult::RotationConflict
    );
    assert!(
        !repository
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("family state should load")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            audience, authorization_details, issued_at, expires_at, subject,
            oidc_auth_context
        ) VALUES (
            '{token_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
            '["resource://default"]'::jsonb, '[]'::jsonb,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}',
            '{context}'::jsonb
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_management_revocation_is_client_scoped_idempotent_and_serializes_family() {
    let Some(database_url) = database_url() else {
        return;
    };
    let owner = fixture(&database_url).await;
    let foreign = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let first = format!("revocation-first-{}", Uuid::now_v7());
    let second = format!("revocation-second-{}", Uuid::now_v7());
    let first_hash = blake3::hash(first.as_bytes()).to_hex().to_string();
    let second_hash = blake3::hash(second.as_bytes()).to_hex().to_string();
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let context = refresh_context_json(&owner.client_public_id, chrono::Utc::now());
    sql_query(format!(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, token_family_id, client_id, user_id, scopes,
            audience, authorization_details, issued_at, expires_at, subject,
            oidc_auth_context
        ) VALUES
            ('{first_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
             '["resource://default"]'::jsonb, '[]'::jsonb,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}',
             '{context}'::jsonb),
            ('{second_hash}', '{family_id}', '{}', '{}', '["openid"]'::jsonb,
             '["resource://default"]'::jsonb, '[]'::jsonb,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 hour', '{}',
             '{context}'::jsonb)
        "#,
        owner.client_id,
        owner.user_id,
        owner.user_id,
        owner.client_id,
        owner.user_id,
        owner.user_id,
    ))
    .execute(&mut connection)
    .await
    .expect("refresh family fixture should insert");

    let foreign_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let foreign_result = foreign_repository
        .revoke_token(TokenRevocation {
            tenant_id,
            client_id: foreign.client_id,
            raw_token: &first,
            access_token: None,
        })
        .await
        .expect("foreign revocation must remain non-disclosing");
    assert_eq!(foreign_result, 0);

    let first_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let second_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let (first_result, second_result) = tokio::join!(
        first_repository.revoke_token(TokenRevocation {
            tenant_id,
            client_id: owner.client_id,
            raw_token: &first,
            access_token: None,
        }),
        second_repository.revoke_token(TokenRevocation {
            tenant_id,
            client_id: owner.client_id,
            raw_token: &second,
            access_token: None,
        }),
    );
    assert_eq!(
        first_result.unwrap() + second_result.unwrap(),
        2,
        "one serialized revocation must revoke the complete active family"
    );

    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    assert_eq!(
        repository
            .revoke_token(TokenRevocation {
                tenant_id,
                client_id: owner.client_id,
                raw_token: &first,
                access_token: None,
            })
            .await
            .expect("repeat family revocation should be idempotent"),
        0
    );

    let access_jti = format!("revocation-access-{}", Uuid::now_v7());
    for _ in 0..2 {
        repository
            .revoke_token(TokenRevocation {
                tenant_id,
                client_id: owner.client_id,
                raw_token: "opaque-access-token",
                access_token: Some(AccessTokenRevocation {
                    jti: access_jti.clone(),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                }),
            })
            .await
            .expect("access-token revocation should be idempotent");
    }

    let active_family = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE token_family_id = $1 AND revoked_at IS NULL",
    )
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(active_family.count, 0);
    let access_revocations = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM access_token_revocations \
         WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(owner.client_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(access_revocations.count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorization_replay_waits_for_concurrent_refresh_rotation_before_compensation() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let original_raw = format!("replay-race-original-{}", Uuid::now_v7());
    let successor_raw = format!("replay-race-successor-{}", Uuid::now_v7());
    let access_jti = format!("replay-race-access-{}", Uuid::now_v7());
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(refresh_issuance(refresh_token_fixture(
                &fixture,
                tenant_id,
                family_id,
                original_raw.clone(),
                None,
            )))
            .await
            .expect("original refresh token should persist"),
        CommitTokenIssuanceResult::Committed
    );
    let original = tokens
        .by_raw_refresh_token(tenant_id, &original_raw)
        .await
        .expect("original refresh token should load")
        .expect("original refresh token should exist");

    let gate_key = family_lock_key(family_id).wrapping_add(1);
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    let (trigger, function) =
        install_rotation_insert_gate(&mut coordinator, family_id, gate_key).await;
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold rotation insert gate");

    let rotation_application = format!("replay-rotation-{}", Uuid::now_v7().simple());
    let rotation_repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &rotation_application), 1).unwrap(),
    );
    let successor = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        successor_raw,
        Some(original.id),
    );
    let rotation = tokio::spawn(async move {
        rotation_repository
            .commit_token_issuance(refresh_issuance(successor))
            .await
    });
    wait_for_lock_wait(&mut coordinator, &rotation_application).await;

    let compensation_application = format!("replay-compensation-{}", Uuid::now_v7().simple());
    let compensation_repository = AuthorizationRepository::new(
        create_pool(
            tagged_database_url(&database_url, &compensation_application),
            1,
        )
        .unwrap(),
    );
    let client_id = fixture.client_id;
    let access_jti_for_task = access_jti.clone();
    let compensation = tokio::spawn(async move {
        compensation_repository
            .revoke_issued_tokens(
                tenant_id,
                client_id,
                &access_jti_for_task,
                Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                Some(family_id),
            )
            .await
    });
    wait_for_lock_wait(&mut coordinator, &compensation_application).await;

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(gate_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release rotation insert gate");
    assert_eq!(
        rotation
            .await
            .expect("rotation task should join")
            .expect("rotation should commit"),
        CommitTokenIssuanceResult::Committed
    );
    compensation
        .await
        .expect("compensation task should join")
        .expect("authorization replay compensation should commit");
    assert!(
        tokens
            .access_token_revoked(tenant_id, &access_jti)
            .await
            .expect("access token compensation should load")
    );
    assert!(
        !tokens
            .family_active(tenant_id, family_id, fixture.user_id)
            .await
            .expect("refresh family state should load"),
        "authorization replay compensation returned while a rotated successor remained active"
    );
    remove_rotation_insert_gate(&mut coordinator, &trigger, &function).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_repository_records_scim_use_and_drives_logout_outbox() {
    let _claim_guard = BACKCHANNEL_CLAIM_TEST_LOCK.lock().await;
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

    let logout_token = format!("logout-token-test-{}", Uuid::now_v7());
    repository
        .enqueue_backchannel_logout(
            tenant_id,
            fixture.client_id,
            &fixture.client_public_id,
            "https://client.example/backchannel-logout",
            &logout_token,
            chrono::Utc::now() + chrono::Duration::minutes(2),
        )
        .await
        .expect("backchannel delivery should enqueue");
    let claimed = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("backchannel delivery should claim");
    let claimed = claimed
        .into_iter()
        .find(|delivery| delivery.logout_token == logout_token)
        .expect("the test delivery should be claimed");
    repository
        .complete_backchannel_logout(claimed.id, claimed.attempts)
        .await
        .expect("backchannel delivery should complete");
    let reclaimed = repository
        .claim_due_backchannel_logout(100, 300)
        .await
        .expect("completed delivery should not reclaim");
    assert!(
        reclaimed.iter().all(|delivery| delivery.id != claimed.id),
        "the completed delivery must not be reclaimed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backchannel_logout_fanout_rolls_back_when_any_delivery_is_invalid() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let repository = AuditRepository::new(create_pool(&database_url, 4).unwrap());
    let marker = format!("logout-atomic-{}", Uuid::now_v7());
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(2);
    let result = repository
        .enqueue_backchannel_logout_batch(&[
            PendingBackchannelLogoutDelivery {
                tenant_id,
                client_id: fixture.client_id,
                client_public_id: fixture.client_public_id,
                logout_uri: "https://client.example/backchannel-logout".to_owned(),
                logout_token: marker.clone(),
                expires_at,
            },
            PendingBackchannelLogoutDelivery {
                tenant_id,
                client_id: Uuid::now_v7(),
                client_public_id: "missing-client".to_owned(),
                logout_uri: "https://missing.example/backchannel-logout".to_owned(),
                logout_token: format!("{marker}-invalid"),
                expires_at,
            },
        ])
        .await;
    assert!(
        result.is_err(),
        "invalid fan-out member must fail the batch"
    );

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let count = sql_query(
        "SELECT COUNT(*) AS count FROM backchannel_logout_deliveries WHERE logout_token = $1",
    )
    .bind::<Text, _>(&marker)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("backchannel rollback count should load");
    assert_eq!(count.count, 0, "fan-out must commit all deliveries or none");
}

#[test]
fn server_auth_callers_do_not_query_diesel_or_auth_tables() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for relative in [
        "authorization-server/src/domain/rows.rs",
        "nazoauth/src/http/admin/grants.rs",
        "authorization-server/src/authorization/request/prompt_none.rs",
        "authorization-server/src/domain/scim.rs",
        "authorization-server/src/token/issue/authorization_code_state.rs",
        "authorization-server/src/token/issue/refresh_persistence.rs",
        "authorization-server/src/token/native_sso.rs",
        "authorization-server/src/token/refresh.rs",
        "authorization-server/src/token/token_exchange.rs",
        "authorization-server/src/domain/userinfo.rs",
        "authorization-server/src/domain/client_policy.rs",
        "nazoauth/src/http/views.rs",
    ] {
        let source = std::fs::read_to_string(crates.join(relative))
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
    for package in ["authorization-server", "nazoauth"] {
        assert!(
            !crates.join(package).join("src/schema.rs").exists(),
            "server production source must not contain a test-only Diesel schema"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_logout_worker_cannot_complete_or_fail_a_reclaimed_delivery() {
    let _claim_guard = BACKCHANNEL_CLAIM_TEST_LOCK.lock().await;
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
            &fixture.client_public_id,
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

// ---------------------------------------------------------------------------
// Refresh-rotation conflict (DB-005/DB-006) and SELECT EXISTS (DB-010) matrix
// coverage.  Helpers below stay private to this file and only append.
//
// These tests share the database with the gated concurrency tests above: a
// parked gated transaction can queue trigger DDL ahead of an ordinary commit
// long enough to trip the 2s lock_timeout inside commit_token_issuance.
// Serializing the added tests among themselves keeps their combined lock
// footprint small; `retry_token_infra` absorbs the residual queue waits.
// ---------------------------------------------------------------------------
static ROTATION_MATRIX_TEST_LOCK: Mutex<()> = Mutex::const_new(());

/// Field-level description of one directly inserted `oauth_tokens` row.
struct RawRefreshRow<'a> {
    tenant_id: Uuid,
    family_id: Uuid,
    rotated_from_id: Option<Uuid>,
    client_id: Uuid,
    user_id: Option<Uuid>,
    subject: &'a str,
    raw_token: &'a str,
    dpop_jkt: Option<&'a str>,
    /// Offset from now in seconds; `None` leaves the row unrevoked.
    revoked_offset_seconds: Option<i32>,
    /// Offset from now in seconds for `expires_at`.
    expires_offset_seconds: i32,
    reuse_detected: bool,
    context_json: &'a str,
}

async fn insert_refresh_row(connection: &mut AsyncPgConnection, row: &RawRefreshRow<'_>) -> Uuid {
    #[derive(QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = SqlUuid)]
        id: Uuid,
    }
    sql_query(
        r#"
        INSERT INTO oauth_tokens (
            refresh_token_blake3, tenant_id, token_family_id, rotated_from_id,
            client_id, user_id, scopes, audience, authorization_details,
            issued_at, expires_at, revoked_at, reuse_detected_at, subject,
            dpop_jkt, oidc_auth_context
        ) VALUES (
            $1, $2, $3, $4, $5, $6, '["openid", "offline_access"]'::jsonb,
            '["resource://default"]'::jsonb, '[]'::jsonb,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP + ($7 * INTERVAL '1 second'),
            CURRENT_TIMESTAMP + ($8 * INTERVAL '1 second'),
            CASE WHEN $9 THEN CURRENT_TIMESTAMP ELSE NULL END,
            $10, $11, $12::jsonb
        ) RETURNING id
        "#,
    )
    .bind::<Text, _>(blake3::hash(row.raw_token.as_bytes()).to_hex().to_string())
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<SqlUuid, _>(row.family_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(row.rotated_from_id)
    .bind::<SqlUuid, _>(row.client_id)
    .bind::<diesel::sql_types::Nullable<SqlUuid>, _>(row.user_id)
    .bind::<diesel::sql_types::Integer, _>(row.expires_offset_seconds)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Integer>, _>(row.revoked_offset_seconds)
    .bind::<diesel::sql_types::Bool, _>(row.reuse_detected)
    .bind::<Text, _>(row.subject)
    .bind::<diesel::sql_types::Nullable<Text>, _>(row.dpop_jkt)
    .bind::<Text, _>(row.context_json)
    .get_result::<IdRow>(connection)
    .await
    .expect("raw refresh token row should insert")
    .id
}

/// Default raw-row template for the shared system tenant fixture.
fn raw_refresh_row<'a>(
    fixture: &'a FixtureIds,
    tenant_id: Uuid,
    family_id: Uuid,
    raw_token: &'a str,
    context_json: &'a str,
) -> RawRefreshRow<'a> {
    RawRefreshRow {
        tenant_id,
        family_id,
        rotated_from_id: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        subject: "raw-refresh-subject",
        raw_token,
        dpop_jkt: None,
        revoked_offset_seconds: None,
        expires_offset_seconds: 3600,
        reuse_detected: false,
        context_json,
    }
}

/// Bounded retry for token-repository calls that may abort on transient
/// lock-queue timeouts.  The shared test database serializes the gated
/// concurrency tests' `CREATE`/`DROP TRIGGER` DDL on `oauth_tokens` and
/// `oauth_token_issuances` behind parked rotation transactions, so an
/// unrelated commit can hit its 2s `lock_timeout` through no fault of the
/// path under test.  An `Err` always means the transaction rolled back, so
/// retrying is safe; business verdicts return immediately and deterministic
/// failures still surface after the last attempt.
async fn retry_token_infra<T, Fut>(
    mut call: impl FnMut() -> Fut,
) -> Result<T, nazo_auth::TokenPortError>
where
    Fut: std::future::Future<Output = Result<T, nazo_auth::TokenPortError>>,
{
    let mut last_error = None;
    for _ in 0..4 {
        match call().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(error);
                tokio::task::yield_now().await;
            }
        }
    }
    Err(last_error.expect("at least one attempt must run"))
}

async fn commit_refresh(
    database_url: &str,
    token: NewRefreshToken,
) -> (CommitTokenIssuanceResult, CommitTokenIssuance) {
    commit_refresh_labeled(database_url, token, "rotation commit").await
}

async fn commit_refresh_labeled(
    database_url: &str,
    token: NewRefreshToken,
    label: &str,
) -> (CommitTokenIssuanceResult, CommitTokenIssuance) {
    let input = refresh_issuance(token);
    let repository = TokenIssuanceRepository::new(create_pool(database_url, 2).unwrap());
    let result = retry_token_infra(|| repository.commit_token_issuance(input.clone()))
        .await
        .unwrap_or_else(|error| panic!("{label} should return a business result: {error:?}"));
    (result, input)
}

/// Durable facts that every ordinary-rotation business conflict must leave
/// behind: no extra family rows, the losing issuance row deleted, exactly one
/// `refresh_reuse_detected` audit (pending in the outbox) and no `token_issued`
/// audit for the losing issuance.
async fn assert_rotation_conflict_facts(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    family_id: Uuid,
    losing: &CommitTokenIssuance,
    expected_family_rows: i64,
    expected_compromised_rows: i64,
    expected_active_rows: i64,
) {
    let totals = sql_query(
        "SELECT \
            COUNT(*)::bigint AS count, \
            COUNT(*) FILTER (WHERE reuse_detected_at IS NOT NULL)::bigint AS compromised, \
            COUNT(*) FILTER (WHERE revoked_at IS NULL)::bigint AS active \
         FROM oauth_tokens WHERE tenant_id = $1 AND token_family_id = $2",
    );
    #[derive(QueryableByName)]
    struct FamilyCounts {
        #[diesel(sql_type = BigInt)]
        count: i64,
        #[diesel(sql_type = BigInt)]
        compromised: i64,
        #[diesel(sql_type = BigInt)]
        active: i64,
    }
    let counts = totals
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(family_id)
        .get_result::<FamilyCounts>(connection)
        .await
        .expect("family counts should load");
    assert_eq!(counts.count, expected_family_rows, "family row total");
    assert_eq!(
        counts.compromised, expected_compromised_rows,
        "compromise marks reuse_detected_at on every tenant-scoped family row"
    );
    assert_eq!(counts.active, expected_active_rows, "active family rows");
    let issuance = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<SqlUuid, _>(losing.issuance_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("losing issuance count should load");
    assert_eq!(issuance.count, 0, "the losing issuance row must be deleted");
    let rotated_from_id = losing
        .refresh_token
        .as_ref()
        .expect("conflict fixture carries a refresh token")
        .rotated_from_id;
    let source_token_id = losing
        .refresh_token
        .as_ref()
        .and_then(|refresh| refresh.lost_response_retry)
        .map(|retry| retry.original_id);
    assert_issuance_audit(
        connection,
        losing,
        &[(
            "refresh_reuse_detected",
            "token_replay",
            json!({
                "token_family_id": family_id,
                "rotated_from_id": rotated_from_id,
                "source_token_id": source_token_id,
            }),
        )],
    )
    .await;
}

/// Inserts a complete second tenant (tenant + realm + organization + client)
/// so a parent row can live outside the acting tenant's scope.
async fn insert_foreign_tenant_client(connection: &mut AsyncPgConnection) -> (Uuid, Uuid, String) {
    let tenant_id = Uuid::now_v7();
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let public_id = format!("foreign-tenant-client-{}", Uuid::now_v7().simple());
    let security_policy = r#"{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}"#;
    #[derive(QueryableByName)]
    struct ClientRow {
        #[diesel(sql_type = SqlUuid)]
        id: Uuid,
    }
    let client = sql_query(format!(
        r#"
        WITH tenant AS (
            INSERT INTO tenants (id, slug, display_name)
            VALUES ('{tenant_id}', 'foreign-{tenant_id}', 'Foreign Tenant')
        ), realm AS (
            INSERT INTO realms (id, tenant_id, slug, display_name)
            VALUES ('{realm_id}', '{tenant_id}', 'foreign', 'Foreign Realm')
        ), organization AS (
            INSERT INTO organizations (id, tenant_id, slug, display_name)
            VALUES ('{organization_id}', '{tenant_id}', 'foreign', 'Foreign Org')
        )
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            redirect_uris, scopes, grant_types, token_endpoint_auth_method, security_policy
        ) VALUES (
            '{tenant_id}', '{realm_id}', '{organization_id}', '{public_id}',
            'Foreign Tenant Client', 'confidential',
            '["https://foreign.example/callback"]'::jsonb, '["openid", "offline_access"]'::jsonb,
            '["authorization_code", "refresh_token"]'::jsonb, 'client_secret_basic',
            '{security_policy}'::jsonb
        ) RETURNING id
        "#,
    ))
    .get_result::<ClientRow>(connection)
    .await
    .expect("foreign tenant client should insert")
    .id;
    (tenant_id, client, public_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_rotation_parent_misses_compromise_family_and_commit_reuse_audit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let foreign = fixture(&database_url).await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    // Parent id does not exist at all: the conditional update finds zero
    // rows.  Parent state is staged with direct inserts so only the rotation
    // under test pays a real commit (raw inserts simply wait out queued DDL
    // instead of expiring on the transaction lock_timeout).
    let missing_family = Uuid::now_v7();
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());
    insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            missing_family,
            &format!("missing-parent-root-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    let (result, losing) = commit_refresh(
        &database_url,
        refresh_token_fixture(
            &fixture,
            tenant_id,
            missing_family,
            format!("missing-parent-child-{}", Uuid::now_v7()),
            Some(Uuid::now_v7()),
        ),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(&mut connection, tenant_id, missing_family, &losing, 1, 1, 0)
        .await;

    // Parent already consumed by an earlier rotation: a revoked root plus
    // the active successor that consumed it.
    let consumed_family = Uuid::now_v7();
    let consumed_root_raw = format!("consumed-root-{}", Uuid::now_v7());
    let mut consumed_root = raw_refresh_row(
        &fixture,
        tenant_id,
        consumed_family,
        &consumed_root_raw,
        &context,
    );
    consumed_root.revoked_offset_seconds = Some(0);
    let consumed_root_id = insert_refresh_row(&mut connection, &consumed_root).await;
    let consumed_child_raw = format!("consumed-first-child-{}", Uuid::now_v7());
    let mut consumed_first_child = raw_refresh_row(
        &fixture,
        tenant_id,
        consumed_family,
        &consumed_child_raw,
        &context,
    );
    consumed_first_child.rotated_from_id = Some(consumed_root_id);
    insert_refresh_row(&mut connection, &consumed_first_child).await;
    let (result, losing) = commit_refresh(
        &database_url,
        refresh_token_fixture(
            &fixture,
            tenant_id,
            consumed_family,
            format!("consumed-second-child-{}", Uuid::now_v7()),
            Some(consumed_root_id),
        ),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(
        &mut connection,
        tenant_id,
        consumed_family,
        &losing,
        2,
        2,
        0,
    )
    .await;

    // The parent lives in a different family than the one being rotated into.
    let source_family = Uuid::now_v7();
    let other_family_root_id = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            source_family,
            &format!("other-family-root-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    let requested_family = Uuid::now_v7();
    let (result, losing) = commit_refresh(
        &database_url,
        refresh_token_fixture(
            &fixture,
            tenant_id,
            requested_family,
            format!("cross-family-child-{}", Uuid::now_v7()),
            Some(other_family_root_id),
        ),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    // The compromise is scoped to the requested family, which has no rows;
    // the source family stays untouched.
    assert_rotation_conflict_facts(
        &mut connection,
        tenant_id,
        requested_family,
        &losing,
        0,
        0,
        0,
    )
    .await;
    let untouched = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE tenant_id = $1 AND token_family_id = $2 \
           AND revoked_at IS NULL AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(source_family)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        untouched.count, 1,
        "a family-mismatched parent must not be compromised"
    );

    // Parent is owned by a different client.
    let client_family = Uuid::now_v7();
    let client_root_id = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            client_family,
            &format!("client-mismatch-root-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    let mut wrong_client = refresh_token_fixture(
        &fixture,
        tenant_id,
        client_family,
        format!("client-mismatch-child-{}", Uuid::now_v7()),
        Some(client_root_id),
    );
    wrong_client.client_id = foreign.client_id;
    let (result, losing) = commit_refresh(&database_url, wrong_client).await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(&mut connection, tenant_id, client_family, &losing, 1, 1, 0)
        .await;

    // Parent is owned by a different user.
    let user_family = Uuid::now_v7();
    let user_root_id = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            user_family,
            &format!("user-mismatch-root-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    let mut wrong_user = refresh_token_fixture(
        &fixture,
        tenant_id,
        user_family,
        format!("user-mismatch-child-{}", Uuid::now_v7()),
        Some(user_root_id),
    );
    wrong_user.user_id = Some(foreign.user_id);
    wrong_user.subject = foreign.user_id.to_string();
    let (result, losing) = commit_refresh(&database_url, wrong_user).await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(&mut connection, tenant_id, user_family, &losing, 1, 1, 0).await;

    // Parent belongs to a different tenant: the update misses and the
    // tenant-scoped compromise cannot touch the foreign row.
    let (foreign_tenant, foreign_client, foreign_public_id) =
        insert_foreign_tenant_client(&mut connection).await;
    let foreign_context = refresh_context_json(&foreign_public_id, chrono::Utc::now());
    let foreign_family = Uuid::now_v7();
    let foreign_raw = format!("foreign-parent-{}", Uuid::now_v7());
    let foreign_parent_id = insert_refresh_row(
        &mut connection,
        &RawRefreshRow {
            client_id: foreign_client,
            user_id: None,
            subject: &foreign_public_id,
            ..raw_refresh_row(
                &fixture,
                foreign_tenant,
                foreign_family,
                &foreign_raw,
                &foreign_context,
            )
        },
    )
    .await;
    let mut cross_tenant = refresh_token_fixture(
        &fixture,
        tenant_id,
        foreign_family,
        format!("cross-tenant-child-{}", Uuid::now_v7()),
        Some(foreign_parent_id),
    );
    cross_tenant.user_id = None;
    cross_tenant.subject = fixture.client_public_id.clone();
    let (result, losing) = commit_refresh(&database_url, cross_tenant).await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(&mut connection, tenant_id, foreign_family, &losing, 0, 0, 0)
        .await;
    let foreign_state = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE id = $1 AND revoked_at IS NULL AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(foreign_parent_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        foreign_state.count, 1,
        "the foreign-tenant parent must survive the conflict untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_rotation_context_mismatch_commits_compromise_and_reuse_audit() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let root_raw = format!("context-drift-root-{}", Uuid::now_v7());
    let (result, _) = commit_refresh(
        &database_url,
        refresh_token_fixture(&fixture, tenant_id, family_id, root_raw.clone(), None),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let root_id = TokenRepository::new(create_pool(&database_url, 1).unwrap())
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap()
        .id;

    let mut drifting = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        format!("context-drift-child-{}", Uuid::now_v7()),
        Some(root_id),
    );
    drifting.authentication_context.acr = Some("urn:example:loa2".to_owned());
    let (result, losing) = commit_refresh(&database_url, drifting).await;
    // The conditional update returns the row and the Rust-side comparison
    // fails; the compromise facts commit instead of propagating an error.
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    assert_rotation_conflict_facts(&mut connection, tenant_id, family_id, &losing, 1, 1, 0).await;
    let persisted_context = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE id = $1 AND oidc_auth_context ->> 'acr' IS NULL",
    )
    .bind::<SqlUuid, _>(root_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        persisted_context.count, 1,
        "the parent's stored context must remain the original one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_rotation_context_compare_uses_serde_value_semantics() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let authentication_time = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();

    // Helper: build the stored context JSON for a claim-request `value`.
    let context_with_claim = |value: serde_json::Value| {
        let mut context = serde_json::to_value(refresh_authentication_context(
            &fixture.client_public_id,
            authentication_time,
        ))
        .unwrap();
        context["userinfo_claim_requests"] = json!([{"name": "claim", "value": value}]);
        serde_json::to_string(&context).unwrap()
    };
    let claim_for = |value: serde_json::Value| nazo_auth::OidcClaimRequest {
        name: "claim".to_owned(),
        essential: false,
        value: Some(value),
        values: Vec::new(),
    };

    // `1` (integer) in the incoming context versus `1.0` (float) in the stored
    // jsonb: PostgreSQL `=` treats them as equal, serde_json::Value does not.
    let float_family = Uuid::now_v7();
    let stored_float = context_with_claim(json!(1.0));
    let float_parent = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            float_family,
            &format!("serde-float-parent-{}", Uuid::now_v7()),
            &stored_float,
        ),
    )
    .await;
    let mut float_child = refresh_token_fixture(
        &fixture,
        tenant_id,
        float_family,
        format!("serde-float-child-{}", Uuid::now_v7()),
        Some(float_parent),
    );
    float_child.authentication_context.userinfo_claim_requests = vec![claim_for(json!(1))];
    let float_input = refresh_issuance(float_child);
    let incoming_json = serde_json::to_value(
        &float_input
            .refresh_token
            .as_ref()
            .unwrap()
            .authentication_context,
    )
    .unwrap();
    #[derive(QueryableByName)]
    struct BoolRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        value: bool,
    }
    let pg_equal = sql_query(
        "SELECT (oidc_auth_context = $2::jsonb) AS value FROM oauth_tokens WHERE id = $1",
    )
    .bind::<SqlUuid, _>(float_parent)
    .bind::<Text, _>(serde_json::to_string(&incoming_json).unwrap())
    .get_result::<BoolRow>(&mut connection)
    .await
    .unwrap();
    assert!(
        pg_equal.value,
        "jsonb equality must consider 1 and 1.0 equal, so only a Rust-side serde_json::Value compare can reject this rotation"
    );
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let result = retry_token_infra(|| repository.commit_token_issuance(float_input.clone()))
        .await
        .expect("serde-visible context drift must classify as a business conflict");
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(
        &mut connection,
        tenant_id,
        float_family,
        &float_input,
        1,
        1,
        0,
    )
    .await;

    // `null` versus a missing member is likewise serde-visible.
    let null_family = Uuid::now_v7();
    let stored_null = context_with_claim(serde_json::Value::Null);
    let null_parent = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            null_family,
            &format!("serde-null-parent-{}", Uuid::now_v7()),
            &stored_null,
        ),
    )
    .await;
    let mut null_child = refresh_token_fixture(
        &fixture,
        tenant_id,
        null_family,
        format!("serde-null-child-{}", Uuid::now_v7()),
        Some(null_parent),
    );
    null_child.authentication_context.userinfo_claim_requests = vec![nazo_auth::OidcClaimRequest {
        name: "claim".to_owned(),
        essential: false,
        value: None,
        values: Vec::new(),
    }];
    let (result, losing) = commit_refresh(&database_url, null_child).await;
    assert_eq!(result, CommitTokenIssuanceResult::RotationConflict);
    assert_rotation_conflict_facts(&mut connection, tenant_id, null_family, &losing, 1, 1, 0).await;

    // The identical semantic context re-serialized stays equal and rotates.
    let equal_family = Uuid::now_v7();
    let stored_equal = context_with_claim(json!(1));
    let equal_parent = insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            equal_family,
            &format!("serde-equal-parent-{}", Uuid::now_v7()),
            &stored_equal,
        ),
    )
    .await;
    let mut equal_child = refresh_token_fixture(
        &fixture,
        tenant_id,
        equal_family,
        format!("serde-equal-child-{}", Uuid::now_v7()),
        Some(equal_parent),
    );
    equal_child.authentication_context.userinfo_claim_requests = vec![claim_for(json!(1))];
    let (result, _) = commit_refresh(&database_url, equal_child).await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let state = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE token_family_id = $1 AND revoked_at IS NULL AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(equal_family)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(state.count, 1, "the equal context must rotate cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_ordinary_rotations_commit_one_winner_and_one_committed_compromise() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let root_raw = format!("race-root-{}", Uuid::now_v7());
    let (result, _) = commit_refresh(
        &database_url,
        refresh_token_fixture(&fixture, tenant_id, family_id, root_raw.clone(), None),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let root_id = TokenRepository::new(create_pool(&database_url, 1).unwrap())
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Holding the family lock at session level parks each rotation transaction
    // inside its commit on the same advisory wait — two genuinely in-flight
    // rotations without adding trigger DDL to the shared tables (queued DDL
    // elsewhere is what stalls unrelated commits into their lock_timeout).
    let family_key = family_lock_key(family_id);
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(family_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold the family lock");

    let app_left = format!("rotation-left-{}", Uuid::now_v7().simple());
    let app_right = format!("rotation-right-{}", Uuid::now_v7().simple());
    let left_input = refresh_issuance(refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        format!("race-left-{}", Uuid::now_v7()),
        Some(root_id),
    ));
    let right_input = refresh_issuance(refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        format!("race-right-{}", Uuid::now_v7()),
        Some(root_id),
    ));
    let left_repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &app_left), 1).unwrap(),
    );
    let right_repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &app_right), 1).unwrap(),
    );
    let mut left = tokio::spawn({
        let input = left_input.clone();
        async move { retry_token_infra(|| left_repository.commit_token_issuance(input.clone())).await }
    });
    let mut right = tokio::spawn({
        let input = right_input.clone();
        async move { retry_token_infra(|| right_repository.commit_token_issuance(input.clone())).await }
    });
    wait_for_lock_wait_or_task(&mut coordinator, &app_left, &mut left).await;
    wait_for_lock_wait_or_task(&mut coordinator, &app_right, &mut right).await;
    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(family_key)
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release the family lock");
    let left_result = left.await.expect("left rotation should join");
    let right_result = right.await.expect("right rotation should join");

    let mut committed = 0;
    let mut loser_input = None;
    for (result, input) in [(left_result, &left_input), (right_result, &right_input)] {
        match result {
            Ok(CommitTokenIssuanceResult::Committed) => committed += 1,
            Ok(CommitTokenIssuanceResult::RotationConflict) => {
                loser_input = Some((*input).clone());
            }
            other => panic!("unexpected rotation race result {other:?}"),
        }
    }
    assert_eq!(committed, 1, "exactly one rotation may commit");
    let losing = loser_input.expect("the loser must see the business conflict");
    // The winner's insert commits, then the loser's compromise revokes every
    // family row — including the just-committed successor — and its reuse
    // audit is persisted rather than rolled back.
    assert_rotation_conflict_facts(&mut coordinator, tenant_id, family_id, &losing, 2, 2, 0).await;
    let winner_issuance = if losing.issuance_id == left_input.issuance_id {
        right_input.issuance_id
    } else {
        left_input.issuance_id
    };
    let kept = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances WHERE issuance_id = $1",
    )
    .bind::<SqlUuid, _>(winner_issuance)
    .get_result::<CountRow>(&mut coordinator)
    .await
    .unwrap();
    assert_eq!(
        kept.count, 1,
        "the winning issuance row must stay committed"
    );
}

/// Commits a bound root refresh token and one bound successor, returning the
/// domain rows needed by the lost-response retry tests.
async fn bound_rotation_fixture(
    database_url: &str,
    fixture: &FixtureIds,
    tenant_id: Uuid,
    family_id: Uuid,
    dpop_jkt: &str,
) -> (nazo_auth::RefreshToken, nazo_auth::RefreshToken) {
    let tokens = TokenRepository::new(create_pool(database_url, 2).unwrap());
    let root_raw = format!("bound-root-{}", Uuid::now_v7());
    let mut root = refresh_token_fixture(fixture, tenant_id, family_id, root_raw.clone(), None);
    root.dpop_jkt = Some(dpop_jkt.to_owned());
    let (result, _) = commit_refresh(database_url, root).await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let successor_raw = format!("bound-successor-{}", Uuid::now_v7());
    let root_id = tokens
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut successor = refresh_token_fixture(
        fixture,
        tenant_id,
        family_id,
        successor_raw.clone(),
        Some(root_id),
    );
    successor.dpop_jkt = Some(dpop_jkt.to_owned());
    let (result, _) = commit_refresh(database_url, successor).await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let original = tokens
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap();
    let successor = tokens
        .by_raw_refresh_token(tenant_id, &successor_raw)
        .await
        .unwrap()
        .unwrap();
    (original, successor)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_response_retry_rechecks_family_compromise_under_the_family_lock() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let dpop_jkt = format!("lost-response-jkt-{}", Uuid::now_v7().simple());
    let (original, successor) =
        bound_rotation_fixture(&database_url, &fixture, tenant_id, family_id, &dpop_jkt).await;
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());

    // Outer snapshot: the unconsumed successor of the revoked original.
    let retry_started_at = chrono::Utc::now();
    let inspected = tokens
        .inspect_lost_response_successor(&original, fixture.client_id, retry_started_at)
        .await
        .expect("outer successor snapshot should load");
    assert_eq!(
        inspected.as_ref().map(|token| token.id),
        Some(successor.id),
        "the outer snapshot must see the persisted successor"
    );

    // Hold the family advisory lock so the in-lock recheck cannot run until
    // the compromise lands — the exact "between the two checks" window.
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query("SELECT pg_advisory_lock($1)")
        .bind::<BigInt, _>(family_lock_key(family_id))
        .execute(&mut coordinator)
        .await
        .expect("coordinator should hold the family lock");

    let retry_application = format!("lost-response-retry-{}", Uuid::now_v7().simple());
    let retry_repository = TokenIssuanceRepository::new(
        create_pool(tagged_database_url(&database_url, &retry_application), 1).unwrap(),
    );
    let mut retry_token = refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        format!("lost-response-next-{}", Uuid::now_v7()),
        Some(successor.id),
    );
    retry_token.dpop_jkt = Some(dpop_jkt.clone());
    retry_token.lost_response_retry = Some(nazo_auth::LostResponseRetry {
        original_id: original.id,
        retry_started_at,
    });
    let retry_input = refresh_issuance(retry_token);
    let mut retry = tokio::spawn({
        let input = retry_input.clone();
        async move { retry_token_infra(|| retry_repository.commit_token_issuance(input.clone())).await }
    });
    wait_for_lock_wait_or_task(&mut coordinator, &retry_application, &mut retry).await;

    // A concurrent reuse verdict commits while the retry waits for the lock.
    let mut compromiser = AsyncPgConnection::establish(&database_url).await.unwrap();
    let marked = sql_query(
        "UPDATE oauth_tokens SET reuse_detected_at = CURRENT_TIMESTAMP \
         WHERE tenant_id = $1 AND token_family_id = $2 AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(family_id)
    .execute(&mut compromiser)
    .await
    .expect("the racing compromise should commit");
    assert!(marked > 0);

    sql_query("SELECT pg_advisory_unlock($1)")
        .bind::<BigInt, _>(family_lock_key(family_id))
        .execute(&mut coordinator)
        .await
        .expect("coordinator should release the family lock");
    let result = retry.await.expect("retry task should join");
    assert_eq!(
        result.expect("the recheck must classify as a business conflict"),
        CommitTokenIssuanceResult::RotationConflict,
        "the in-lock recheck must see the compromise committed after the outer snapshot"
    );
    assert_rotation_conflict_facts(
        &mut coordinator,
        tenant_id,
        family_id,
        &retry_input,
        2,
        2,
        0,
    )
    .await;
}

/// Stages a revoked original refresh row plus `successor_count` successor rows
/// in a fresh family and returns the original's domain token together with the
/// inserted successor ids.
#[allow(clippy::too_many_arguments)]
async fn stage_lost_response(
    database_url: &str,
    fixture: &FixtureIds,
    tenant_id: Uuid,
    label: &str,
    original_revoked_offset_seconds: i32,
    original_dpop_jkt: Option<&str>,
    successor_dpop_jkt: Option<&str>,
    successor_expires_offset_seconds: i32,
    successor_reuse_detected: bool,
    successor_count: usize,
) -> (nazo_auth::RefreshToken, Vec<Uuid>) {
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());
    let family_id = Uuid::now_v7();
    let original_raw = format!("{label}-original-{}", Uuid::now_v7());
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    let mut original_row = raw_refresh_row(fixture, tenant_id, family_id, &original_raw, &context);
    original_row.revoked_offset_seconds = Some(original_revoked_offset_seconds);
    original_row.dpop_jkt = original_dpop_jkt;
    let original_id = insert_refresh_row(&mut connection, &original_row).await;
    let mut successor_ids = Vec::new();
    for index in 0..successor_count {
        let successor_raw = format!("{label}-successor-{index}-{}", Uuid::now_v7());
        let mut successor_row =
            raw_refresh_row(fixture, tenant_id, family_id, &successor_raw, &context);
        successor_row.rotated_from_id = Some(original_id);
        successor_row.dpop_jkt = successor_dpop_jkt;
        successor_row.expires_offset_seconds = successor_expires_offset_seconds;
        successor_row.reuse_detected = successor_reuse_detected;
        successor_ids.push(insert_refresh_row(&mut connection, &successor_row).await);
    }
    let original = TokenRepository::new(create_pool(database_url, 1).unwrap())
        .by_raw_refresh_token(tenant_id, &original_raw)
        .await
        .expect("staged original should load")
        .expect("staged original should exist");
    (original, successor_ids)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_response_successor_requires_exactly_one_bound_unexpired_successor() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    let jkt = "lost-successor-jkt";
    // The retry timestamp must follow the staged `revoked_at` for the
    // sixty-second recovery window to be entered at all.
    let now = || chrono::Utc::now();

    // Zero successors → nothing to recover.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "zero",
        0,
        Some(jkt),
        Some(jkt),
        3600,
        false,
        0,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "no successor may be reported when none exists"
    );

    // Exactly one bound, unexpired, unrevoked successor → recovered.
    let (original, successor_ids) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "one",
        0,
        Some(jkt),
        Some(jkt),
        3600,
        false,
        1,
    )
    .await;
    let recovered = tokens
        .inspect_lost_response_successor(&original, fixture.client_id, now())
        .await
        .expect("successor lookup should load")
        .expect("exactly one bound successor must be recoverable");
    assert_eq!(recovered.id, successor_ids[0]);

    // Two competing successors trip the LIMIT 2 + exactly-one constraint.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "two",
        0,
        Some(jkt),
        Some(jkt),
        3600,
        false,
        2,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "two candidate successors must fail the exactly-one constraint"
    );

    // An expired successor does not count.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "expired",
        0,
        Some(jkt),
        Some(jkt),
        -60,
        false,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "an expired successor must not be recovered"
    );

    // Without any holder binding on the original there is no successor proof.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "unbound",
        0,
        None,
        Some(jkt),
        3600,
        false,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "an unbound original has no recoverable successor"
    );

    // A successor bound to a different key is not this retry's successor.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "mismatch",
        0,
        Some(jkt),
        Some("a-different-jkt"),
        3600,
        false,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "a successor bound to another key must not be recovered"
    );

    // A client different from the original's owner sees nothing.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "client",
        0,
        Some(jkt),
        Some(jkt),
        3600,
        false,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, Uuid::now_v7(), now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "a different client id must not recover the successor"
    );

    // A retry started outside the sixty-second window recovers nothing.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "late",
        -120,
        Some(jkt),
        Some(jkt),
        3600,
        false,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "a successor outside the retry window must not be recovered"
    );

    // A family already flagged for reuse hides the successor entirely.
    let (original, _) = stage_lost_response(
        &database_url,
        &fixture,
        tenant_id,
        "compromised",
        0,
        Some(jkt),
        Some(jkt),
        3600,
        true,
        1,
    )
    .await;
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, now())
            .await
            .expect("successor lookup should load")
            .is_none(),
        "a compromised family must hide every successor"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_sql_failure_propagates_error_and_rolls_back_instead_of_conflicting() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let family_id = Uuid::now_v7();
    let root_raw = format!("sql-failure-root-{}", Uuid::now_v7());
    let (result, _) = commit_refresh(
        &database_url,
        refresh_token_fixture(&fixture, tenant_id, family_id, root_raw.clone(), None),
    )
    .await;
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let root_id = TokenRepository::new(create_pool(&database_url, 1).unwrap())
        .by_raw_refresh_token(tenant_id, &root_raw)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Reusing the parent's raw refresh token makes the successor INSERT hit
    // ux_oauth_tokens_tenant_refresh_token_blake3 — a real constraint
    // violation after the conditional parent UPDATE has already run.  The
    // transaction must abort and roll back instead of degrading into a
    // business conflict.
    let repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let failing = refresh_issuance(refresh_token_fixture(
        &fixture,
        tenant_id,
        family_id,
        root_raw.clone(),
        Some(root_id),
    ));
    let failing_issuance_id = failing.issuance_id;
    let result = repository
        .commit_token_issuance(failing.clone())
        .await
        .expect_err("a SQL failure must surface as an error, never a business result");
    assert_eq!(
        result,
        nazo_auth::TokenPortError::Unexpected,
        "a constraint violation inside rotation is an error, not RotationConflict"
    );
    let mut coordinator = AsyncPgConnection::establish(&database_url).await.unwrap();
    let intact = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_tokens \
         WHERE id = $1 AND revoked_at IS NULL AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(root_id)
    .get_result::<CountRow>(&mut coordinator)
    .await
    .unwrap();
    assert_eq!(
        intact.count, 1,
        "the parent must stay active and uncompromised"
    );
    for (table, clause) in [
        (
            "oauth_token_issuances",
            format!("issuance_id = '{failing_issuance_id}'"),
        ),
        (
            "security_audit_events",
            format!("payload->>'issuance_id' = '{failing_issuance_id}'"),
        ),
        ("oauth_tokens", format!("rotated_from_id = '{root_id}'")),
    ] {
        let count = sql_query(format!(
            "SELECT COUNT(*)::bigint AS count FROM {table} WHERE {clause}"
        ))
        .get_result::<CountRow>(&mut coordinator)
        .await
        .unwrap();
        assert_eq!(count.count, 0, "{table} must roll back completely");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn family_active_exists_semantics_cover_cardinality_and_predicates() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let tokens = TokenRepository::new(create_pool(&database_url, 4).unwrap());
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let context = refresh_context_json(&fixture.client_public_id, chrono::Utc::now());

    // No rows at all.
    assert!(
        !tokens
            .family_active(tenant_id, Uuid::now_v7(), fixture.user_id)
            .await
            .expect("empty family state should load")
    );

    // Many rows with at least one active → true.
    let many_family = Uuid::now_v7();
    for (label, revoked, expires) in [
        ("active", None, 3600),
        ("revoked", Some(0), 3600),
        ("expired", None, -60),
    ] {
        let raw = format!("exists-many-{label}-{}", Uuid::now_v7());
        let mut row = raw_refresh_row(&fixture, tenant_id, many_family, &raw, &context);
        row.revoked_offset_seconds = revoked;
        row.expires_offset_seconds = expires;
        insert_refresh_row(&mut connection, &row).await;
    }
    assert!(
        tokens
            .family_active(tenant_id, many_family, fixture.user_id)
            .await
            .expect("multi-row family state should load"),
        "one unrevoked unexpired row is enough"
    );
    // Single active row family.
    let single_family = Uuid::now_v7();
    insert_refresh_row(
        &mut connection,
        &raw_refresh_row(
            &fixture,
            tenant_id,
            single_family,
            &format!("exists-single-{}", Uuid::now_v7()),
            &context,
        ),
    )
    .await;
    assert!(
        tokens
            .family_active(tenant_id, single_family, fixture.user_id)
            .await
            .expect("single-row family state should load")
    );
    // Tenant and user predicates must both hold.
    assert!(
        !tokens
            .family_active(Uuid::now_v7(), single_family, fixture.user_id)
            .await
            .expect("wrong-tenant family state should load"),
        "a different tenant must not see the family active"
    );
    assert!(
        !tokens
            .family_active(tenant_id, single_family, Uuid::now_v7())
            .await
            .expect("wrong-user family state should load"),
        "a different user must not see the family active"
    );
    // Revoke the single row → false; a family of only expired rows → false.
    sql_query("UPDATE oauth_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_family_id = $1")
        .bind::<SqlUuid, _>(single_family)
        .execute(&mut connection)
        .await
        .unwrap();
    assert!(
        !tokens
            .family_active(tenant_id, single_family, fixture.user_id)
            .await
            .expect("revoked family state should load")
    );
    let expired_family = Uuid::now_v7();
    let expired_raw = format!("exists-expired-{}", Uuid::now_v7());
    let mut expired_row =
        raw_refresh_row(&fixture, tenant_id, expired_family, &expired_raw, &context);
    expired_row.expires_offset_seconds = -60;
    insert_refresh_row(&mut connection, &expired_row).await;
    assert!(
        !tokens
            .family_active(tenant_id, expired_family, fixture.user_id)
            .await
            .expect("expired family state should load"),
        "an unrevoked but expired row is not active"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_token_revoked_exists_semantics_ignore_deadline_and_scope() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _serial = ROTATION_MATRIX_TEST_LOCK.lock().await;
    let fixture = fixture(&database_url).await;
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let tokens = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    let issuance = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let jti = format!("revoked-jti-{}", Uuid::now_v7());

    assert!(
        !tokens
            .access_token_revoked(tenant_id, &jti)
            .await
            .expect("unknown jti lookup should load"),
        "an unknown jti is not revoked"
    );
    retry_token_infra(|| {
        issuance.revoke_token(TokenRevocation {
            tenant_id,
            client_id: fixture.client_id,
            raw_token: "revoked-jti-unused-refresh",
            access_token: Some(AccessTokenRevocation {
                jti: jti.clone(),
                // Already past even after the verifier clock-skew deadline.
                expires_at: chrono::Utc::now() - chrono::Duration::hours(2),
            }),
        })
    })
    .await
    .expect("revocation should commit");
    assert!(
        tokens
            .access_token_revoked(tenant_id, &jti)
            .await
            .expect("revoked jti lookup should load"),
        "a persisted revocation row stays true until cleanup removes it"
    );
    assert!(
        !tokens
            .access_token_revoked(Uuid::now_v7(), &jti)
            .await
            .expect("foreign-tenant lookup should load"),
        "a revocation never leaks across tenants"
    );
    assert!(
        !tokens
            .access_token_revoked(tenant_id, "never-issued-jti")
            .await
            .expect("other jti lookup should load")
    );

    // Cleanup deletes the row → the exists check flips back to false.
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let removed = sql_query(
        "DELETE FROM access_token_revocations \
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<Text, _>(blake3::hash(jti.as_bytes()).to_hex().to_string())
    .execute(&mut connection)
    .await
    .expect("cleanup should delete the revocation row");
    assert_eq!(removed, 1);
    assert!(
        !tokens
            .access_token_revoked(tenant_id, &jti)
            .await
            .expect("post-cleanup lookup should load")
    );
}
