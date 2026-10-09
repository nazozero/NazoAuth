//! Active refresh-family cardinality: at most
//! `MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE` live families per
//! `(tenant_id, user_id, client_id)` scope. Reaching the cap retires the
//! deterministically oldest family inside the same authority transaction —
//! the limit holds at every commit boundary, including under concurrency.

#[path = "support/refresh_fixture.rs"]
mod refresh_fixture;
use refresh_fixture::RefreshFixture;

use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, RefreshTokenAuthenticationContext,
    TokenIssuanceMode, TokenIssuedAuditFields, TokenRepositoryPort,
};
use nazo_postgres::{TokenIssuanceRepository, TokenRepository, create_pool};
use serde_json::json;
use uuid::Uuid;

const CAP: i64 = nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE;
// Global maintenance may reclaim another test's revoked-family fixtures.
static TERMINAL_FAMILY_TEST_GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI capacity tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
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

#[derive(QueryableByName)]
struct FamilyIdRow {
    #[diesel(sql_type = SqlUuid)]
    token_family_id: Uuid,
}

async fn fixture(database_url: &str, tag: &str) -> FixtureIds {
    nazo_postgres::run_pending_migrations(database_url)
        .await
        .expect("migrations should apply");
    let tag = format!("{tag}-{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("capacity test database should connect");
    let security_policy = r#"{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}"#;
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
                '{tag}', 'Capacity Test', 'confidential',
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
    .expect("capacity fixture should insert")
}

fn new_refresh(
    fixture: &FixtureIds,
    tenant_id: Uuid,
    family_id: Uuid,
    raw_token: String,
    rotated_from_id: Option<Uuid>,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> RefreshFixture {
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
                // Fixed: the immutable contract digest must stay identical across
                // generations of the same family.
                auth_time: 1_700_000_000,
                amr: vec!["pwd".to_owned()],
                oidc_sid: None,
                id_token_sid: None,
                acr: None,
                nonce: None,
                userinfo_claim_requests: (Vec::new()).into(),
                id_token_claim_requests: (Vec::new()).into(),
            },
        }
        .persisted(),
    )
}

async fn issuance(token: RefreshFixture) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        authorization_id: None,
        native_sso_source: None,
        principal_state: nazo_auth::TokenPrincipalState {
            client_epoch: 0,
            user_epoch: (token.user_id).map(|_| 0),
            subject_bound: false,
        },
        subject: (token.user_id)
            .map(|id| id.to_string())
            .unwrap_or_else(|| "client".to_owned()),
        issuance_id,
        tenant_id: token.tenant_id,
        client_id: token.client_id,
        user_id: token.user_id,
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (token.issued_at + chrono::Duration::minutes(5)).timestamp(),
        audit_fields: TokenIssuedAuditFields {
            client_id: token.contract.authentication_context.audience.clone(),
            subject_hash: blake3::hash(token.contract.subject.as_bytes())
                .to_hex()
                .to_string(),
            scope: token.contract.scopes.join(" "),
            audience: token.audiences.clone(),
        },
        refresh_token: Some(token.into_commit().await),
    }
}

/// Commit one fresh family; returns `(family_id, member_id)` for later
/// rotation/lookup assertions.
async fn issue_family(
    database_url: &str,
    fixture: &FixtureIds,
    tenant_id: Uuid,
    ordinal: i64,
) -> (Uuid, Uuid) {
    let family_id = Uuid::now_v7();
    // Stagger `issued_at` by whole seconds in the recent past so the
    // oldest-first ordering never depends on a same-millisecond UUID
    // tie-break while every issued token stays well inside its TTL.
    let issued_at = chrono::Utc::now() - chrono::Duration::seconds(300 - ordinal);
    let token = new_refresh(
        fixture,
        tenant_id,
        family_id,
        format!("cap-{ordinal}-{}", Uuid::now_v7()),
        None,
        issued_at,
    );
    let member_id = token.member_id;
    let result = TokenIssuanceRepository::new(create_pool(database_url, 2).unwrap())
        .commit_token_issuance(issuance(token).await)
        .await
        .expect("family issuance should commit");
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    (family_id, member_id)
}

async fn live_family_count(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) -> i64 {
    sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 \
           AND revoked_at IS NULL AND reuse_detected_at IS NULL \
           AND current_expires_at > CURRENT_TIMESTAMP",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client_id)
    .get_result::<CountRow>(connection)
    .await
    .expect("live family count should query")
    .count
}

async fn live_family_ids(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: Uuid,
) -> Vec<Uuid> {
    sql_query(
        "SELECT token_family_id FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 \
           AND revoked_at IS NULL AND reuse_detected_at IS NULL \
           AND current_expires_at > CURRENT_TIMESTAMP",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client_id)
    .load::<FamilyIdRow>(connection)
    .await
    .expect("live family ids should query")
    .into_iter()
    .map(|row| row.token_family_id)
    .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_grows_to_ten_then_retires_the_deterministic_oldest() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = TERMINAL_FAMILY_TEST_GATE.acquire().await.unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-grow").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(
        "UPDATE oauth_clients SET client_type = 'public', \
         token_endpoint_auth_method = 'none', client_secret_hash = NULL WHERE id = $1",
    )
    .bind::<SqlUuid, _>(fixture.client_id)
    .execute(&mut connection)
    .await
    .expect("the capacity client should become public before families exist");

    let mut created = Vec::new();
    for ordinal in 0..CAP {
        let (family_id, _) = issue_family(&database_url, &fixture, tenant_id, ordinal).await;
        created.push(family_id);
        assert_eq!(
            live_family_count(
                &mut connection,
                tenant_id,
                fixture.user_id,
                fixture.client_id
            )
            .await,
            ordinal + 1,
            "issuance {ordinal} should grow the scope to {} families",
            ordinal + 1
        );
    }

    // A public family's unexpired proof history is unbounded. Capacity
    // retirement must not cascade these rows or make issuance perform an
    // unbounded delete.
    let seeded_proofs = sql_query(
        "INSERT INTO oauth_refresh_spent_tokens (\
             tenant_id, refresh_token_blake3, token_family_id, member_id, \
             successor_member_id, spent_at, expires_at) \
         SELECT family.tenant_id, \
                decode(md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text), 'hex'), \
                family.token_family_id, gen_random_uuid(), family.current_member_id, \
                CURRENT_TIMESTAMP, family.current_expires_at \
         FROM oauth_refresh_families AS family CROSS JOIN generate_series(1, 300) \
         WHERE family.tenant_id = $1 AND family.token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(created[0])
    .execute(&mut connection)
    .await
    .expect("large unexpired public proof history should insert");
    assert_eq!(seeded_proofs, 300);

    // The eleventh authorization retires exactly the oldest family.
    let (eleventh, _) = issue_family(&database_url, &fixture, tenant_id, CAP).await;
    let live = live_family_ids(
        &mut connection,
        tenant_id,
        fixture.user_id,
        fixture.client_id,
    )
    .await;
    assert_eq!(live.len() as i64, CAP, "the cap must hold after eviction");
    assert!(
        !live.contains(&created[0]),
        "the oldest family must be the eviction victim"
    );
    for survivor in &created[1..] {
        assert!(live.contains(survivor), "newer families must survive");
    }
    assert!(live.contains(&eleventh));
    let retained_proofs = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_spent_tokens \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(created[0])
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("retired proof count should query")
    .count;
    assert_eq!(
        retained_proofs, 300,
        "capacity eviction must leave every unexpired public proof for bounded maintenance"
    );
    let retired = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 AND revoked_at IS NOT NULL",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(created[0])
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("retired family tombstone should query")
    .count;
    assert_eq!(
        retired, 1,
        "the eviction victim should remain as a tombstone"
    );

    // A burst of further authorizations never exceeds the cap.
    for ordinal in (CAP + 1)..(CAP + 31) {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        CAP,
        "sustained authorization churn must stay bounded"
    );

    // Each retirement left one Required audit fact.
    let retired_audits = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE event_type = 'refresh_family_capacity_retired' \
           AND payload->>'token_family_id' = $1",
    )
    .bind::<Text, _>(created[0].to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("capacity audit should query")
    .count;
    assert_eq!(
        retired_audits, 1,
        "capacity retirement must emit exactly one Required audit event"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_family_retains_more_than_sixty_four_unexpired_rotation_proofs() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::from_u128(1);
    let fixture = fixture(&database_url, "public-proof-history").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    sql_query(
        "UPDATE oauth_clients SET client_type = 'public', \
         token_endpoint_auth_method = 'none', client_secret_hash = NULL WHERE id = $1",
    )
    .bind::<SqlUuid, _>(fixture.client_id)
    .execute(&mut connection)
    .await
    .expect("client should become public before issuance");

    let family_id = Uuid::now_v7();
    let root_raw = format!("public-proof-root-{}", Uuid::now_v7());
    let root = new_refresh(
        &fixture,
        tenant_id,
        family_id,
        root_raw,
        None,
        chrono::Utc::now() - chrono::Duration::seconds(1),
    );
    let mut previous_member = root.member_id;
    assert_eq!(
        TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(root).await)
            .await
            .expect("public root should commit"),
        CommitTokenIssuanceResult::Committed
    );

    for generation in 0..72 {
        let token = new_refresh(
            &fixture,
            tenant_id,
            family_id,
            format!("public-proof-{generation}-{}", Uuid::now_v7()),
            Some(previous_member),
            chrono::Utc::now(),
        );
        previous_member = token.member_id;
        assert_eq!(
            TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
                .commit_token_issuance(issuance(token).await)
                .await
                .expect("public rotation should commit"),
            CommitTokenIssuanceResult::Committed
        );
    }

    let proofs = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_spent_tokens \
         WHERE tenant_id = $1 AND token_family_id = $2 \
           AND expires_at > CURRENT_TIMESTAMP",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("public proof count should query")
    .count;
    assert_eq!(
        proofs, 72,
        "unbound public refresh proofs must remain until their own expiry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_capacity_audit_failure_rolls_back_retirement_and_issuance() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::from_u128(1);
    let fixture = fixture(&database_url, "cap-audit-rollback").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let mut families = Vec::new();
    for ordinal in 0..CAP {
        families.push(issue_family(&database_url, &fixture, tenant_id, ordinal).await);
    }

    let pending_family_id = Uuid::now_v7();
    let pending = issuance(new_refresh(
        &fixture,
        tenant_id,
        pending_family_id,
        format!("cap-audit-failure-{}", Uuid::now_v7()),
        None,
        chrono::Utc::now(),
    ))
    .await;
    let issuance_id = pending.issuance_id;
    let suffix = Uuid::now_v7().simple().to_string();
    let function = format!("test_cap_audit_fail_{suffix}");
    let trigger = format!("test_cap_audit_fail_trigger_{suffix}");
    sql_query(format!(
        r#"
        CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.event_type::text = 'refresh_family_capacity_retired'
               AND NEW.payload->>'issuance_id' = '{issuance_id}' THEN
                RAISE EXCEPTION 'deliberate capacity audit failure';
            END IF;
            RETURN NEW;
        END
        $$
        "#
    ))
    .execute(&mut connection)
    .await
    .expect("required audit failure trigger function should install");
    sql_query(format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON security_audit_events \
         FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&mut connection)
    .await
    .expect("required audit failure trigger should install");

    let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
        .commit_token_issuance(pending)
        .await;
    sql_query(format!("DROP TRIGGER {trigger} ON security_audit_events"))
        .execute(&mut connection)
        .await
        .expect("audit failure trigger should be removed");
    sql_query(format!("DROP FUNCTION {function}()"))
        .execute(&mut connection)
        .await
        .expect("audit failure function should be removed");
    assert!(
        result.is_err(),
        "a Required capacity audit failure must fail the issuance transaction"
    );

    let victim_active = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 \
           AND revoked_at IS NULL AND reuse_detected_at IS NULL",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(families[0].0)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("victim state should query")
    .count;
    assert_eq!(
        victim_active, 1,
        "failed audit must roll back victim revocation"
    );
    let pending_family = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(pending_family_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("pending family state should query")
    .count;
    assert_eq!(
        pending_family, 0,
        "failed audit must roll back new family insertion"
    );
    let audit_rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM security_audit_events \
         WHERE payload->>'issuance_id' = $1",
    )
    .bind::<Text, _>(issuance_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("rolled-back audit count should query")
    .count;
    assert_eq!(audit_rows, 0, "failed Required audit must leave no event");
    let issuance_rows = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_token_issuances \
         WHERE issuance_id = $1",
    )
    .bind::<SqlUuid, _>(issuance_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("rolled-back issuance count should query")
    .count;
    assert_eq!(
        issuance_rows, 0,
        "failed Required audit must roll back issuance state too"
    );
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        CAP,
        "failed audit must preserve the original active-family cap"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_is_per_tenant_user_client_scope() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture_a = fixture(&database_url, "cap-scope-a").await;
    let fixture_b = fixture(&database_url, "cap-scope-b").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    for ordinal in 0..CAP {
        issue_family(&database_url, &fixture_a, tenant_id, ordinal).await;
    }
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture_b.user_id,
            fixture_b.client_id
        )
        .await,
        0,
        "a different user/client scope is untouched by the first scope's cap"
    );

    // A second scope under the same tenant still receives its own full budget.
    let (other, _) = issue_family(&database_url, &fixture_b, tenant_id, 0).await;
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture_b.user_id,
            fixture_b.client_id
        )
        .await,
        1
    );
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture_a.user_id,
            fixture_a.client_id
        )
        .await,
        CAP,
        "scope A remains at its cap"
    );
    let live_b = live_family_ids(
        &mut connection,
        tenant_id,
        fixture_b.user_id,
        fixture_b.client_id,
    )
    .await;
    assert_eq!(live_b, vec![other]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_never_consumes_a_family_slot() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-rotate").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    for ordinal in 0..CAP {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }

    // Rotate the oldest live family twice; rotation is generation churn inside
    // one slot, not a new authorization decision.
    let live = live_family_ids(
        &mut connection,
        tenant_id,
        fixture.user_id,
        fixture.client_id,
    )
    .await;
    let family = live[0];
    let mut member = {
        let rows = sql_query(
            "SELECT current_member_id AS token_family_id FROM oauth_refresh_families \
             WHERE tenant_id = $1 AND token_family_id = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(family)
        .get_result::<FamilyIdRow>(&mut connection)
        .await
        .expect("current member should load");
        rows.token_family_id
    };
    for generation in 0..2 {
        let issued_at = chrono::Utc::now() + chrono::Duration::seconds(generation);
        let child = new_refresh(
            &fixture,
            tenant_id,
            family,
            format!("cap-rotate-g{generation}-{}", Uuid::now_v7()),
            Some(member),
            issued_at,
        );
        member = child.member_id;
        let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(child).await)
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        assert_eq!(
            live_family_count(
                &mut connection,
                tenant_id,
                fixture.user_id,
                fixture.client_id
            )
            .await,
            CAP,
            "rotation must not trigger capacity eviction"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capacity_retired_family_tokens_remain_revoked_tombstones() {
    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = TERMINAL_FAMILY_TEST_GATE.acquire().await.unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-retire").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    let mut created = Vec::new();
    for ordinal in 0..CAP {
        let family_id = Uuid::now_v7();
        let issued_at = chrono::Utc::now() - chrono::Duration::seconds(300 - ordinal);
        let raw = format!("cap-retire-{ordinal}-{}", Uuid::now_v7());
        let token = new_refresh(&fixture, tenant_id, family_id, raw.clone(), None, issued_at);
        let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(token).await)
            .await
            .expect("family issuance should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        created.push((family_id, raw));
    }

    // Rotate the NEWEST family once so it owns a spent proof while remaining
    // a survivor — rotation refreshes `current_issued_at`, so rotating the
    // oldest would move the deterministic victim.
    let newest = CAP as usize - 1;
    let spent_raw = {
        let child = new_refresh(
            &fixture,
            tenant_id,
            created[newest].0,
            format!("cap-retire-successor-{}", Uuid::now_v7()),
            Some(
                sql_query(
                    "SELECT current_member_id AS token_family_id FROM oauth_refresh_families \
                     WHERE tenant_id = $1 AND token_family_id = $2",
                )
                .bind::<SqlUuid, _>(tenant_id)
                .bind::<SqlUuid, _>(created[newest].0)
                .get_result::<FamilyIdRow>(&mut connection)
                .await
                .unwrap()
                .token_family_id,
            ),
            chrono::Utc::now(),
        );
        let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(child).await)
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        created[newest].1.clone()
    };

    // The next authorization revokes the oldest family and leaves its tombstone.
    issue_family(&database_url, &fixture, tenant_id, CAP).await;
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        CAP
    );

    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    for (ordinal, (_family_id, raw)) in created.iter().enumerate() {
        let resolved = repository
            .by_raw_refresh_token(tenant_id, raw)
            .await
            .expect("refresh lookup should succeed");
        if ordinal == 0 {
            let retired = resolved.expect("a retired family must remain resolvable as revoked");
            assert!(
                retired.revoked_at.is_some(),
                "the capacity-retired current token must resolve with revoked state"
            );
        } else {
            assert!(resolved.is_some(), "surviving families still resolve");
        }
    }
    // This victim has no spent proofs; its tombstone remains until bounded
    // maintenance removes the parent. The surviving family's spent proof
    // still resolves for replay detection.
    let retired_family = created[0].0;
    let spent_left = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_spent_tokens \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(retired_family)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap()
    .count;
    assert_eq!(spent_left, 0, "the victim had no spent proofs to drain");
    assert!(
        repository
            .by_raw_refresh_token(tenant_id, &spent_raw)
            .await
            .expect("spent lookup should succeed")
            .is_some(),
        "a surviving family's spent proof still resolves for replay evidence"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_authorizations_never_exceed_the_cap() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-concurrent").await;

    // Pre-fill to the cap, then race twelve fresh authorizations.
    for ordinal in 0..CAP {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }

    let url = std::sync::Arc::new(database_url.clone());
    let fixture = std::sync::Arc::new(fixture);
    let mut handles = Vec::new();
    for ordinal in 0..12 {
        let url = url.clone();
        let fixture = fixture.clone();
        handles.push(tokio::spawn(async move {
            issue_family(&url, &fixture, tenant_id, CAP + ordinal).await
        }));
    }
    for handle in handles {
        handle.await.expect("concurrent issuance should not panic");
    }

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        CAP,
        "concurrent authorizations must converge on the cap, not past it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn machine_issuance_without_user_skips_the_cap() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-machine").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    for ordinal in 0..CAP {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }

    // client_credentials-style refresh issuances carry no user; they do not
    // consume or disturb the user-bound family budget.
    let mut machine = new_refresh(
        &fixture,
        tenant_id,
        Uuid::now_v7(),
        format!("cap-machine-{}", Uuid::now_v7()),
        None,
        chrono::Utc::now(),
    );
    machine.user_id = None;
    machine.contract.subject = "client".to_owned();
    let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
        .commit_token_issuance(issuance(machine).await)
        .await
        .expect("machine issuance should commit");
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        CAP,
        "machine issuance must not evict user-bound families"
    );
}

const PROOF_CAP: i64 = nazo_auth::MAX_SPENT_PROOFS_PER_REFRESH_FAMILY;

/// Spent-proof bound: sustained rotation of one long-lived family keeps at
/// most `MAX_SPENT_PROOFS_PER_REFRESH_FAMILY` proofs — the replay window is a
/// generation bound, not a time-based accumulation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spent_proofs_stay_bounded_under_sustained_rotation() {
    let Some(database_url) = database_url() else {
        return;
    };
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-proofs").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    let (family_id, mut member) = issue_family(&database_url, &fixture, tenant_id, 0).await;

    async fn proof_count(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        family_id: Uuid,
    ) -> i64 {
        sql_query(
            "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_spent_tokens \
             WHERE tenant_id = $1 AND token_family_id = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(family_id)
        .get_result::<CountRow>(connection)
        .await
        .expect("spent count should query")
        .count
    }

    // Rotate well past the proof bound; the family stays one live row and the
    // proof count must converge on the cap, never exceed it.
    let mut raw_tokens = Vec::new();
    let rotation_start = chrono::Utc::now();
    for generation in 0..(PROOF_CAP + 8) {
        let raw = format!("cap-proof-g{generation}-{}", Uuid::now_v7());
        let child = new_refresh(
            &fixture,
            tenant_id,
            family_id,
            raw.clone(),
            Some(member),
            rotation_start + chrono::Duration::milliseconds(generation),
        );
        member = child.member_id;
        let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(child).await)
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        raw_tokens.push(raw);
        if [0, PROOF_CAP - 1, PROOF_CAP, PROOF_CAP + 7].contains(&generation) {
            assert_eq!(
                proof_count(&mut connection, tenant_id, family_id).await,
                (generation + 1).min(PROOF_CAP),
                "proof retention at generation {generation}"
            );
        }
    }

    let proofs = proof_count(&mut connection, tenant_id, family_id).await;
    assert_eq!(
        proofs, PROOF_CAP,
        "sustained rotation must converge on the per-family proof bound"
    );

    // Verify the identities retained, not just the count: only the newest
    // PROOF_CAP spent presentations and the current member still resolve.
    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    let current_index = raw_tokens.len() - 1;
    let first_retained = current_index - PROOF_CAP as usize;
    for (index, raw) in raw_tokens.iter().enumerate() {
        let found = repository
            .by_raw_refresh_token(tenant_id, raw)
            .await
            .expect("presentation lookup should succeed");
        if index < first_retained {
            assert!(found.is_none(), "the oldest proof must be trimmed");
        } else {
            let found = found.expect("retained presentation should resolve");
            assert_eq!(found.revoked_at.is_none(), index == current_index);
        }
    }
    assert_eq!(
        live_family_count(
            &mut connection,
            tenant_id,
            fixture.user_id,
            fixture.client_id
        )
        .await,
        1,
        "rotation never multiplies the family row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_retired_contract_is_reclaimed_without_touching_live_references() {
    use diesel::sql_types::Binary;
    use nazo_persistence::SecurityStateMaintenancePort;
    use nazo_postgres::SecurityStateMaintenanceRepository;

    #[derive(QueryableByName)]
    struct ContractDigest {
        #[diesel(sql_type = Binary)]
        contract_blake3: Vec<u8>,
    }

    let Some(database_url) = database_url() else {
        return;
    };
    let _permit = TERMINAL_FAMILY_TEST_GATE.acquire().await.unwrap();
    let tenant_id = Uuid::from_u128(1);
    let fixture = fixture(&database_url, "cap-contract-gc").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    let issuance_repository = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap());
    let retired_family = Uuid::now_v7();
    let mut token = new_refresh(
        &fixture,
        tenant_id,
        retired_family,
        format!("cap-contract-gc-{}", Uuid::now_v7()),
        None,
        chrono::Utc::now() - chrono::Duration::minutes(10),
    );
    // Give the oldest family an earlier authentication time, which is part
    // of the persisted contract. Nonce/id_token_sid are cleared by persisted()
    // and therefore cannot distinguish the orphan from the ten live families.
    token.contract.authentication_context.auth_time -= 60;
    assert_eq!(
        issuance_repository
            .commit_token_issuance(issuance(token).await)
            .await
            .expect("oldest family should commit"),
        CommitTokenIssuanceResult::Committed
    );
    let orphan_digest = sql_query(
        "SELECT contract_blake3 FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(retired_family)
    .get_result::<ContractDigest>(&mut connection)
    .await
    .unwrap()
    .contract_blake3;
    for ordinal in 0..CAP {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }
    let live_digest = sql_query(
        "SELECT contract_blake3 FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 \
           AND revoked_at IS NULL LIMIT 1",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(fixture.user_id)
    .bind::<SqlUuid, _>(fixture.client_id)
    .get_result::<ContractDigest>(&mut connection)
    .await
    .unwrap()
    .contract_blake3;
    assert_ne!(orphan_digest, live_digest);

    async fn contract_exists(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        digest: &[u8],
    ) -> bool {
        sql_query(
            "SELECT count(*)::bigint AS count FROM oauth_refresh_contracts \
             WHERE tenant_id = $1 AND contract_blake3 = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Binary, _>(digest)
        .get_result::<CountRow>(connection)
        .await
        .unwrap()
        .count
            == 1
    }

    let tombstone = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 AND revoked_at IS NOT NULL",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(retired_family)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap()
    .count;
    assert_eq!(
        tombstone, 1,
        "capacity retirement leaves the parent for bounded maintenance"
    );
    assert!(
        contract_exists(&mut connection, tenant_id, &orphan_digest).await,
        "capacity retirement must leave the orphan contract to maintenance"
    );
    let maintenance =
        SecurityStateMaintenanceRepository::new(create_pool(&database_url, 2).unwrap());
    maintenance
        .cleanup_batch()
        .await
        .expect("fresh-contract sweep should succeed");
    let retired_parent = sql_query(
        "SELECT COUNT(*)::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(retired_family)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap()
    .count;
    assert_eq!(
        retired_parent, 0,
        "bounded maintenance should remove the proofless terminal parent"
    );
    assert!(
        !contract_exists(&mut connection, tenant_id, &orphan_digest).await,
        "the unreferenced fresh contract must be reclaimed after its terminal parent"
    );
    assert!(
        contract_exists(&mut connection, tenant_id, &live_digest).await,
        "a surviving family reference must protect a fresh contract"
    );
    // A live reference protects the contract independently of its age.
    for digest in [&live_digest] {
        sql_query(
            "UPDATE oauth_refresh_contracts SET created_at = '1970-01-01 UTC' \
             WHERE tenant_id = $1 AND contract_blake3 = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Binary, _>(digest)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    maintenance
        .cleanup_batch()
        .await
        .expect("aged-contract sweep should succeed");
    assert!(!contract_exists(&mut connection, tenant_id, &orphan_digest).await);
    assert!(
        contract_exists(&mut connection, tenant_id, &live_digest).await,
        "a surviving family reference must protect an old contract"
    );
}
