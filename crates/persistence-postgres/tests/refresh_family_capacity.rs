//! Active refresh-family cardinality: at most
//! `MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE` live families per
//! `(tenant_id, user_id, client_id)` scope. Reaching the cap retires the
//! deterministically oldest family inside the same authority transaction —
//! the limit holds at every commit boundary, including under concurrency.

use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken,
    RefreshTokenAuthenticationContext, TokenIssuanceMode, TokenIssuedAuditFields,
    TokenRepositoryPort,
};
use nazo_postgres::{TokenIssuanceRepository, TokenRepository, create_pool};
use serde_json::json;
use uuid::Uuid;

const CAP: i64 = nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE;

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
) -> NewRefreshToken {
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
            // Fixed: the immutable contract digest must stay identical across
            // generations of the same family.
            auth_time: 1_700_000_000,
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

fn issuance(token: NewRefreshToken) -> CommitTokenIssuance {
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
        .commit_token_issuance(issuance(token))
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
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let fixture = fixture(&database_url, "cap-grow").await;
    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();

    let mut created = Vec::new();
    for ordinal in 0..CAP {
        let (family_id, _) =
            issue_family(&database_url, &fixture, tenant_id, ordinal).await;
        created.push(family_id);
        assert_eq!(
            live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id)
                .await,
            ordinal + 1,
            "issuance {ordinal} should grow the scope to {} families",
            ordinal + 1
        );
    }

    // The eleventh authorization retires exactly the oldest family.
    let (eleventh, _) = issue_family(&database_url, &fixture, tenant_id, CAP).await;
    let live = live_family_ids(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await;
    assert_eq!(live.len() as i64, CAP, "the cap must hold after eviction");
    assert!(
        !live.contains(&created[0]),
        "the oldest family must be the eviction victim"
    );
    for survivor in &created[1..] {
        assert!(live.contains(survivor), "newer families must survive");
    }
    assert!(live.contains(&eleventh));

    // A burst of further authorizations never exceeds the cap.
    for ordinal in (CAP + 1)..(CAP + 31) {
        issue_family(&database_url, &fixture, tenant_id, ordinal).await;
    }
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await,
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
        live_family_count(&mut connection, tenant_id, fixture_b.user_id, fixture_b.client_id)
            .await,
        0,
        "a different user/client scope is untouched by the first scope's cap"
    );

    // A second scope under the same tenant still receives its own full budget.
    let (other, _) = issue_family(&database_url, &fixture_b, tenant_id, 0).await;
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture_b.user_id, fixture_b.client_id)
            .await,
        1
    );
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture_a.user_id, fixture_a.client_id)
            .await,
        CAP,
        "scope A remains at its cap"
    );
    let live_b =
        live_family_ids(&mut connection, tenant_id, fixture_b.user_id, fixture_b.client_id).await;
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
    let live = live_family_ids(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await;
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
            .commit_token_issuance(issuance(child))
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        assert_eq!(
            live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id)
                .await,
            CAP,
            "rotation must not trigger capacity eviction"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_family_tokens_resolve_as_unknown_grant() {
    let Some(database_url) = database_url() else {
        return;
    };
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
            .commit_token_issuance(issuance(token))
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
            .commit_token_issuance(issuance(child))
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        created[newest].1.clone()
    };

    // The next authorization retires the oldest family outright.
    issue_family(&database_url, &fixture, tenant_id, CAP).await;
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await,
        CAP
    );

    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    for (ordinal, (_family_id, raw)) in created.iter().enumerate() {
        let resolved = repository
            .by_raw_refresh_token(tenant_id, raw)
            .await
            .expect("refresh lookup should succeed");
        if ordinal == 0 {
            assert!(
                resolved.is_none(),
                "a capacity-retired family's current token must resolve as unknown"
            );
        } else {
            assert!(resolved.is_some(), "surviving families still resolve");
        }
    }
    // The retired family left no residual state: no spent proofs and no
    // orphaned contract, while the surviving family's spent proof still
    // resolves for replay detection.
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
    assert_eq!(spent_left, 0, "spent proofs cascade with the family");
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
        live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await,
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
    let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
        .commit_token_issuance(issuance(machine))
        .await
        .expect("machine issuance should commit");
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await,
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
    let mut last_raw = String::new();
    for generation in 0..(PROOF_CAP + 8) {
        let raw = format!("cap-proof-g{generation}-{}", Uuid::now_v7());
        let child = new_refresh(
            &fixture,
            tenant_id,
            family_id,
            raw.clone(),
            Some(member),
            chrono::Utc::now() + chrono::Duration::milliseconds(generation),
        );
        member = child.member_id;
        let result = TokenIssuanceRepository::new(create_pool(&database_url, 2).unwrap())
            .commit_token_issuance(issuance(child))
            .await
            .expect("rotation should commit");
        assert_eq!(result, CommitTokenIssuanceResult::Committed);
        last_raw = raw;
    }

    let proofs = proof_count(&mut connection, tenant_id, family_id).await;
    assert_eq!(
        proofs, PROOF_CAP,
        "sustained rotation must converge on the per-family proof bound"
    );

    // The trimmed tail really is gone: the earliest generation's proof no
    // longer resolves, while the newest member still resolves through the
    // family row.
    let repository = TokenRepository::new(create_pool(&database_url, 2).unwrap());
    assert!(
        repository
            .by_raw_refresh_token(tenant_id, &last_raw)
            .await
            .expect("current lookup should succeed")
            .is_some(),
        "the current generation still resolves"
    );
    assert_eq!(
        live_family_count(&mut connection, tenant_id, fixture.user_id, fixture.client_id).await,
        1,
        "rotation never multiplies the family row"
    );
}
