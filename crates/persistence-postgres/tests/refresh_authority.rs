//! Real PostgreSQL regressions for the refresh source checked at commit.
//! The migration case replays the actual SQL lineage in its own database;
//! no fixture manufactures a legacy contract key or substitutes a fake store.

use chrono::{DateTime, Duration, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken, RefreshContract, RefreshToken,
    RefreshTokenAuthenticationContext, RefreshTokenCommit, TokenIssuanceMode,
    TokenIssuedAuditFields, TokenPrincipalState, TokenRepositoryPort, TokenRevocation,
};
use nazo_postgres::{TokenIssuanceRepository, TokenRepository, create_pool};
use serde_json::{Value, json};
use uuid::Uuid;

const A: &str = "resource://a";
const B: &str = "resource://b";

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI refresh-authority tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn tenant() -> Uuid {
    Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
}

#[derive(QueryableByName)]
struct Fixture {
    #[diesel(sql_type = sql_types::Uuid)]
    user_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_public_id: String,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(Debug, PartialEq, QueryableByName)]
struct FamilyState {
    #[diesel(sql_type = sql_types::Jsonb)]
    family: Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    contract: Value,
    #[diesel(sql_type = sql_types::BigInt)]
    spent: i64,
}

// Same user/client fixture shape as auth_repositories and refresh_family_capacity.
// Split seeding from migration so the genuine pre-cutover test can use it too.
async fn seed_fixture(connection: &mut AsyncPgConnection) -> Fixture {
    let tag = format!("refresh-authority-{}", Uuid::now_v7().simple());
    sql_query(
        "WITH u AS (INSERT INTO users (username, email, password_hash) \
         VALUES ($1, $1 || '@example.test', 'test-only-hash') RETURNING id), \
         c AS (INSERT INTO oauth_clients (client_id, client_name, client_type, \
         redirect_uris, scopes, grant_types, token_endpoint_auth_method, security_policy) \
         VALUES ($1, 'Refresh Authority Test', 'confidential', \
         '[\"https://client.example/callback\"]', '[\"openid\",\"offline_access\"]', \
         '[\"authorization_code\",\"refresh_token\"]', 'client_secret_basic', \
         '{\"version\":1,\"assurance\":\"baseline\",\"require_signed_authorization_request\":false,\"require_signed_authorization_response\":false,\"require_signed_introspection_response\":false,\"session_management\":false,\"allow_cross_device_flows\":false,\"allow_confidential_oidc_without_pkce\":false}') \
         RETURNING id, client_id) \
         SELECT u.id AS user_id, c.id AS client_id, c.client_id AS client_public_id FROM u CROSS JOIN c",
    )
    .bind::<sql_types::Text, _>(tag)
    .get_result(connection)
    .await
    .expect("refresh authority identities should seed")
}

async fn fixture(url: &str) -> Fixture {
    nazo_postgres::run_pending_migrations(url).await.unwrap();
    seed_fixture(&mut AsyncPgConnection::establish(url).await.unwrap()).await
}

fn contract(fixture: &Fixture) -> RefreshContract {
    RefreshContract {
        subject: fixture.user_id.to_string(),
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        audiences: vec![A.to_owned(), B.to_owned()],
        authorization_details: json!([]),
        authentication_context: RefreshTokenAuthenticationContext {
            version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
            issuer: "https://issuer.example".to_owned(),
            audience: fixture.client_public_id.clone(),
            auth_time: 1_700_000_000,
            amr: vec!["pwd".to_owned()],
            oidc_sid: Some("original-oidc-session".to_owned()),
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

fn new_token(fixture: &Fixture, issued_at: DateTime<Utc>) -> NewRefreshToken {
    NewRefreshToken {
        raw_token: format!("refresh-authority-{}", Uuid::now_v7()),
        member_id: Uuid::now_v7(),
        tenant_id: tenant(),
        family_id: Uuid::now_v7(),
        rotated_from_id: None,
        lost_response_retry: None,
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        audiences: vec![A.to_owned(), B.to_owned()],
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        id_token_sid: Some(format!("id-session-{}", Uuid::now_v7())),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
    }
}

fn issuance(fixture: &Fixture, refresh_token: RefreshTokenCommit) -> CommitTokenIssuance {
    let issuance_id = Uuid::now_v7();
    CommitTokenIssuance {
        authorization_id: None,
        native_sso_source: None,
        principal_state: TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: fixture.user_id.to_string(),
        issuance_id,
        tenant_id: tenant(),
        client_id: fixture.client_id,
        user_id: Some(fixture.user_id),
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: issuance_id.to_string(),
        access_token_expires_at: (Utc::now() + Duration::minutes(5)).timestamp(),
        refresh_token: Some(refresh_token),
        audit_fields: TokenIssuedAuditFields {
            client_id: fixture.client_public_id.clone(),
            subject_hash: blake3::hash(fixture.user_id.to_string().as_bytes())
                .to_hex()
                .to_string(),
            scope: "openid offline_access".to_owned(),
            audience: vec![A.to_owned()],
        },
    }
}

fn preserve(fixture: &Fixture, source: &RefreshToken) -> CommitTokenIssuance {
    issuance(
        fixture,
        RefreshTokenCommit::UseExisting {
            authority: source.authority(),
            rotation: None,
        },
    )
}

fn rotation(
    fixture: &Fixture,
    source: &RefreshToken,
    audiences: &[&str],
) -> (CommitTokenIssuance, String) {
    let mut token = new_token(fixture, Utc::now());
    token.family_id = source.token_family_id;
    token.rotated_from_id = Some(source.id);
    token.audiences = audiences.iter().map(|value| (*value).to_owned()).collect();
    token.dpop_jkt.clone_from(&source.dpop_jkt);
    token.mtls_x5t_s256.clone_from(&source.mtls_x5t_s256);
    token
        .client_attestation_jkt
        .clone_from(&source.client_attestation_jkt);
    let raw = token.raw_token.clone();
    (
        issuance(
            fixture,
            RefreshTokenCommit::UseExisting {
                authority: source.authority(),
                rotation: Some(token),
            },
        ),
        raw,
    )
}

async fn lookup(url: &str, raw: &str) -> RefreshToken {
    TokenRepository::new(create_pool(url, 1).unwrap())
        .by_raw_refresh_token(tenant(), raw)
        .await
        .unwrap()
        .expect("source refresh token should resolve")
}

async fn issue_at(
    url: &str,
    fixture: &Fixture,
    issued_at: DateTime<Utc>,
) -> (String, RefreshToken) {
    let token = new_token(fixture, issued_at);
    let raw = token.raw_token.clone();
    let result = TokenIssuanceRepository::new(create_pool(url, 1).unwrap())
        .commit_token_issuance(issuance(
            fixture,
            RefreshTokenCommit::IssueNew {
                token,
                contract: contract(fixture),
            },
        ))
        .await
        .unwrap();
    assert_eq!(result, CommitTokenIssuanceResult::Committed);
    let source = lookup(url, &raw).await;
    (raw, source)
}

async fn state(connection: &mut AsyncPgConnection, family_id: Uuid) -> FamilyState {
    sql_query(
        "SELECT to_jsonb(f) AS family, c.contract, \
         (SELECT count(*) FROM oauth_refresh_spent_tokens s \
          WHERE s.tenant_id = f.tenant_id AND s.token_family_id = f.token_family_id) AS spent \
         FROM oauth_refresh_families f JOIN oauth_refresh_contracts c \
         ON c.tenant_id = f.tenant_id AND c.contract_blake3 = f.contract_blake3 \
         WHERE f.tenant_id = $1 AND f.token_family_id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Uuid, _>(family_id)
    .get_result(connection)
    .await
    .unwrap()
}

async fn assert_issuance_writes(connection: &mut AsyncPgConnection, id: Uuid, committed: bool) {
    let count = sql_query(
        "SELECT count(*) AS count FROM security_audit_events \
         WHERE event_id = $1 AND event_type = 'token_issued'",
    )
    .bind::<sql_types::Uuid, _>(id)
    .get_result::<Count>(&mut *connection)
    .await
    .unwrap();
    assert_eq!(count.count, i64::from(committed));
    let all_audits = sql_query(
        "SELECT count(*) AS count FROM security_audit_events WHERE payload->>'issuance_id' = $1",
    )
    .bind::<sql_types::Text, _>(id.to_string())
    .get_result::<Count>(&mut *connection)
    .await
    .unwrap();
    assert_eq!(
        all_audits.count,
        i64::from(committed),
        "unavailability or malformed input must not emit reuse audit"
    );
    let receipts =
        sql_query("SELECT count(*) AS count FROM oauth_token_issuances WHERE issuance_id = $1")
            .bind::<sql_types::Uuid, _>(id)
            .get_result::<Count>(connection)
            .await
            .unwrap();
    assert_eq!(
        receipts.count, 0,
        "Fresh refresh commits never allocate a grant receipt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_narrows_and_reorders_current_audience_without_replacing_original_contract() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let (_, mut source) = issue_at(&url, &fixture, Utc::now()).await;
    let original = state(&mut connection, source.token_family_id).await;
    let original_key = source.contract_key;
    // Reordering is set-equivalent; narrowing is generation state. After A+B
    // becomes A, another A-only rotation still references the original A+B.
    for (generation, audiences) in [&[B, A][..], &[A][..], &[A][..]].into_iter().enumerate() {
        let (input, raw) = rotation(&fixture, &source, audiences);
        assert_eq!(
            repository
                .commit_token_issuance(input.clone())
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        source = lookup(&url, &raw).await;
        assert_eq!(source.contract_key, original_key);
        assert_eq!(source.contract_audiences, vec![A, B]);
        assert_eq!(source.audience, json!(audiences));
        let after = state(&mut connection, source.token_family_id).await;
        assert_eq!(after.contract, original.contract);
        assert_eq!(
            after.family["contract_blake3"],
            original.family["contract_blake3"]
        );
        assert_eq!(after.spent, generation as i64 + 1);
        assert_issuance_writes(&mut connection, input.issuance_id, true).await;
    }
    let contracts = sql_query("SELECT count(*) AS count FROM oauth_refresh_contracts WHERE tenant_id = $1 AND contract->>'subject' = $2")
        .bind::<sql_types::Uuid, _>(tenant())
        .bind::<sql_types::Text, _>(fixture.user_id.to_string())
        .get_result::<Count>(&mut connection).await.unwrap();
    assert_eq!(
        contracts.count, 1,
        "audience changes must not create orphan replacement contracts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_rejects_audience_expansion_without_compromising_the_family() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
    let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
    let (input, raw) = rotation(&fixture, &source, &[A]);
    assert_eq!(
        repository.commit_token_issuance(input).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let narrowed = lookup(&url, &raw).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let before = state(&mut connection, source.token_family_id).await;
    for audiences in [&[A, B][..], &["resource://never-authorized"][..]] {
        let (input, _) = rotation(&fixture, &narrowed, audiences);
        assert!(
            repository
                .commit_token_issuance(input.clone())
                .await
                .is_err(),
            "an expanded candidate is invalid input"
        );
        assert_issuance_writes(&mut connection, input.issuance_id, false).await;
        assert_eq!(state(&mut connection, source.token_family_id).await, before);
    }
}

async fn fill_capacity(url: &str, fixture: &Fixture) {
    for ordinal in 1..nazo_auth::MAX_ACTIVE_REFRESH_FAMILIES_PER_SCOPE {
        issue_at(url, fixture, Utc::now() - Duration::seconds(300 - ordinal)).await;
    }
}

async fn retire_oldest(url: &str, fixture: &Fixture, family_id: Uuid) {
    issue_at(url, fixture, Utc::now()).await;
    let mut connection = AsyncPgConnection::establish(url).await.unwrap();
    let retired = sql_query(
        "SELECT count(*) AS count FROM security_audit_events \
         WHERE event_type = 'refresh_family_capacity_retired' \
         AND payload->>'token_family_id' = $1",
    )
    .bind::<sql_types::Text, _>(family_id.to_string())
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        retired.count, 1,
        "the real capacity path must retire this source"
    );
    let retired_state = state(&mut connection, family_id).await;
    assert!(
        !retired_state.family["revoked_at"].is_null(),
        "capacity retirement must retain a revoked tombstone"
    );
    assert!(retired_state.family["reuse_detected_at"].is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_snapshot_cannot_commit_after_real_revocation_or_capacity_retirement() {
    let Some(url) = database_url() else { return };
    for capacity in [false, true] {
        let fixture = fixture(&url).await;
        let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
        let (raw, source) = issue_at(&url, &fixture, Utc::now() - Duration::minutes(10)).await;
        if capacity {
            fill_capacity(&url, &fixture).await;
        }
        let preserved = preserve(&fixture, &source);
        let (rotated, _) = rotation(&fixture, &source, &[A]);
        if capacity {
            retire_oldest(&url, &fixture, source.token_family_id).await;
        } else {
            assert_eq!(
                repository
                    .revoke_token(TokenRevocation {
                        tenant_id: tenant(),
                        client_id: fixture.client_id,
                        raw_token: &raw,
                        access_token: None,
                    })
                    .await
                    .unwrap(),
                1
            );
        }
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        for input in [preserved, rotated] {
            assert_eq!(
                repository
                    .commit_token_issuance(input.clone())
                    .await
                    .unwrap(),
                CommitTokenIssuanceResult::RefreshGrantUnavailable
            );
            assert_issuance_writes(&mut connection, input.issuance_id, false).await;
        }
        let compromise = sql_query(
            "SELECT count(*) AS count FROM security_audit_events \
             WHERE event_type = 'refresh_reuse_detected' AND payload->>'token_family_id' = $1",
        )
        .bind::<sql_types::Text, _>(source.token_family_id.to_string())
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(
            compromise.count, 0,
            "terminal unavailability is not a new compromise"
        );
        let after = state(&mut connection, source.token_family_id).await;
        assert!(!after.family["revoked_at"].is_null());
        assert!(after.family["reuse_detected_at"].is_null());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserve_rechecks_source_expiry_contract_and_sender_binding() {
    let Some(url) = database_url() else { return };
    for mutation in ["expiry", "contract", "dpop", "mtls", "attestation"] {
        let fixture = fixture(&url).await;
        let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
        let input = preserve(&fixture, &source);
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        match mutation {
            "expiry" => sql_query(
                "UPDATE oauth_refresh_families SET current_issued_at = CURRENT_TIMESTAMP - interval '2 hours', \
                 current_expires_at = CURRENT_TIMESTAMP - interval '1 second' WHERE token_family_id = $1",
            ).bind::<sql_types::Uuid, _>(source.token_family_id).execute(&mut connection).await.unwrap(),
            "contract" => sql_query(
                "UPDATE oauth_refresh_contracts SET contract = jsonb_set(contract, \
                 '{authentication_context,acr}', '\"urn:example:changed-assurance\"') \
                 WHERE tenant_id = $1 AND contract_blake3 = $2",
            ).bind::<sql_types::Uuid, _>(tenant()).bind::<sql_types::Binary, _>(source.contract_key.to_vec())
                .execute(&mut connection).await.unwrap(),
            "dpop" => sql_query(
                "UPDATE oauth_refresh_families SET dpop_jkt = 'changed-sender' WHERE token_family_id = $1",
            ).bind::<sql_types::Uuid, _>(source.token_family_id).execute(&mut connection).await.unwrap(),
            "mtls" => sql_query(
                "UPDATE oauth_refresh_families SET mtls_x5t_s256 = 'changed-certificate' WHERE token_family_id = $1",
            ).bind::<sql_types::Uuid, _>(source.token_family_id).execute(&mut connection).await.unwrap(),
            "attestation" => sql_query(
                "UPDATE oauth_refresh_families SET client_attestation_jkt = 'changed-instance' WHERE token_family_id = $1",
            ).bind::<sql_types::Uuid, _>(source.token_family_id).execute(&mut connection).await.unwrap(),
            _ => unreachable!(),
        };
        let before = state(&mut connection, source.token_family_id).await;
        let repository = TokenIssuanceRepository::new(create_pool(&url, 1).unwrap());
        assert_eq!(
            repository
                .commit_token_issuance(input.clone())
                .await
                .unwrap(),
            CommitTokenIssuanceResult::RefreshGrantUnavailable,
            "{mutation} drift must reject the stale source"
        );
        assert_issuance_writes(&mut connection, input.issuance_id, false).await;
        assert_eq!(state(&mut connection, source.token_family_id).await, before);
        if mutation == "expiry" {
            let (input, _) = rotation(&fixture, &source, &[A]);
            assert_eq!(
                repository
                    .commit_token_issuance(input.clone())
                    .await
                    .unwrap(),
                CommitTokenIssuanceResult::RefreshGrantUnavailable
            );
            assert_issuance_writes(&mut connection, input.issuance_id, false).await;
            assert_eq!(state(&mut connection, source.token_family_id).await, before);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_legal_preserves_overlap_while_revocation_waits_for_both() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (raw, source) = issue_at(&url, &fixture, Utc::now()).await;
    let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
    let before = state(&mut coordinator, source.token_family_id).await;
    let left = preserve(&fixture, &source);
    let right = preserve(&fixture, &source);
    let suffix = Uuid::now_v7().simple().to_string();
    let gate = format!("test_preserve_overlap_{suffix}");
    let left_key = i64::from_be_bytes(Uuid::now_v7().as_bytes()[8..].try_into().unwrap());
    let right_key = left_key.wrapping_add(1);
    let bytes = source.token_family_id.as_bytes();
    let family_key = i64::from_be_bytes(bytes[..8].try_into().unwrap())
        ^ i64::from_be_bytes(bytes[8..].try_into().unwrap());
    coordinator
        .batch_execute(&format!(
            "CREATE FUNCTION {gate}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             IF NEW.event_id = '{}'::uuid THEN PERFORM pg_advisory_xact_lock({left_key}); \
             ELSIF NEW.event_id = '{}'::uuid THEN PERFORM pg_advisory_xact_lock({right_key}); END IF; \
             RETURN NEW; END $$; CREATE TRIGGER {gate} BEFORE INSERT ON security_audit_events \
             FOR EACH ROW EXECUTE FUNCTION {gate}();",
            left.issuance_id, right.issuance_id,
        ))
        .await
        .unwrap();
    for key in [left_key, right_key] {
        sql_query("SELECT pg_advisory_lock($1)")
            .bind::<sql_types::BigInt, _>(key)
            .execute(&mut coordinator)
            .await
            .unwrap();
    }
    let left_app = format!("preserve-left-{suffix}");
    let right_app = format!("preserve-right-{suffix}");
    let left_repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &left_app), 1).unwrap());
    let right_repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &right_app), 1).unwrap());
    let left_input = left.clone();
    let right_input = right.clone();
    let mut left_task =
        tokio::spawn(async move { left_repository.commit_token_issuance(left_input).await });
    let mut right_task =
        tokio::spawn(async move { right_repository.commit_token_issuance(right_input).await });
    wait_for_lock(&mut coordinator, &left_app, &mut left_task).await;
    assert_advisory_wait(&mut coordinator, &left_app, left_key).await;
    wait_for_lock(&mut coordinator, &right_app, &mut right_task).await;
    assert_advisory_wait(&mut coordinator, &right_app, right_key).await;
    // Exact distinct audit gates prove simultaneous post-validation readers;
    // a generic lock wait alone could hide serialization on the family.
    assert_advisory_wait(&mut coordinator, &left_app, left_key).await;
    let reclaim = sql_query(
        "SELECT CASE WHEN pg_try_advisory_xact_lock($1) THEN 1 ELSE 0 END::bigint AS count",
    )
    .bind::<sql_types::BigInt, _>(family_key)
    .get_result::<Count>(&mut coordinator)
    .await
    .unwrap();
    assert_eq!(
        reclaim.count, 0,
        "maintenance must skip shared advisory holders"
    );

    let revoke_app = format!("preserve-revoke-{suffix}");
    let repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &revoke_app), 1).unwrap());
    let client_id = fixture.client_id;
    let mut revoking = tokio::spawn(async move {
        repository
            .revoke_token(TokenRevocation {
                tenant_id: tenant(),
                client_id,
                raw_token: &raw,
                access_token: None,
            })
            .await
    });
    wait_for_lock(&mut coordinator, &revoke_app, &mut revoking).await;
    assert_advisory_wait(&mut coordinator, &revoke_app, family_key).await;
    for (key, task) in [(left_key, left_task), (right_key, right_task)] {
        sql_query("SELECT pg_advisory_unlock($1)")
            .bind::<sql_types::BigInt, _>(key)
            .execute(&mut coordinator)
            .await
            .unwrap();
        assert_eq!(
            task.await.unwrap().unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        if key == left_key {
            // One committed reader must not release the other's authority.
            assert_advisory_wait(&mut coordinator, &right_app, right_key).await;
            assert_advisory_wait(&mut coordinator, &revoke_app, family_key).await;
        }
    }
    assert_eq!(revoking.await.unwrap().unwrap(), 1);
    coordinator
        .batch_execute(&format!(
            "DROP TRIGGER {gate} ON security_audit_events; DROP FUNCTION {gate}();",
        ))
        .await
        .unwrap();
    assert_issuance_writes(&mut coordinator, left.issuance_id, true).await;
    assert_issuance_writes(&mut coordinator, right.issuance_id, true).await;
    let mut after = state(&mut coordinator, source.token_family_id).await;
    assert!(!after.family["revoked_at"].is_null());
    after.family["revoked_at"] = Value::Null;
    assert_eq!(
        after, before,
        "only the real revocation may change the source"
    );
}

/// The existing wait helper establishes a lock wait; match the exact advisory
/// key too so an earlier family lock cannot masquerade as reaching the audit.
async fn assert_advisory_wait(connection: &mut AsyncPgConnection, application: &str, key: i64) {
    let waiting = sql_query(
        "SELECT count(*) AS count FROM pg_stat_activity AS activity \
         JOIN pg_locks AS waiting ON waiting.pid = activity.pid \
         WHERE activity.application_name = $1 AND activity.wait_event_type = 'Lock' \
           AND waiting.locktype = 'advisory' AND NOT waiting.granted \
           AND waiting.classid::bigint = (($2::bigint >> 32) & 4294967295) \
           AND waiting.objid::bigint = ($2::bigint & 4294967295) \
           AND waiting.objsubid = 1",
    )
    .bind::<sql_types::Text, _>(application)
    .bind::<sql_types::BigInt, _>(key)
    .get_result::<Count>(connection)
    .await
    .unwrap();
    assert_eq!(
        waiting.count, 1,
        "{application} must wait on its exact advisory key"
    );
}

fn tagged_url(url: &str, application_name: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}application_name={application_name}")
}

async fn wait_for_lock<T: std::fmt::Debug>(
    connection: &mut AsyncPgConnection,
    application_name: &str,
    task: &mut tokio::task::JoinHandle<T>,
) {
    let wait = async {
        loop {
            // The coordinator may hold an open transaction. PostgreSQL caches
            // its backend roster, so refresh it before looking for a newly
            // connected task; wait_event itself is read live.
            connection
                .batch_execute("SELECT pg_stat_clear_snapshot()")
                .await
                .unwrap();
            let blocked = sql_query(
                "SELECT count(*) AS count FROM pg_stat_activity \
                 WHERE application_name = $1 AND wait_event_type = 'Lock'",
            )
            .bind::<sql_types::Text, _>(application_name)
            .get_result::<Count>(&mut *connection)
            .await
            .unwrap();
            if blocked.count > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        result = tokio::time::timeout(std::time::Duration::from_secs(10), wait) => {
            result.expect("the in-flight repository operation should reach a real PG lock wait");
        }
        result = task => panic!("{application_name} completed before the required lock wait: {result:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserve_commit_serializes_before_real_revocation_and_capacity_retirement() {
    let Some(url) = database_url() else { return };
    for capacity in [false, true] {
        let fixture = fixture(&url).await;
        let (raw, source) = issue_at(&url, &fixture, Utc::now() - Duration::minutes(10)).await;
        if capacity {
            fill_capacity(&url, &fixture).await;
        }
        let preserved = preserve(&fixture, &source);
        let replacement = issuance(
            &fixture,
            RefreshTokenCommit::IssueNew {
                token: new_token(&fixture, Utc::now()),
                contract: contract(&fixture),
            },
        );
        let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
        let suffix = Uuid::now_v7().simple().to_string();
        let gate = format!("test_preserve_gate_{suffix}");
        let gate_key = i64::from_be_bytes(Uuid::now_v7().as_bytes()[8..].try_into().unwrap());
        // Park at the actual audit write, after source validation. The source
        // lock must remain held until the same transaction commits its audit.
        coordinator
            .batch_execute(&format!(
                "CREATE FUNCTION {gate}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
             IF NEW.event_id = '{}'::uuid THEN PERFORM pg_advisory_xact_lock({gate_key}); END IF; \
             RETURN NEW; END $$; \
             CREATE TRIGGER {gate} BEFORE INSERT ON security_audit_events \
             FOR EACH ROW EXECUTE FUNCTION {gate}();",
                preserved.issuance_id,
            ))
            .await
            .unwrap();
        sql_query("SELECT pg_advisory_lock($1)")
            .bind::<sql_types::BigInt, _>(gate_key)
            .execute(&mut coordinator)
            .await
            .unwrap();
        let preserve_app = format!("preserve-{suffix}");
        let repository =
            TokenIssuanceRepository::new(create_pool(tagged_url(&url, &preserve_app), 1).unwrap());
        let input = preserved.clone();
        let mut preserving =
            tokio::spawn(async move { repository.commit_token_issuance(input).await });
        wait_for_lock(&mut coordinator, &preserve_app, &mut preserving).await;
        let mutate_app = format!("mutate-{suffix}");
        let repository =
            TokenIssuanceRepository::new(create_pool(tagged_url(&url, &mutate_app), 1).unwrap());
        let client_id = fixture.client_id;
        let mut mutating = tokio::spawn(async move {
            if capacity {
                assert_eq!(
                    repository.commit_token_issuance(replacement).await.unwrap(),
                    CommitTokenIssuanceResult::Committed
                );
            } else {
                assert_eq!(
                    repository
                        .revoke_token(TokenRevocation {
                            tenant_id: tenant(),
                            client_id,
                            raw_token: &raw,
                            access_token: None,
                        })
                        .await
                        .unwrap(),
                    1
                );
            }
        });
        wait_for_lock(&mut coordinator, &mutate_app, &mut mutating).await;
        sql_query("SELECT pg_advisory_unlock($1)")
            .bind::<sql_types::BigInt, _>(gate_key)
            .execute(&mut coordinator)
            .await
            .unwrap();
        assert_eq!(
            preserving.await.unwrap().unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        mutating.await.unwrap();
        coordinator
            .batch_execute(&format!(
                "DROP TRIGGER {gate} ON security_audit_events; DROP FUNCTION {gate}();",
            ))
            .await
            .unwrap();
        assert_issuance_writes(&mut coordinator, preserved.issuance_id, true).await;
        let after = state(&mut coordinator, source.token_family_id).await;
        assert!(
            !after.family["revoked_at"].is_null(),
            "the source must be revoked after the valid Preserve commit"
        );
        assert!(after.family["reuse_detected_at"].is_null());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn family_contract_lookup_preserves_per_family_lock_scope() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (_, first) = issue_at(&url, &fixture, Utc::now()).await;
    let (_, second) = issue_at(&url, &fixture, Utc::now()).await;
    assert_ne!(first.token_family_id, second.token_family_id);
    assert_eq!(first.contract_key, second.contract_key);

    let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
    coordinator.batch_execute("BEGIN").await.unwrap();
    sql_query(
        "SELECT 1::bigint AS count FROM oauth_refresh_contracts \
         WHERE tenant_id = $1 AND contract_blake3 = $2 FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Binary, _>(first.contract_key.to_vec())
    .get_result::<Count>(&mut coordinator)
    .await
    .unwrap();

    let suffix = Uuid::now_v7().simple().to_string();
    let other_app = format!("family-contract-other-{suffix}");
    let other_repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &other_app), 1).unwrap());
    let other_input = preserve(&fixture, &second);
    let mut other_task =
        tokio::spawn(async move { other_repository.commit_token_issuance(other_input).await });
    match tokio::time::timeout(std::time::Duration::from_secs(5), &mut other_task).await {
        Ok(result) => assert_eq!(
            result.unwrap().unwrap(),
            CommitTokenIssuanceResult::Committed,
            "a shared contract row lock must not block a family's scalar contract read"
        ),
        Err(_) => {
            coordinator.batch_execute("ROLLBACK").await.unwrap();
            let _ = other_task.await;
            panic!("a family read must not lock its shared contract row");
        }
    }
    coordinator.batch_execute("ROLLBACK").await.unwrap();

    // Lock one family exclusively. A different family sharing the contract
    // remains independent, while a Preserve on the locked family still waits.
    coordinator.batch_execute("BEGIN").await.unwrap();
    sql_query(
        "SELECT 1::bigint AS count FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Uuid, _>(first.token_family_id)
    .get_result::<Count>(&mut coordinator)
    .await
    .unwrap();

    let distinct_app = format!("family-distinct-{suffix}");
    let distinct_repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &distinct_app), 1).unwrap());
    let distinct_input = preserve(&fixture, &second);
    let mut distinct_task = tokio::spawn(async move {
        distinct_repository
            .commit_token_issuance(distinct_input)
            .await
    });
    match tokio::time::timeout(std::time::Duration::from_secs(5), &mut distinct_task).await {
        Ok(result) => assert_eq!(
            result.unwrap().unwrap(),
            CommitTokenIssuanceResult::Committed,
            "distinct families sharing a contract must have separate row-lock scopes"
        ),
        Err(_) => {
            coordinator.batch_execute("ROLLBACK").await.unwrap();
            let _ = distinct_task.await;
            panic!("a different family's Preserve must not wait on this family row");
        }
    }

    let same_app = format!("family-same-{suffix}");
    // Freeze the coordinator's roster before the new task connects. The wait
    // helper must refresh it rather than polling this incomplete snapshot.
    coordinator
        .batch_execute("SELECT count(*) FROM pg_stat_activity")
        .await
        .unwrap();
    let same_repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &same_app), 1).unwrap());
    let same_input = preserve(&fixture, &first);
    let mut same_task =
        tokio::spawn(async move { same_repository.commit_token_issuance(same_input).await });
    wait_for_lock(&mut coordinator, &same_app, &mut same_task).await;
    coordinator.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        same_task.await.unwrap().unwrap(),
        CommitTokenIssuanceResult::Committed,
        "the locked family's Preserve must proceed after the family lock is released"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contract_reference_reuses_equal_payload_and_rejects_same_key_different_payload() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let before = state(&mut connection, source.token_family_id).await;
    let same = sql_query("SELECT public.nazo_oauth_refresh_contract_ensure($1, $2, $3)")
        .bind::<sql_types::Uuid, _>(tenant())
        .bind::<sql_types::Binary, _>(source.contract_key.to_vec())
        .bind::<sql_types::Jsonb, _>(before.contract.clone())
        .execute(&mut connection)
        .await;
    assert!(
        same.is_ok(),
        "an equal existing payload is a reusable reference"
    );
    let mut different = before.contract.clone();
    different["authentication_context"]["acr"] = json!("urn:example:different");
    let mismatch = sql_query("SELECT public.nazo_oauth_refresh_contract_ensure($1, $2, $3)")
        .bind::<sql_types::Uuid, _>(tenant())
        .bind::<sql_types::Binary, _>(source.contract_key.to_vec())
        .bind::<sql_types::Jsonb, _>(different)
        .execute(&mut connection)
        .await;
    assert!(
        mismatch.is_err(),
        "the content key must never accept a different contract"
    );
    assert_eq!(state(&mut connection, source.token_family_id).await, before);
    // JSONB's ordinary equality considers 1 and 1.0 equal. The reference
    // contract must retain the stricter distinction used by serde_json.
    let numeric_key = blake3::hash(Uuid::now_v7().as_bytes()).as_bytes().to_vec();
    let mut integer_contract = before.contract.clone();
    integer_contract["authorization_details"] = json!([{"type": "numeric", "value": 1}]);
    sql_query("SELECT public.nazo_oauth_refresh_contract_ensure($1, $2, $3)")
        .bind::<sql_types::Uuid, _>(tenant())
        .bind::<sql_types::Binary, _>(&numeric_key)
        .bind::<sql_types::Jsonb, _>(&integer_contract)
        .execute(&mut connection)
        .await
        .unwrap();
    let mut float_contract = integer_contract;
    float_contract["authorization_details"] = json!([{"type": "numeric", "value": 1.0}]);
    assert!(
        sql_query("SELECT public.nazo_oauth_refresh_contract_ensure($1, $2, $3)")
            .bind::<sql_types::Uuid, _>(tenant())
            .bind::<sql_types::Binary, _>(&numeric_key)
            .bind::<sql_types::Jsonb, _>(&float_contract)
            .execute(&mut connection)
            .await
            .is_err()
    );
}

async fn apply_migration(connection: &mut AsyncPgConnection, path: &std::path::Path) {
    let sql = std::fs::read_to_string(path.join("up.sql")).unwrap();
    connection
        .transaction::<_, diesel::result::Error, _>(async |connection| {
            connection.batch_execute(&sql).await
        })
        .await
        .unwrap_or_else(|error| panic!("migration {} failed: {error}", path.display()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_full_migration_sql_key_rotates_without_rekeying_its_original_contract() {
    let Some(base) = database_url() else { return };
    // The upgrade checks public.oauth_tokens explicitly, so an isolated schema
    // cannot exercise it. Follow audit_pending_upgrade's scratch-database pattern.
    let name = format!("refresh_authority_{}", Uuid::now_v7().simple());
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(&base).unwrap();
    url.set_path(&name);
    let url = url.to_string();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut migrations: Vec<_> = std::fs::read_dir(migrations_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir() && path.join("up.sql").is_file())
        .collect();
    migrations.sort();
    let cutover = migrations
        .iter()
        .position(|path| path.file_name().unwrap() == "20260926000100_refresh_state_minimal")
        .expect("the real refresh migration should exist");
    for migration in &migrations[..cutover] {
        apply_migration(&mut connection, migration).await;
    }
    let fixture = seed_fixture(&mut connection).await;
    let token = new_token(&fixture, Utc::now() - Duration::minutes(1));
    let original_contract = contract(&fixture);
    let mut context = original_contract.authentication_context.clone();
    context.nonce = Some("legacy-original-nonce".to_owned());
    context.id_token_sid.clone_from(&token.id_token_sid);
    // Seed the real old schema. The opaque token hash is the public BLAKE3
    // token contract; the migration alone computes its SQL-namespaced key.
    sql_query(
        "INSERT INTO oauth_tokens (id, tenant_id, refresh_token_blake3, token_family_id, \
         client_id, user_id, scopes, audience, authorization_details, issued_at, expires_at, \
         subject, oidc_auth_context) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind::<sql_types::Uuid, _>(token.member_id)
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Text, _>(blake3::hash(token.raw_token.as_bytes()).to_hex().to_string())
    .bind::<sql_types::Uuid, _>(token.family_id)
    .bind::<sql_types::Uuid, _>(fixture.client_id)
    .bind::<sql_types::Uuid, _>(fixture.user_id)
    .bind::<sql_types::Jsonb, _>(json!(original_contract.scopes))
    .bind::<sql_types::Jsonb, _>(json!(original_contract.audiences))
    .bind::<sql_types::Jsonb, _>(original_contract.authorization_details.clone())
    .bind::<sql_types::Timestamptz, _>(token.issued_at)
    .bind::<sql_types::Timestamptz, _>(token.expires_at)
    .bind::<sql_types::Text, _>(&original_contract.subject)
    .bind::<sql_types::Jsonb, _>(serde_json::to_value(context).unwrap())
    .execute(&mut connection).await.unwrap();
    // Run the entire original migration, including table creation and the real
    // dual-MD5 upgrade DO block, followed by every append-only migration to head.
    for migration in &migrations[cutover..] {
        apply_migration(&mut connection, migration).await;
    }
    let source = lookup(&url, &token.raw_token).await;
    assert_ne!(
        source.contract_key,
        original_contract.persisted().blake3_digest(),
        "this source must use the genuine migration key, not a fabricated Rust key"
    );
    assert_eq!(source.contract_audiences, vec![A, B]);
    assert!(source.authentication_context.nonce.is_none());
    assert_eq!(
        source.authentication_context.id_token_sid,
        token.id_token_sid
    );
    let before = state(&mut connection, source.token_family_id).await;
    let (input, raw) = rotation(&fixture, &source, &[A]);
    let repository = TokenIssuanceRepository::new(create_pool(&url, 1).unwrap());
    assert_eq!(
        repository
            .commit_token_issuance(input.clone())
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let current = lookup(&url, &raw).await;
    let after = state(&mut connection, source.token_family_id).await;
    assert_eq!(current.contract_key, source.contract_key);
    assert_eq!(current.contract_audiences, vec![A, B]);
    assert_eq!(current.audience, json!([A]));
    assert_eq!(after.contract, before.contract);
    assert_eq!(
        after.family["contract_blake3"],
        before.family["contract_blake3"]
    );
    assert_eq!(after.spent, 1);
    assert_issuance_writes(&mut connection, input.issuance_id, true).await;
    let contracts =
        sql_query("SELECT count(*) AS count FROM oauth_refresh_contracts WHERE tenant_id = $1")
            .bind::<sql_types::Uuid, _>(tenant())
            .get_result::<Count>(&mut connection)
            .await
            .unwrap();
    assert_eq!(
        contracts.count, 1,
        "rotation must not create a BLAKE3-keyed duplicate of the SQL-keyed contract"
    );
    drop(repository);
    drop(connection);
    admin
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await
        .unwrap();
}

async fn make_public(connection: &mut AsyncPgConnection, client_id: Uuid) {
    sql_query(
        "UPDATE oauth_clients SET client_type = 'public', \
         token_endpoint_auth_method = 'none', client_secret_hash = NULL WHERE id = $1",
    )
    .bind::<sql_types::Uuid, _>(client_id)
    .execute(connection)
    .await
    .unwrap();
}

async fn issue_with_binding(
    url: &str,
    fixture: &Fixture,
    binding: Option<&str>,
) -> (String, RefreshToken) {
    let mut token = new_token(fixture, Utc::now());
    match binding {
        Some("dpop") => token.dpop_jkt = Some("A".repeat(43)),
        Some("mtls") => token.mtls_x5t_s256 = Some("B".repeat(43)),
        None => {}
        _ => unreachable!(),
    }
    let raw = token.raw_token.clone();
    let repository = TokenIssuanceRepository::new(create_pool(url, 1).unwrap());
    assert_eq!(
        repository
            .commit_token_issuance(issuance(
                fixture,
                RefreshTokenCommit::IssueNew {
                    token,
                    contract: contract(fixture),
                },
            ))
            .await
            .unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let source = lookup(url, &raw).await;
    (raw, source)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_unbound_replay_after_65_rotations_revokes_only_its_family() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    make_public(&mut connection, fixture.client_id).await;
    let (original_raw, mut current) = issue_at(&url, &fixture, Utc::now()).await;
    let (_, unrelated) = issue_at(&url, &fixture, Utc::now()).await;
    let unrelated_before = state(&mut connection, unrelated.token_family_id).await;
    let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
    for _ in 0..65 {
        let (input, raw) = rotation(&fixture, &current, &[A]);
        assert_eq!(
            repository.commit_token_issuance(input).await.unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        current = lookup(&url, &raw).await;
    }
    let before = state(&mut connection, current.token_family_id).await;
    assert_eq!(before.spent, 65);
    let tokens = TokenRepository::new(create_pool(&url, 1).unwrap());
    assert!(
        tokens
            .by_raw_refresh_token(tenant(), &format!("unknown-{}", Uuid::now_v7()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        state(&mut connection, current.token_family_id).await,
        before
    );
    let original = lookup(&url, &original_raw).await;
    assert!(original.expires_at > Utc::now());
    assert!(original.revoked_at.is_some());
    assert!(
        tokens
            .inspect_lost_response_successor(&original, fixture.client_id, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "unbound replay must not receive the bound lost-response exception"
    );
    let (replay, _) = rotation(&fixture, &original, &[A]);
    assert_eq!(
        repository.commit_token_issuance(replay).await.unwrap(),
        CommitTokenIssuanceResult::RotationConflict
    );
    let after = state(&mut connection, current.token_family_id).await;
    assert!(!after.family["revoked_at"].is_null());
    assert!(!after.family["reuse_detected_at"].is_null());
    let (next, _) = rotation(&fixture, &current, &[A]);
    assert_eq!(
        repository.commit_token_issuance(next).await.unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert_eq!(
        state(&mut connection, unrelated.token_family_id).await,
        unrelated_before
    );
    let audit = sql_query(
        "SELECT count(*) AS count FROM security_audit_events \
         WHERE event_type = 'refresh_reuse_detected' \
         AND payload->>'token_family_id' = $1",
    )
    .bind::<sql_types::Text, _>(current.token_family_id.to_string())
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(audit.count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_and_public_sender_bound_families_keep_64_proofs() {
    let Some(url) = database_url() else { return };
    for (public, binding) in [(false, None), (true, Some("dpop")), (true, Some("mtls"))] {
        let fixture = fixture(&url).await;
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        if public {
            make_public(&mut connection, fixture.client_id).await;
        }
        let (first_raw, mut current) = issue_with_binding(&url, &fixture, binding).await;
        let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
        let mut predecessor = current.clone();
        for _ in 0..66 {
            predecessor = current.clone();
            let (input, raw) = rotation(&fixture, &current, &[A]);
            assert_eq!(
                repository.commit_token_issuance(input).await.unwrap(),
                CommitTokenIssuanceResult::Committed
            );
            current = lookup(&url, &raw).await;
        }
        let family = state(&mut connection, current.token_family_id).await;
        assert_eq!(family.spent, nazo_auth::MAX_SPENT_PROOFS_PER_REFRESH_FAMILY);
        assert!(family.family["revoked_at"].is_null());
        let tokens = TokenRepository::new(create_pool(&url, 1).unwrap());
        assert!(
            tokens
                .by_raw_refresh_token(tenant(), &first_raw)
                .await
                .unwrap()
                .is_none()
        );
        let recovered = tokens
            .inspect_lost_response_successor(&predecessor, fixture.client_id, Utc::now())
            .await
            .unwrap();
        assert_eq!(
            recovered.map(|token| token.id),
            binding.map(|_| current.id),
            "only a real sender-bound direct predecessor gets lost-response recovery"
        );
        assert_eq!(
            state(&mut connection, current.token_family_id).await,
            family
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_proof_cleanup_respects_original_expiry_without_ending_live_family() {
    use nazo_persistence::SecurityStateMaintenancePort;
    use nazo_postgres::SecurityStateMaintenanceRepository;

    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    make_public(&mut connection, fixture.client_id).await;
    let (first_raw, mut current) = issue_at(&url, &fixture, Utc::now()).await;
    let repository = TokenIssuanceRepository::new(create_pool(&url, 1).unwrap());
    let mut recent_raw = String::new();
    for _ in 0..2 {
        let (input, raw) = rotation(&fixture, &current, &[A]);
        assert_eq!(
            repository.commit_token_issuance(input).await.unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        recent_raw = raw.clone();
        current = lookup(&url, &raw).await;
    }
    sql_query(
        "UPDATE oauth_refresh_spent_tokens SET spent_at = CURRENT_TIMESTAMP - interval '2 minutes', \
         expires_at = CURRENT_TIMESTAMP - interval '1 minute' \
         WHERE tenant_id = $1 AND refresh_token_blake3 = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Binary, _>(blake3::hash(first_raw.as_bytes()).as_bytes().to_vec())
    .execute(&mut connection).await.unwrap();
    let maintenance = SecurityStateMaintenanceRepository::new(create_pool(&url, 1).unwrap());
    // Other integration fixtures may have queued older due rows; observe our
    // own proof after bounded batches rather than asserting global counters.
    let tokens = TokenRepository::new(create_pool(&url, 1).unwrap());
    for _ in 0..64 {
        maintenance.cleanup_batch().await.unwrap();
        if tokens
            .by_raw_refresh_token(tenant(), &first_raw)
            .await
            .unwrap()
            .is_none()
        {
            break;
        }
    }
    assert!(
        tokens
            .by_raw_refresh_token(tenant(), &first_raw)
            .await
            .unwrap()
            .is_none()
    );
    let after = state(&mut connection, current.token_family_id).await;
    assert_eq!(after.spent, 1);
    assert!(after.family["revoked_at"].is_null());
    assert_eq!(lookup(&url, &recent_raw).await.id, current.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_class_downgrade_serializes_with_rotation_in_both_orders() {
    let Some(url) = database_url() else { return };
    for downgrade_first in [true, false] {
        let fixture = fixture(&url).await;
        let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
        let (input, successor_raw) = rotation(&fixture, &source, &[A]);
        let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
        let suffix = Uuid::now_v7().simple().to_string();
        let rotate_app = format!("downgrade-rotate-{suffix}");
        let repository =
            TokenIssuanceRepository::new(create_pool(tagged_url(&url, &rotate_app), 1).unwrap());
        if downgrade_first {
            coordinator.batch_execute("BEGIN").await.unwrap();
            make_public(&mut coordinator, fixture.client_id).await;
            let mut rotating =
                tokio::spawn(async move { repository.commit_token_issuance(input).await });
            let mut observer = AsyncPgConnection::establish(&url).await.unwrap();
            wait_for_lock(&mut observer, &rotate_app, &mut rotating).await;
            coordinator.batch_execute("COMMIT").await.unwrap();
            assert_eq!(
                rotating.await.unwrap().unwrap(),
                CommitTokenIssuanceResult::RefreshGrantUnavailable
            );
        } else {
            // Stop issuance at its real audit append, after it holds client
            // FOR SHARE and family authority locks. The downgrade must wait.
            let gate = format!("test_downgrade_gate_{suffix}");
            let gate_key = i64::from_be_bytes(Uuid::now_v7().as_bytes()[8..].try_into().unwrap());
            coordinator.batch_execute(&format!(
                "CREATE FUNCTION {gate}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
                 IF NEW.event_id = '{}'::uuid THEN PERFORM pg_advisory_xact_lock({gate_key}); END IF; \
                 RETURN NEW; END $$; CREATE TRIGGER {gate} BEFORE INSERT ON security_audit_events \
                 FOR EACH ROW EXECUTE FUNCTION {gate}();",
                input.issuance_id,
            )).await.unwrap();
            sql_query("SELECT pg_advisory_lock($1)")
                .bind::<sql_types::BigInt, _>(gate_key)
                .execute(&mut coordinator)
                .await
                .unwrap();
            let mut rotating =
                tokio::spawn(async move { repository.commit_token_issuance(input).await });
            wait_for_lock(&mut coordinator, &rotate_app, &mut rotating).await;
            let downgrade_app = format!("downgrade-mutate-{suffix}");
            let downgrade_url = tagged_url(&url, &downgrade_app);
            let client_id = fixture.client_id;
            let mut mutating = tokio::spawn(async move {
                let mut connection = AsyncPgConnection::establish(&downgrade_url).await.unwrap();
                make_public(&mut connection, client_id).await;
            });
            wait_for_lock(&mut coordinator, &downgrade_app, &mut mutating).await;
            sql_query("SELECT pg_advisory_unlock($1)")
                .bind::<sql_types::BigInt, _>(gate_key)
                .execute(&mut coordinator)
                .await
                .unwrap();
            assert_eq!(
                rotating.await.unwrap().unwrap(),
                CommitTokenIssuanceResult::Committed
            );
            mutating.await.unwrap();
            coordinator
                .batch_execute(&format!(
                    "DROP TRIGGER {gate} ON security_audit_events; DROP FUNCTION {gate}();",
                ))
                .await
                .unwrap();
            assert!(lookup(&url, &successor_raw).await.revoked_at.is_some());
        }
        let after = state(&mut coordinator, source.token_family_id).await;
        assert!(!after.family["revoked_at"].is_null());
        assert!(
            after.family["reuse_detected_at"].is_null(),
            "a class change is not evidence of replay"
        );
        let audit = sql_query(
            "SELECT count(*) AS count FROM security_audit_events \
             WHERE event_type = 'refresh_family_security_revoked' \
             AND payload->>'token_family_id' = $1 \
             AND payload->>'reason' = 'client_authentication_class_downgrade'",
        )
        .bind::<sql_types::Text, _>(source.token_family_id.to_string())
        .get_result::<Count>(&mut coordinator)
        .await
        .unwrap();
        assert_eq!(audit.count, 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_retention_upgrade_invalidates_unprovable_history_without_reviving_on_down() {
    let Some(base) = database_url() else { return };
    let name = format!("refresh_retention_{}", Uuid::now_v7().simple());
    let mut admin = AsyncPgConnection::establish(&base).await.unwrap();
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .unwrap();
    let mut parsed = url::Url::parse(&base).unwrap();
    parsed.set_path(&name);
    let url = parsed.to_string();
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut migrations: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir() && path.join("up.sql").is_file())
        .collect();
    migrations.sort();
    let cutover = migrations
        .iter()
        .position(|path| path.file_name().unwrap() == "20261001000500_refresh_replay_retention")
        .expect("public replay retention migration must exist");
    for migration in &migrations[..cutover] {
        apply_migration(&mut connection, migration).await;
    }
    // The current repository uses this invoker-only creation boundary. Install
    // its function on the genuine preceding tables; it changes neither their
    // schema nor replay-retention data, so the historical cutover stays real.
    let creation = migrations
        .iter()
        .find(|path| path.file_name().unwrap() == "20261009000100_refresh_family_creation_boundary")
        .expect("family creation boundary migration must exist");
    apply_migration(&mut connection, creation).await;
    // Populate the genuine preceding schema. No proof count can distinguish a
    // fresh family from one whose old opaque-token associations were trimmed.
    let public = seed_fixture(&mut connection).await;
    make_public(&mut connection, public.client_id).await;
    let (old_raw, old) = issue_at(&url, &public, Utc::now()).await;
    let repository = TokenIssuanceRepository::new(create_pool(&url, 1).unwrap());
    let (rotated, latest_raw) = rotation(&public, &old, &[A]);
    assert_eq!(
        repository.commit_token_issuance(rotated).await.unwrap(),
        CommitTokenIssuanceResult::Committed
    );
    let legacy_current = lookup(&url, &latest_raw).await;
    // This deliberately models already-lost pre-upgrade evidence; the actual
    // migration must revoke the family, never try to recreate the opaque proof.
    sql_query("DELETE FROM oauth_refresh_spent_tokens WHERE token_family_id = $1")
        .bind::<sql_types::Uuid, _>(old.token_family_id)
        .execute(&mut connection)
        .await
        .unwrap();
    let (_, public_no_proofs) = issue_at(&url, &public, Utc::now()).await;
    let (_, dpop) = issue_with_binding(&url, &public, Some("dpop")).await;
    let (_, mtls) = issue_with_binding(&url, &public, Some("mtls")).await;
    let confidential = seed_fixture(&mut connection).await;
    let (_, confidential_source) = issue_at(&url, &confidential, Utc::now()).await;
    let dpop_before = state(&mut connection, dpop.token_family_id).await;
    let mtls_before = state(&mut connection, mtls.token_family_id).await;
    let confidential_before = state(&mut connection, confidential_source.token_family_id).await;
    apply_migration(&mut connection, &migrations[cutover]).await;
    for source in [&old, &public_no_proofs] {
        let after = state(&mut connection, source.token_family_id).await;
        assert!(!after.family["revoked_at"].is_null());
        assert!(after.family["reuse_detected_at"].is_null());
        let audit = sql_query(
            "SELECT count(*) AS count FROM security_audit_events \
             WHERE event_type = 'refresh_family_security_revoked' \
             AND payload->>'token_family_id' = $1 \
             AND payload->>'reason' = 'public_replay_retention_cutover'",
        )
        .bind::<sql_types::Text, _>(source.token_family_id.to_string())
        .get_result::<Count>(&mut connection)
        .await
        .unwrap();
        assert_eq!(audit.count, 1);
    }
    let (blocked_after_upgrade, _) = rotation(&public, &legacy_current, &[A]);
    assert_eq!(
        repository
            .commit_token_issuance(blocked_after_upgrade)
            .await
            .unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert_eq!(
        state(&mut connection, dpop.token_family_id).await,
        dpop_before
    );
    assert_eq!(
        state(&mut connection, mtls.token_family_id).await,
        mtls_before
    );
    assert_eq!(
        state(&mut connection, confidential_source.token_family_id).await,
        confidential_before
    );
    assert!(
        TokenRepository::new(create_pool(&url, 1).unwrap())
            .by_raw_refresh_token(tenant(), &old_raw)
            .await
            .unwrap()
            .is_none()
    );
    let (_, fresh_public) = issue_at(&url, &public, Utc::now()).await;
    assert!(
        fresh_public.revoked_at.is_none(),
        "post-cutover grants start with complete proof retention"
    );

    // Existing client mutation also traverses the invoker-rights tenant-owner
    // guard, whose only additional relation read is tenant_resource_bindings.
    // Keep that read-only prerequisite; no direct audit-table permission and
    // no SECURITY DEFINER privilege expansion is needed by the new trigger.
    let role = format!("retention_writer_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "CREATE ROLE {role} NOLOGIN; GRANT USAGE ON SCHEMA public TO {role}; \
         GRANT SELECT, UPDATE ON oauth_clients, oauth_refresh_families TO {role}; \
         GRANT SELECT ON tenant_resource_bindings TO {role}; \
         GRANT EXECUTE ON FUNCTION public.nazo_persist_security_audit_event(uuid,text,text,jsonb,timestamptz) TO {role}; \
         SET ROLE {role};",
    )).await.unwrap();
    make_public(&mut connection, confidential.client_id).await;
    connection.batch_execute("RESET ROLE").await.unwrap();
    assert!(
        !state(&mut connection, confidential_source.token_family_id)
            .await
            .family["revoked_at"]
            .is_null()
    );
    connection
        .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role};"))
        .await
        .unwrap();

    let revoked_before_down = state(&mut connection, old.token_family_id).await;
    let down = std::fs::read_to_string(migrations[cutover].join("down.sql")).unwrap();
    connection.batch_execute(&down).await.unwrap();
    assert_eq!(
        state(&mut connection, old.token_family_id).await,
        revoked_before_down
    );
    let (blocked_after_down, _) = rotation(&public, &legacy_current, &[A]);
    assert_eq!(
        repository
            .commit_token_issuance(blocked_after_down)
            .await
            .unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    let audit = sql_query(
        "SELECT count(*) AS count FROM security_audit_events \
         WHERE event_type = 'refresh_family_security_revoked'",
    )
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        audit.count, 3,
        "rollback preserves both cutover and downgrade evidence"
    );
    drop(repository);
    drop(connection);
    admin
        .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_class_downgrade_rolls_back_when_required_audit_fails() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let before = state(&mut connection, source.token_family_id).await;
    let gate = format!("test_downgrade_audit_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(
        "CREATE FUNCTION {gate}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN \
         IF NEW.event_type = 'refresh_family_security_revoked' \
         AND NEW.payload->>'client_id' = '{}' THEN RAISE EXCEPTION 'test required audit failure'; END IF; \
         RETURN NEW; END $$; CREATE TRIGGER {gate} BEFORE INSERT ON security_audit_events \
         FOR EACH ROW EXECUTE FUNCTION {gate}();",
        fixture.client_id,
    )).await.unwrap();
    assert!(sql_query(
        "UPDATE oauth_clients SET client_type = 'public', token_endpoint_auth_method = 'none' WHERE id = $1",
    ).bind::<sql_types::Uuid, _>(fixture.client_id)
        .execute(&mut connection).await.is_err());
    assert_eq!(state(&mut connection, source.token_family_id).await, before);
    let unchanged = sql_query(
        "SELECT count(*) AS count FROM oauth_clients WHERE id = $1 AND client_type = 'confidential'",
    ).bind::<sql_types::Uuid, _>(fixture.client_id)
        .get_result::<Count>(&mut connection).await.unwrap();
    assert_eq!(unchanged.count, 1);
    connection
        .batch_execute(&format!(
            "DROP TRIGGER {gate} ON security_audit_events; DROP FUNCTION {gate}();",
        ))
        .await
        .unwrap();
    make_public(&mut connection, fixture.client_id).await;
    assert!(!state(&mut connection, source.token_family_id).await.family["revoked_at"].is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r05_snapshot_candidate_rechecks_terminal_state_and_member_at_commit() {
    let Some(url) = database_url() else { return };
    for change in ["revoke", "expire", "rerotate", "spent-edge"] {
        let fixture = fixture(&url).await;
        let (original_raw, original) = issue_with_binding(&url, &fixture, Some("dpop")).await;
        let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
        let (first_rotation, child_raw) = rotation(&fixture, &original, &[A]);
        assert_eq!(
            repository
                .commit_token_issuance(first_rotation)
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let snapshot = repository
            .refresh_token_snapshot(tenant(), &original_raw, fixture.client_id, Utc::now())
            .await
            .unwrap()
            .expect("spent presentation exists");
        assert_eq!(snapshot.presented.id, original.id);
        let candidate = snapshot
            .successor
            .unwrap()
            .expect("bound direct successor exists");
        let child = lookup(&url, &child_raw).await;
        assert_eq!(candidate, child);
        let (mut retry, _) = rotation(&fixture, &candidate, &[A]);
        if let Some(RefreshTokenCommit::UseExisting {
            rotation: Some(token),
            ..
        }) = retry.refresh_token.as_mut()
        {
            token.lost_response_retry = Some(nazo_auth::LostResponseRetry {
                original_id: original.id,
                original_blake3: original.token_blake3,
                retry_started_at: Utc::now(),
            });
        } else {
            panic!("rotation carries its existing authority");
        }
        let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
        match change {
            "revoke" => {
                repository
                    .revoke_token(nazo_auth::TokenRevocation {
                        tenant_id: tenant(),
                        client_id: fixture.client_id,
                        raw_token: &child_raw,
                        access_token: None,
                    })
                    .await
                    .unwrap();
            }
            "expire" => {
                sql_query("UPDATE oauth_refresh_families SET current_issued_at = CURRENT_TIMESTAMP - interval '2 seconds', current_expires_at = CURRENT_TIMESTAMP - interval '1 second' WHERE tenant_id = $1 AND token_family_id = $2")
                    .bind::<sql_types::Uuid, _>(tenant()).bind::<sql_types::Uuid, _>(child.token_family_id)
                    .execute(&mut connection).await.unwrap();
            }
            "rerotate" => {
                let (next, _) = rotation(&fixture, &child, &[A]);
                assert_eq!(
                    repository.commit_token_issuance(next).await.unwrap(),
                    CommitTokenIssuanceResult::Committed
                );
            }
            "spent-edge" => {
                sql_query("UPDATE oauth_refresh_spent_tokens SET spent_at = CURRENT_TIMESTAMP - interval '61 seconds' WHERE tenant_id = $1 AND refresh_token_blake3 = $2")
                    .bind::<sql_types::Uuid, _>(tenant()).bind::<sql_types::Binary, _>(original.token_blake3.as_slice())
                    .execute(&mut connection).await.unwrap();
            }
            _ => unreachable!(),
        }
        let expected = if matches!(change, "rerotate" | "spent-edge") {
            CommitTokenIssuanceResult::RotationConflict
        } else {
            CommitTokenIssuanceResult::RefreshGrantUnavailable
        };
        assert_eq!(
            repository
                .commit_token_issuance(retry.clone())
                .await
                .unwrap(),
            expected
        );
        let audit = sql_query("SELECT count(*) AS count FROM security_audit_events WHERE event_id = $1 AND event_type = 'token_issued'")
            .bind::<sql_types::Uuid, _>(retry.issuance_id).get_result::<Count>(&mut connection).await.unwrap();
        assert_eq!(
            audit.count, 0,
            "a stale candidate publishes no issuance success"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_delayed_rotation_uses_transition_clock_without_false_reuse() {
    let Some(url) = database_url() else { return };
    for binding in ["dpop", "mtls"] {
        for old_anchor in [true, false] {
            let fixture = fixture(&url).await;
            let (original_raw, original) = issue_with_binding(&url, &fixture, Some(binding)).await;
            let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
            let (mut first, child_raw) = rotation(&fixture, &original, &[A]);
            // Simulate signing/pool delay with explicit timestamps, without sleeping.
            let signed_at = DateTime::<Utc>::from_timestamp_micros(
                (Utc::now() - Duration::seconds(20)).timestamp_micros(),
            )
            .unwrap();
            let signed_expiry = signed_at + Duration::hours(1);
            if let Some(RefreshTokenCommit::UseExisting {
                rotation: Some(token),
                ..
            }) = first.refresh_token.as_mut()
            {
                token.issued_at = signed_at;
                token.expires_at = signed_expiry;
            } else {
                panic!("rotation carries its existing authority");
            }
            let before_commit = Utc::now();
            assert_eq!(
                repository.commit_token_issuance(first).await.unwrap(),
                CommitTokenIssuanceResult::Committed
            );
            let operation_completed_at = Utc::now();
            let child = lookup(&url, &child_raw).await;
            assert_eq!(child.issued_at, signed_at);
            assert_eq!(child.expires_at, signed_expiry);
            let spent = lookup(&url, &original_raw).await;
            // Admission is exactly 45s after the durable transition, independent
            // of repository-return or fixture-read scheduling delays.
            let retry_started_at = spent.revoked_at.unwrap() + Duration::seconds(45);
            assert_eq!(spent.expires_at, original.expires_at);
            let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
            if old_anchor {
                // Recreate the defective persisted anchor as a negative control.
                sql_query(
                    "UPDATE oauth_refresh_spent_tokens SET spent_at = $3 \
                     WHERE tenant_id = $1 AND refresh_token_blake3 = $2",
                )
                .bind::<sql_types::Uuid, _>(tenant())
                .bind::<sql_types::Binary, _>(original.token_blake3.as_slice())
                .bind::<sql_types::Timestamptz, _>(signed_at)
                .execute(&mut connection)
                .await
                .unwrap();
            }
            let snapshot = repository
                .refresh_token_snapshot(
                    tenant(),
                    &original_raw,
                    fixture.client_id,
                    retry_started_at,
                )
                .await
                .unwrap()
                .expect("unexpired spent presentation exists");
            let candidate = snapshot.successor.unwrap();
            // No candidate retains original authority: the locked mismatch
            // exercises the actual false-compromise branch.
            let source = candidate.as_ref().unwrap_or(&snapshot.presented);
            let (mut retry, retry_raw) = rotation(&fixture, source, &[A]);
            if !old_anchor && candidate.is_some() {
                if let Some(RefreshTokenCommit::UseExisting {
                    rotation: Some(token),
                    ..
                }) = retry.refresh_token.as_mut()
                {
                    token.lost_response_retry = Some(nazo_auth::LostResponseRetry {
                        original_id: original.id,
                        original_blake3: original.token_blake3,
                        retry_started_at,
                    });
                } else {
                    panic!("rotation carries its existing authority");
                }
            }
            let expected = if old_anchor {
                CommitTokenIssuanceResult::RotationConflict
            } else {
                CommitTokenIssuanceResult::Committed
            };
            let result = repository
                .commit_token_issuance(retry.clone())
                .await
                .unwrap();
            let after = state(&mut connection, original.token_family_id).await;
            let reuse = sql_query(
                "SELECT count(*) AS count FROM security_audit_events \
                 WHERE event_type = 'refresh_reuse_detected' \
                   AND payload->>'issuance_id' = $1",
            )
            .bind::<sql_types::Text, _>(retry.issuance_id.to_string())
            .get_result::<Count>(&mut connection)
            .await
            .unwrap();
            assert_eq!(
                result,
                expected,
                "45s retry: old_anchor={old_anchor}, successor_available={}, reuse_audit={}",
                candidate.is_some(),
                reuse.count,
            );
            assert_eq!(candidate.is_some(), !old_anchor);
            if !old_anchor {
                let transition_at = spent.revoked_at.expect("spent transition is retained");
                assert!(transition_at >= before_commit && transition_at <= operation_completed_at);
            }
            assert_eq!(reuse.count, i64::from(old_anchor));
            assert_eq!(after.family["revoked_at"].is_null(), !old_anchor);
            assert_eq!(after.family["reuse_detected_at"].is_null(), !old_anchor);
            if old_anchor {
                let issued = sql_query(
                    "SELECT count(*) AS count FROM security_audit_events \
                     WHERE event_id = $1 AND event_type = 'token_issued'",
                )
                .bind::<sql_types::Uuid, _>(retry.issuance_id)
                .get_result::<Count>(&mut connection)
                .await
                .unwrap();
                assert_eq!(issued.count, 0);
            } else {
                assert_issuance_writes(&mut connection, retry.issuance_id, true).await;
                let recovered = lookup(&url, &retry_raw).await;
                assert_eq!(recovered.dpop_jkt, original.dpop_jkt);
                assert_eq!(recovered.mtls_x5t_s256, original.mtls_x5t_s256);
                assert_eq!(
                    lookup(&url, &original_raw).await.expires_at,
                    original.expires_at
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_retry_rechecks_exact_transition_window_at_commit() {
    let Some(url) = database_url() else { return };
    for binding in ["dpop", "mtls"] {
        for elapsed in [
            Duration::zero(),
            Duration::seconds(60),
            Duration::microseconds(-1),
            Duration::seconds(60) + Duration::microseconds(1),
        ] {
            let fixture = fixture(&url).await;
            let (original_raw, original) = issue_with_binding(&url, &fixture, Some(binding)).await;
            let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
            let (first, child_raw) = rotation(&fixture, &original, &[A]);
            assert_eq!(
                repository.commit_token_issuance(first).await.unwrap(),
                CommitTokenIssuanceResult::Committed
            );
            let spent = lookup(&url, &original_raw).await;
            assert_eq!(spent.expires_at, original.expires_at);
            let retry_started_at = spent.revoked_at.unwrap() + elapsed;
            let within = elapsed >= Duration::zero() && elapsed <= Duration::seconds(60);
            let snapshot = repository
                .refresh_token_snapshot(
                    tenant(),
                    &original_raw,
                    fixture.client_id,
                    retry_started_at,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.successor.unwrap().is_some(), within);
            // A cached direct-successor authority must pass the locked edge too.
            let child = lookup(&url, &child_raw).await;
            let (mut retry, _) = rotation(&fixture, &child, &[A]);
            if let Some(RefreshTokenCommit::UseExisting {
                rotation: Some(token),
                ..
            }) = retry.refresh_token.as_mut()
            {
                token.lost_response_retry = Some(nazo_auth::LostResponseRetry {
                    original_id: original.id,
                    original_blake3: original.token_blake3,
                    retry_started_at,
                });
            } else {
                panic!("rotation carries its existing authority");
            }
            assert_eq!(
                repository.commit_token_issuance(retry).await.unwrap(),
                if within {
                    CommitTokenIssuanceResult::Committed
                } else {
                    CommitTokenIssuanceResult::RotationConflict
                }
            );
            assert_eq!(
                lookup(&url, &original_raw).await.expires_at,
                original.expires_at
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_rechecks_expiry_after_acquiring_the_source_row_lock() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
    let (input, _) = rotation(&fixture, &source, &[A]);
    let mut coordinator = AsyncPgConnection::establish(&url).await.unwrap();
    coordinator.batch_execute("BEGIN").await.unwrap();
    sql_query(
        "SELECT token_family_id FROM oauth_refresh_families \
         WHERE tenant_id = $1 AND token_family_id = $2 FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Uuid, _>(source.token_family_id)
    .execute(&mut coordinator)
    .await
    .unwrap();
    let application = format!("rotation-expiry-{}", Uuid::now_v7().simple());
    let repository =
        TokenIssuanceRepository::new(create_pool(tagged_url(&url, &application), 1).unwrap());
    let in_flight = input.clone();
    let mut task = tokio::spawn(async move { repository.commit_token_issuance(in_flight).await });
    wait_for_lock(&mut coordinator, &application, &mut task).await;
    sql_query(
        "UPDATE oauth_refresh_families \
         SET current_issued_at = $3 - interval '1 second', current_expires_at = $3 \
         WHERE tenant_id = $1 AND token_family_id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant())
    .bind::<sql_types::Uuid, _>(source.token_family_id)
    // Use the same Rust clock as the repository, not a separate DB clock.
    .bind::<sql_types::Timestamptz, _>(Utc::now() - Duration::milliseconds(1))
    .execute(&mut coordinator)
    .await
    .unwrap();
    let before = state(&mut coordinator, source.token_family_id).await;
    coordinator.batch_execute("COMMIT").await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap(),
        CommitTokenIssuanceResult::RefreshGrantUnavailable
    );
    assert_eq!(
        state(&mut coordinator, source.token_family_id).await,
        before
    );
    assert_issuance_writes(&mut coordinator, input.issuance_id, false).await;
}
