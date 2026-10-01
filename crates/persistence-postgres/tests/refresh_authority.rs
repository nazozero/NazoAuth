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
    let remaining = sql_query(
        "SELECT count(*) AS count FROM oauth_refresh_families WHERE token_family_id = $1",
    )
    .bind::<sql_types::Uuid, _>(family_id)
    .get_result::<Count>(&mut connection)
    .await
    .unwrap();
    assert_eq!(remaining.count, 0);
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
        if !capacity {
            assert!(
                state(&mut connection, source.token_family_id).await.family["reuse_detected_at"]
                    .is_null()
            );
        }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_legal_preserves_commit_without_consuming_or_mutating_the_source() {
    let Some(url) = database_url() else { return };
    let fixture = fixture(&url).await;
    let (_, source) = issue_at(&url, &fixture, Utc::now()).await;
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    let before = state(&mut connection, source.token_family_id).await;
    let left = preserve(&fixture, &source);
    let right = preserve(&fixture, &source);
    let repository = TokenIssuanceRepository::new(create_pool(&url, 2).unwrap());
    let (left_result, right_result) = tokio::join!(
        repository.commit_token_issuance(left.clone()),
        repository.commit_token_issuance(right.clone()),
    );
    assert_eq!(left_result.unwrap(), CommitTokenIssuanceResult::Committed);
    assert_eq!(right_result.unwrap(), CommitTokenIssuanceResult::Committed);
    assert_eq!(state(&mut connection, source.token_family_id).await, before);
    assert_issuance_writes(&mut connection, left.issuance_id, true).await;
    assert_issuance_writes(&mut connection, right.issuance_id, true).await;
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
        if capacity {
            let remaining = sql_query(
                "SELECT count(*) AS count FROM oauth_refresh_families WHERE token_family_id = $1",
            )
            .bind::<sql_types::Uuid, _>(source.token_family_id)
            .get_result::<Count>(&mut coordinator)
            .await
            .unwrap();
            assert_eq!(
                remaining.count, 0,
                "capacity retires the source after the valid Preserve commit"
            );
        } else {
            let after = state(&mut coordinator, source.token_family_id).await;
            assert!(!after.family["revoked_at"].is_null());
            assert!(after.family["reuse_detected_at"].is_null());
        }
    }
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
