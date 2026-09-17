//! Unit coverage for the access-token revocation fact store (DB-002).
//!
//! `access_token_revocation_deadline` is deliberately context-free: it adds
//! exactly one maximum verifier clock-skew window to whatever verified `exp`
//! it receives. Idempotent retention is not its job — the monotonic upsert
//! keeps the longest deadline ever observed and the migration ledger runs the
//! retention backfill exactly once.
//!
//! The PostgreSQL-facing tests use session-local TEMP tables so they are
//! independent from application data, matching the sibling
//! `token_issuance` unit fixture.

use super::*;

use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, SimpleAsyncConnection};

use crate::repositories::token_issuance::revoke_access_tokens_for_owner_on_connection;

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

/// PostgreSQL stores timestamptz at microsecond precision; truncating the
/// fixture timestamps keeps equality assertions exact.
fn micros(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros()).expect("in-range timestamp")
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct StoredRevocation {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Timestamptz)]
    revoked_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

async fn stored_revocation(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    jti: &str,
) -> Option<StoredRevocation> {
    sql_query(
        "SELECT id, client_id, tenant_id, revoked_at, expires_at \
         FROM access_token_revocations \
         WHERE tenant_id = $1 AND access_token_jti_blake3 = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(blake3_hex(jti))
    .get_result::<StoredRevocation>(connection)
    .await
    .optional()
    .expect("stored revocation row should be readable")
}

/// Session-local copies of every table the revocation writers touch.
async fn temp_connection() -> Option<AsyncPgConnection> {
    let Some(url) = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
    else {
        assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
        return None;
    };
    let mut connection = AsyncPgConnection::establish(&url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(
            "CREATE TEMP TABLE oauth_token_issuances (
                tenant_id uuid, client_id uuid, user_id uuid,
                access_token_jti text, access_token_expires_at timestamptz);
             CREATE TEMP TABLE oauth_clients (id uuid, tenant_id uuid, client_id text);
             CREATE TEMP TABLE openid4vci_access_grants (
                tenant_id uuid, client_id text, subject_id uuid, token_id uuid,
                expires_at timestamptz, revoked_at timestamptz);
             CREATE TEMP TABLE access_token_revocations (
                id uuid, access_token_jti_blake3 text, client_id uuid, tenant_id uuid,
                revoked_at timestamptz, expires_at timestamptz,
                UNIQUE (tenant_id, access_token_jti_blake3));",
        )
        .await
        .expect("temp revocation fixture should create");
    Some(connection)
}

fn revocation(
    tenant_id: Uuid,
    client_id: Uuid,
    jti: &str,
    revoked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> NewAccessTokenRevocation {
    NewAccessTokenRevocation {
        id: Uuid::now_v7(),
        access_token_jti_blake3: blake3_hex(jti),
        client_id,
        tenant_id,
        revoked_at,
        expires_at,
    }
}

#[test]
fn deadline_is_exp_plus_exactly_one_clock_skew_window() {
    let exp = DateTime::from_timestamp(1_700_000_000, 123_456_789)
        .expect("fixed exp should be representable");
    let deadline =
        access_token_revocation_deadline(exp).expect("a representable exp must produce a deadline");
    assert_eq!(
        deadline.signed_duration_since(exp),
        chrono::Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
        "the stored deadline is the verified exp plus exactly one maximum \
         verifier clock-skew window"
    );
    assert_eq!(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS, 60);
}

#[test]
fn deadline_rejects_an_unrepresentable_exp_instead_of_wrapping() {
    let result = access_token_revocation_deadline(DateTime::<Utc>::MAX_UTC);
    match &result {
        Err(RepositoryError::Consistency(message)) => assert!(
            message.contains("not representable"),
            "the consistency error must name the unrepresentable deadline: {message}"
        ),
        _ => panic!("an overflowing deadline must fail as a consistency error, got {result:?}"),
    }
}

/// The helper has no already-padded notion: whatever timestamp it is given is
/// treated as the verified `exp` and receives exactly one additional window.
/// Re-padding is therefore observable and bounded — the monotonic upsert and
/// the ledger-run-once backfill are what prevent unbounded extension, not
/// silent idempotence inside this function.
#[test]
fn deadline_adds_one_more_window_to_an_already_padded_input() {
    let exp = DateTime::from_timestamp(1_700_000_000, 0).expect("fixed exp should be valid");
    let padded = access_token_revocation_deadline(exp).expect("first window should apply");
    let repadded =
        access_token_revocation_deadline(padded).expect("a padded input still represents an exp");
    assert_eq!(
        repadded.signed_duration_since(padded),
        chrono::Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
        "an already-padded value gains exactly one more window"
    );
    assert_eq!(
        repadded.signed_duration_since(exp),
        chrono::Duration::seconds(2 * MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
    );
}

#[tokio::test]
async fn upsert_extends_only_forward_and_preserves_the_first_fact() {
    let Some(mut connection) = temp_connection().await else {
        return;
    };
    let tenant = Uuid::now_v7();
    let first_client = Uuid::now_v7();
    let other_client = Uuid::now_v7();
    let jti = format!("mono-{}", Uuid::now_v7());
    let first_revoked_at = micros(Utc::now() - chrono::Duration::minutes(2));
    let base = micros(Utc::now() + chrono::Duration::minutes(5));

    let first = revocation(
        tenant,
        first_client,
        &jti,
        first_revoked_at,
        base + chrono::Duration::seconds(60),
    );
    let first_id = first.id;
    assert_eq!(
        upsert_access_token_revocations(&mut connection, &[first])
            .await
            .expect("initial revocation fact should insert"),
        1
    );

    // An equal or shorter deadline is not an extension: the upsert filter
    // leaves the stored row byte-identical and reports no write.
    for expires_at in [base + chrono::Duration::seconds(60), base] {
        assert_eq!(
            upsert_access_token_revocations(
                &mut connection,
                &[revocation(
                    tenant,
                    other_client,
                    &jti,
                    micros(Utc::now()),
                    expires_at,
                )],
            )
            .await
            .expect("non-extending upsert should be a no-op"),
            0,
            "a non-longer deadline must not touch the stored fact"
        );
    }
    let stored = stored_revocation(&mut connection, tenant, &jti)
        .await
        .expect("the revocation fact should exist");
    assert_eq!(stored.id, first_id, "the fact id is never rewritten");
    assert_eq!(
        stored.client_id, first_client,
        "ownership is never rewritten"
    );
    assert_eq!(stored.tenant_id, tenant);
    assert_eq!(
        stored.revoked_at, first_revoked_at,
        "the first revocation timestamp is authoritative"
    );
    assert_eq!(stored.expires_at, base + chrono::Duration::seconds(60));

    // A longer deadline extends the retention window; identity stays intact.
    assert_eq!(
        upsert_access_token_revocations(
            &mut connection,
            &[revocation(
                tenant,
                other_client,
                &jti,
                micros(Utc::now()),
                base + chrono::Duration::seconds(120),
            )],
        )
        .await
        .expect("an extending upsert should update the deadline"),
        1
    );
    let stored = stored_revocation(&mut connection, tenant, &jti)
        .await
        .expect("the revocation fact should exist");
    assert_eq!(stored.id, first_id);
    assert_eq!(stored.client_id, first_client);
    assert_eq!(stored.revoked_at, first_revoked_at);
    assert_eq!(
        stored.expires_at,
        base + chrono::Duration::seconds(120),
        "the stored deadline is the maximum ever observed"
    );
}

/// PostgreSQL cannot run ON CONFLICT DO UPDATE twice on the same authority
/// key inside one statement, so callers must deduplicate a batch before
/// upserting — this pins that behavior.
#[tokio::test]
async fn upsert_rejects_duplicate_authority_keys_inside_one_batch() {
    let Some(mut connection) = temp_connection().await else {
        return;
    };
    let tenant = Uuid::now_v7();
    let client = Uuid::now_v7();
    let jti = format!("dup-{}", Uuid::now_v7());
    let now = micros(Utc::now());
    let batch = [
        revocation(
            tenant,
            client,
            &jti,
            now,
            now + chrono::Duration::seconds(60),
        ),
        revocation(
            tenant,
            client,
            &jti,
            now,
            now + chrono::Duration::seconds(120),
        ),
    ];
    let error = upsert_access_token_revocations(&mut connection, &batch)
        .await
        .expect_err("a duplicated authority key inside one batch must error");
    assert!(
        error
            .to_string()
            .contains("cannot affect row a second time"),
        "PostgreSQL should reject the double-touch: {error}"
    );
}

/// The owner-revocation cursor can surface the same (tenant, jti) from both
/// sources (a generic issuance row and a VCI access grant whose token id text
/// equals the JTI). The batch dedup keeps the longest deadline.
#[tokio::test]
async fn owner_batch_dedups_duplicate_keys_to_the_longest_deadline() {
    let Some(mut connection) = temp_connection().await else {
        return;
    };
    let tenant = Uuid::now_v7();
    let client = Uuid::now_v7();
    let user = Uuid::now_v7();
    let token_id = Uuid::now_v7();
    let jti = token_id.to_string();
    let short_exp = micros(Utc::now() + chrono::Duration::seconds(300));
    let long_exp = micros(Utc::now() + chrono::Duration::seconds(600));

    sql_query("INSERT INTO oauth_clients VALUES ($1, $2, 'dup-client')")
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(tenant)
        .execute(&mut connection)
        .await
        .expect("client fixture should insert");
    sql_query("INSERT INTO oauth_token_issuances VALUES ($1, $2, $3, $4, $5)")
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(user)
        .bind::<sql_types::Text, _>(jti.clone())
        .bind::<sql_types::Timestamptz, _>(short_exp)
        .execute(&mut connection)
        .await
        .expect("issuance fixture should insert");
    sql_query("INSERT INTO openid4vci_access_grants VALUES ($1, 'dup-client', $2, $3, $4, NULL)")
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(user)
        .bind::<sql_types::Uuid, _>(token_id)
        .bind::<sql_types::Timestamptz, _>(long_exp)
        .execute(&mut connection)
        .await
        .expect("vci grant fixture should insert");

    let affected = connection
        .transaction::<usize, diesel::result::Error, _>(async |connection| {
            revoke_access_tokens_for_owner_on_connection(connection, tenant, Some(client), None)
                .await
        })
        .await
        .expect("deduplicated owner revocation should commit");
    assert_eq!(affected, 1, "duplicate authority keys fold into one fact");

    let stored = stored_revocation(&mut connection, tenant, &jti)
        .await
        .expect("the revocation fact should exist");
    assert_eq!(stored.client_id, client);
    assert_eq!(
        stored.expires_at,
        long_exp + chrono::Duration::seconds(MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS),
        "the deduplicated fact keeps the longest of the duplicated deadlines"
    );
}

/// When the same (tenant, jti) arrives with contradictory ownership the whole
/// revocation transaction rolls back; a different tenant sharing the JTI is a
/// separate authority key and stays untouched.
#[tokio::test]
async fn owner_batch_conflicting_clients_roll_back_and_other_tenants_are_untouched() {
    let Some(mut connection) = temp_connection().await else {
        return;
    };
    let tenant = Uuid::now_v7();
    let other_tenant = Uuid::now_v7();
    let client = Uuid::now_v7();
    let conflicting_client = Uuid::now_v7();
    let user = Uuid::now_v7();
    let token_id = Uuid::now_v7();
    let jti = token_id.to_string();
    let exp = micros(Utc::now() + chrono::Duration::seconds(300));

    // The same JTI under another tenant is an independent authority key.
    let foreign = revocation(
        other_tenant,
        Uuid::now_v7(),
        &jti,
        micros(Utc::now()),
        micros(Utc::now() + chrono::Duration::seconds(90)),
    );
    let foreign_id = foreign.id;
    let foreign_expires_at = foreign.expires_at;
    upsert_access_token_revocations(&mut connection, &[foreign])
        .await
        .expect("foreign-tenant fact should insert");

    sql_query("INSERT INTO oauth_clients VALUES ($1, $2, 'owner-a'), ($3, $2, 'owner-b')")
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(conflicting_client)
        .execute(&mut connection)
        .await
        .expect("client fixtures should insert");
    sql_query("INSERT INTO oauth_token_issuances VALUES ($1, $2, $3, $4, $5)")
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(client)
        .bind::<sql_types::Uuid, _>(user)
        .bind::<sql_types::Text, _>(jti.clone())
        .bind::<sql_types::Timestamptz, _>(exp)
        .execute(&mut connection)
        .await
        .expect("issuance fixture should insert");
    sql_query("INSERT INTO openid4vci_access_grants VALUES ($1, 'owner-b', $2, $3, $4, NULL)")
        .bind::<sql_types::Uuid, _>(tenant)
        .bind::<sql_types::Uuid, _>(user)
        .bind::<sql_types::Uuid, _>(token_id)
        .bind::<sql_types::Timestamptz, _>(exp)
        .execute(&mut connection)
        .await
        .expect("conflicting vci grant fixture should insert");

    let outcome = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            // A same-transaction write before the failing call must roll back
            // together with the partial revocation work.
            upsert_access_token_revocations(
                connection,
                &[revocation(
                    tenant,
                    client,
                    "marker-jti",
                    micros(Utc::now()),
                    micros(Utc::now() + chrono::Duration::seconds(120)),
                )],
            )
            .await?;
            revoke_access_tokens_for_owner_on_connection(connection, tenant, None, Some(user))
                .await?;
            Ok(())
        })
        .await;
    let error = outcome.expect_err("conflicting ownership must abort the transaction");
    assert!(
        matches!(error, diesel::result::Error::DeserializationError(_))
            && error
                .to_string()
                .contains("conflicting access-token revocation ownership"),
        "the conflict must surface as a typed deserialization failure: {error:?}"
    );

    let remaining = sql_query(
        "SELECT count(*)::bigint AS count FROM access_token_revocations WHERE tenant_id = $1",
    )
    .bind::<sql_types::Uuid, _>(tenant)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("tenant revocation count should query");
    assert_eq!(
        remaining.count, 0,
        "the marker write and every batched revocation must roll back together"
    );
    let foreign = stored_revocation(&mut connection, other_tenant, &jti)
        .await
        .expect("the other tenant's fact is a separate authority key");
    assert_eq!(foreign.id, foreign_id);
    assert_eq!(
        foreign.expires_at, foreign_expires_at,
        "the conflicting tenant-scoped batch must not touch other tenants"
    );
}
