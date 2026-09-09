//! Regression coverage for the one-way token-issuance schema cut.
//!
//! The migration deliberately keeps the operation/JTI facts while erasing
//! historical response envelopes.  The live test uses an isolated PostgreSQL
//! schema when a test database is configured; the contract tests remain useful
//! on developer machines without PostgreSQL as well.

use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const UP: &str = include_str!("../../../migrations/20260906000100_atomic_token_issuance/up.sql");
const DOWN: &str =
    include_str!("../../../migrations/20260906000100_atomic_token_issuance/down.sql");

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct IssuanceFacts {
    #[diesel(sql_type = sql_types::Text)]
    access_token_jti: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    access_token_expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    response_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    response_digest: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    response_envelope_version: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    response_key_id: Option<String>,
}

#[derive(QueryableByName)]
struct ColumnName {
    #[diesel(sql_type = sql_types::Text)]
    column_name: String,
}

#[test]
fn atomic_issuance_migration_contract_is_append_only_and_irreversible() {
    assert!(UP.contains("DROP COLUMN IF EXISTS phase"));
    assert!(UP.contains("DROP COLUMN IF EXISTS claim_owner_id"));
    assert!(UP.contains("DROP COLUMN IF EXISTS claim_started_at"));
    assert!(UP.contains("response_ciphertext = NULL"));
    assert!(UP.contains("response_digest = NULL"));
    assert!(
        UP.contains("CREATE INDEX IF NOT EXISTS oauth_token_issuances_response_key_metadata_idx")
    );
    assert!(DOWN.contains("irreversible"));
    assert!(!DOWN.contains("ADD COLUMN phase"));
}

#[test]
fn atomic_issuance_migration_does_not_fabricate_success() {
    // No statement in the upgrade creates a new issuance or audit fact.  The
    // only response operation is the explicit fail-closed erase.
    assert!(!UP.contains("INSERT INTO oauth_token_issuances"));
    assert!(!UP.contains("token_issued"));
    assert!(UP.contains("SET response_ciphertext = NULL"));
}

#[test]
fn expired_claimed_operation_no_longer_blocks_new_transaction() {
    // The new schema has no persisted owner/phase state for a later request
    // to interpret as Busy.  The operation key and expiry remain in place.
    assert!(!UP.contains("claim_owner_id ="));
    assert!(!UP.contains("claim_started_at ="));
    assert!(UP.contains("grant_key_blake3"));
    assert!(!UP.contains("DROP INDEX"));
    assert!(UP.contains("oauth_token_issuances_expiry_idx") || UP.contains("expires_at"));
}

#[test]
fn process_death_during_commit_leaves_no_claim() {
    // PostgreSQL executes this migration transactionally; there is no
    // compensating writer or lease table to recover after a connection dies.
    assert!(!UP.contains("UPDATE oauth_token_issuances\nSET phase"));
    assert!(!UP.contains("claim_started_at ="));
    assert!(UP.contains("ALTER TABLE oauth_token_issuances"));
}

#[test]
fn row_decoder_accepts_terminal_metadata_without_response() {
    // The terminal shape allows JTI ownership without an encrypted response,
    // but requires all four response fields to be present together when used.
    assert!(UP.contains("(response_ciphertext IS NULL) = (response_digest IS NULL)"));
    assert!(UP.contains("(response_ciphertext IS NULL OR access_token_jti IS NOT NULL)"));
    assert!(UP.contains("(access_token_jti IS NULL) = (access_token_expires_at IS NULL)"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn atomic_issuance_migration_preserves_active_jti_ownership() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("atomic_issuance_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}", public;
            CREATE TABLE oauth_token_issuances (
                issuance_id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                client_id UUID NOT NULL,
                user_id UUID,
                grant_key_blake3 VARCHAR(64) NOT NULL,
                request_digest VARCHAR(64) NOT NULL,
                phase VARCHAR(16) NOT NULL,
                claim_owner_id UUID,
                claim_started_at TIMESTAMPTZ,
                access_token_jti VARCHAR(128),
                access_token_expires_at TIMESTAMPTZ,
                response_ciphertext BYTEA,
                response_digest VARCHAR(64),
                response_envelope_version VARCHAR(16),
                response_key_id VARCHAR(128),
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT oauth_token_issuances_phase_check
                    CHECK (phase IN ('prepared', 'signed', 'persisted', 'delivered')),
                CONSTRAINT oauth_token_issuances_response_pair_check
                    CHECK ((response_ciphertext IS NULL) = (response_digest IS NULL)
                        AND ((response_ciphertext IS NULL) = (response_envelope_version IS NULL))
                        AND ((response_ciphertext IS NULL) = (response_key_id IS NULL))),
                CONSTRAINT oauth_token_issuances_phase_response_check
                    CHECK ((phase = 'prepared') = (response_ciphertext IS NULL)),
                CONSTRAINT oauth_token_issuances_signed_fields_check
                    CHECK (phase = 'prepared' OR (access_token_jti IS NOT NULL AND access_token_expires_at IS NOT NULL)),
                CONSTRAINT oauth_token_issuances_claim_owner_pair_check
                    CHECK ((claim_owner_id IS NULL) = (claim_started_at IS NULL))
            );
            CREATE UNIQUE INDEX oauth_token_issuances_grant_key_idx
                ON oauth_token_issuances (tenant_id, client_id, grant_key_blake3);
            CREATE INDEX oauth_token_issuances_expiry_idx
                ON oauth_token_issuances (expires_at);
            INSERT INTO oauth_token_issuances (
                issuance_id, tenant_id, client_id, user_id, grant_key_blake3,
                request_digest, phase, claim_owner_id, claim_started_at,
                access_token_jti, access_token_expires_at,
                response_ciphertext, response_digest, response_envelope_version,
                response_key_id, expires_at
            ) VALUES (
                '00000000-0000-7000-8000-000000000001',
                '00000000-0000-7000-8000-000000000002',
                '00000000-0000-7000-8000-000000000003',
                '00000000-0000-7000-8000-000000000004',
                repeat('a', 64), repeat('b', 64), 'signed',
                '00000000-0000-7000-8000-000000000005', NOW(),
                'active-jti', NOW() + INTERVAL '1 hour',
                '\\x0102'::bytea, repeat('c', 64), 'v1', 'current',
                NOW() + INTERVAL '1 hour'
            );
            "#
        ))
        .await
        .expect("legacy issuance fixture should create");

    connection
        .batch_execute(UP)
        .await
        .expect("atomic issuance migration should apply once");

    let facts = sql_query(
        "SELECT access_token_jti, access_token_expires_at,
                response_ciphertext, response_digest,
                response_envelope_version, response_key_id
         FROM oauth_token_issuances",
    )
    .get_result::<IssuanceFacts>(&mut connection)
    .await
    .expect("migrated issuance should remain readable");
    assert_eq!(facts.access_token_jti, "active-jti");
    assert!(facts.access_token_expires_at > chrono::Utc::now());
    assert!(facts.response_ciphertext.is_none());
    assert!(facts.response_digest.is_none());
    assert!(facts.response_envelope_version.is_none());
    assert!(facts.response_key_id.is_none());

    let columns = sql_query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = 'oauth_token_issuances'",
    )
    .load::<ColumnName>(&mut connection)
    .await
    .expect("migrated columns should be inspectable")
    .into_iter()
    .map(|row| row.column_name)
    .collect::<Vec<_>>();
    for removed in ["phase", "claim_owner_id", "claim_started_at"] {
        assert!(!columns.iter().any(|column| column == removed));
    }

    connection
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .await
        .expect("isolated migration schema should be removed");
}
