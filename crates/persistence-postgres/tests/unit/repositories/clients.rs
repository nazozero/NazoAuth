use super::mapping::string_array;
use super::*;
use nazo_identity::ports::RepositoryError;
use serde_json::Value;

#[test]
fn persisted_client_string_arrays_reject_non_array_json() {
    assert!(
        string_array(
            Value::String("authorization_code".to_owned()),
            "grant_types"
        )
        .is_err()
    );
}

#[test]
fn missing_client_rows_preserve_not_found_semantics() {
    assert_eq!(
        map_error(diesel::result::Error::NotFound),
        RepositoryError::NotFound
    );
}

fn dc04_database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() {
        assert!(std::env::var_os("CI").is_none(), "CI requires PostgreSQL");
    }
    url
}

/// Inserts the minimum constraint-satisfying client row and returns its id.
async fn insert_dc04_client(connection: &mut diesel_async::AsyncPgConnection, client_id: Uuid) {
    sql_query(
        "INSERT INTO oauth_clients (
            id, client_id, client_name, client_type, redirect_uris, scopes,
            grant_types, token_endpoint_auth_method, security_policy
         ) VALUES (
            $1, $2, 'DC-04 unit client', 'confidential',
            '[\"https://client.example/cb\"]'::jsonb, '[\"openid\"]'::jsonb,
            '[\"authorization_code\"]'::jsonb, 'client_secret_basic', $3
         )",
    )
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Text, _>(format!("dc04-unit-{}", Uuid::now_v7()))
    .bind::<sql_types::Jsonb, _>(serde_json::json!(nazo_auth::ClientSecurityPolicy::default()))
    .execute(connection)
    .await
    .unwrap();
}

async fn delete_dc04_client(connection: &mut diesel_async::AsyncPgConnection, client_id: Uuid) {
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<sql_types::Uuid, _>(client_id)
        .execute(connection)
        .await
        .unwrap();
}

/// DC-04a: `OAuthClientRecord` derives `QueryableByName` so the
/// `UPDATE ... RETURNING` decode fails closed on a malformed row — the diesel
/// error propagates to the caller instead of yielding a partial record.
#[tokio::test]
async fn oauth_client_record_queryable_by_name_rejects_malformed_rows() {
    let Some(url) = dc04_database_url() else {
        return;
    };
    let mut connection = diesel_async::AsyncPgConnection::establish(&url)
        .await
        .unwrap();

    // A wrong-typed `id` column fails the very first named-field decode.
    let error = sql_query("SELECT 'not-a-uuid'::text AS id")
        .get_result::<OAuthClientRecord>(&mut connection)
        .await
        .unwrap_err();
    assert!(
        matches!(error, diesel::result::Error::DeserializationError(_)),
        "a mistyped record column must fail decode, got {error:?}"
    );

    // A projection missing the record's named columns also fails closed
    // (never `NotFound`: one malformed row was returned).
    let error = sql_query("SELECT '00000000-0000-7000-8000-000000000001'::uuid AS id")
        .get_result::<OAuthClientRecord>(&mut connection)
        .await
        .unwrap_err();
    assert!(
        !matches!(error, diesel::result::Error::NotFound),
        "a missing record column must fail decode, got {error:?}"
    );
}

/// DC-04b: `into_domain` is the post-statement validation stage — a row can
/// decode cleanly into `OAuthClientRecord` yet still be rejected by the
/// domain conversion (here: a JSONB array column holding non-strings passes
/// the table CHECK and the `Value` decode, but fails `string_array`). Through
/// `replace_registration` itself this state is unreachable — the statement
/// rewrites every validated column from an already-domain `OAuthClient` — so
/// the boundary is exercised at the record level and confirmed by inspection
/// in the companion source test below.
#[tokio::test]
async fn oauth_client_record_into_domain_validates_json_columns_after_decode() {
    let Some(url) = dc04_database_url() else {
        return;
    };
    let mut connection = diesel_async::AsyncPgConnection::establish(&url)
        .await
        .unwrap();
    let client_id = Uuid::now_v7();
    insert_dc04_client(&mut connection, client_id).await;
    sql_query("UPDATE oauth_clients SET scopes = '[1, \"openid\"]'::jsonb WHERE id = $1")
        .bind::<sql_types::Uuid, _>(client_id)
        .execute(&mut connection)
        .await
        .unwrap();

    // Stage one (mirrors the RETURNING decode) still succeeds.
    let record = sql_query("SELECT * FROM oauth_clients WHERE id = $1")
        .bind::<sql_types::Uuid, _>(client_id)
        .get_result::<OAuthClientRecord>(&mut connection)
        .await
        .expect("a JSONB array of non-strings still decodes into the record");
    // Stage two (post-commit) fails closed on the domain-invalid column.
    let error = record.into_domain().unwrap_err();
    assert!(
        matches!(error, RepositoryError::Unexpected(ref message) if message.contains("scopes")),
        "into_domain must reject a non-string array column, got {error:?}"
    );
    delete_dc04_client(&mut connection, client_id).await;
}

/// DC-04b: `replace_registration` runs exactly one `UPDATE ... RETURNING`
/// statement — a single statement is already atomic, so no transaction wraps
/// it — and converts the decoded record to the domain client only after the
/// statement resolves, so a conversion error can neither resurrect a rejected
/// update nor hide a committed one.
#[test]
fn replace_registration_converts_the_record_after_commit() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/repositories/clients/mutation.rs"
    ))
    .expect("client mutation source is readable");
    let body = source
        .split("pub async fn replace_registration(")
        .nth(1)
        .and_then(|source| source.split("pub async fn rotate_credentials(").next())
        .expect("replace_registration remains present");

    assert!(
        !body.contains(".transaction"),
        "a single UPDATE ... RETURNING needs no explicit transaction"
    );
    let statement = body
        .find("UPDATE oauth_clients SET")
        .expect("the single update statement is present");
    let domain = body
        .rfind("record.into_domain()")
        .expect("the returned record converts to the domain client");
    assert!(
        statement < domain,
        "into_domain must run after the statement returns, not before"
    );
    assert!(
        body.contains("RETURNING") && body.contains("get_result::<OAuthClientRecord>"),
        "the statement decodes the returned row into the record type"
    );
    let metadata = body
        .find("serde_json::json!")
        .expect("metadata is serialized before the statement runs");
    let acquire = body
        .find("self.connection().await?")
        .expect("the connection is acquired for the statement");
    assert!(
        metadata < acquire && acquire < statement,
        "metadata is constructed before the pooled connection is acquired"
    );
}

use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use uuid::Uuid;
