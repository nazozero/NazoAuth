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

/// DC-04b: one UPDATE RETURNING is drained and validated inside the shared
/// Required-audit transaction. Domain conversion failure rolls back the update;
/// the domain client is returned only after the full transaction acknowledgement.
#[test]
fn replace_registration_validates_the_record_before_audited_commit() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/src/repositories/clients/mutation.rs"
    )).expect("client mutation source is readable");
    let body = source.split("pub async fn replace_registration(").nth(1)
        .and_then(|source| source.split("pub async fn rotate_credentials(").next())
        .expect("replace_registration remains present");
    let transaction = body.find(".transaction::<OAuthClient").expect("atomic owner remains present");
    let statement = body.find("UPDATE oauth_clients SET").expect("single update remains present");
    assert_eq!(body.matches("UPDATE oauth_clients SET").count(), 1);
    let drain = body.find(".load::<OAuthClientRecord>").expect("RETURNING is fully drained");
    let domain = body.find(".into_domain()").expect("returned record is validated");
    let audit = body.find("append_dynamic_registration_audit")
        .expect("audited update retains the Required owner");
    assert!(transaction < statement && statement < drain && drain < domain && domain < audit);
    assert!(body.contains("RETURNING") && body.contains("records.len() != 1"));
    let metadata = body.find("serde_json::json!").expect("metadata serialization remains present");
    let acquire = body.find("self.connection().await?").expect("single connection is acquired");
    assert!(metadata < acquire && acquire < transaction);
    assert_eq!(body.matches("self.connection().await?").count(), 1);
    assert!(body.contains("if result.is_ok()") && body.contains("guard.return_to_pool()"),
        "failed acknowledgements must discard the guarded connection");
}

use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use uuid::Uuid;
