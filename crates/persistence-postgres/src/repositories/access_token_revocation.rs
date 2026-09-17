use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, query_dsl::methods::FilterDsl, upsert::excluded};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_resource_server::MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS;
use uuid::Uuid;

use crate::schema::access_token_revocations;

/// A persisted revocation fact. `expires_at` is the retention deadline:
/// the revoked token's verified `exp` plus the maximum verifier clock skew.
#[derive(diesel::Insertable)]
#[diesel(table_name = access_token_revocations)]
pub(super) struct NewAccessTokenRevocation {
    pub id: Uuid,
    pub access_token_jti_blake3: String,
    pub client_id: Uuid,
    pub tenant_id: Uuid,
    pub revoked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Converts a verified access-token `exp` into the revocation-fact retention
/// deadline covering the verifier's maximum acceptance window.
pub(super) fn access_token_revocation_deadline(
    expires_at: DateTime<Utc>,
) -> Result<DateTime<Utc>, RepositoryError> {
    expires_at
        .checked_add_signed(chrono::Duration::seconds(
            MAX_ACCESS_TOKEN_CLOCK_SKEW_SECONDS,
        ))
        .ok_or_else(|| {
            RepositoryError::Consistency(
                "access-token revocation deadline is not representable".to_owned(),
            )
        })
}

/// Inserts revocation facts on a caller-owned connection. A conflict on the
/// `(tenant_id, access_token_jti_blake3)` authority key only extends the
/// stored deadline toward the later value; identity, ownership, and the first
/// `revoked_at` are never rewritten. Returns the number of rows inserted or
/// actually extended.
pub(super) async fn upsert_access_token_revocations(
    connection: &mut AsyncPgConnection,
    revocations: &[NewAccessTokenRevocation],
) -> diesel::QueryResult<usize> {
    if revocations.is_empty() {
        return Ok(0);
    }
    diesel::insert_into(access_token_revocations::table)
        .values(revocations)
        .on_conflict((
            access_token_revocations::tenant_id,
            access_token_revocations::access_token_jti_blake3,
        ))
        .do_update()
        .set(access_token_revocations::expires_at.eq(diesel::dsl::sql::<
            diesel::sql_types::Timestamptz,
        >(
            "GREATEST(access_token_revocations.expires_at, EXCLUDED.expires_at)",
        )))
        .filter(
            access_token_revocations::expires_at.lt(excluded(access_token_revocations::expires_at)),
        )
        .execute(connection)
        .await
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/access_token_revocation.rs"]
mod tests;
