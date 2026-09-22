use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, get_conn, schema::oauth_refresh_families};

use super::{
    access_token_revocation::{
        NewAccessTokenRevocation, access_token_revocation_deadline, upsert_access_token_revocations,
    },
    tokens::lock_refresh_family,
};

#[derive(Clone)]
pub struct AuthorizationRepository {
    pool: DbPool,
}

impl AuthorizationRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn revoke_issued_tokens(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> Result<(), RepositoryError> {
        // `access_token_expires_at` is the token's verified exp; the stored
        // fact keeps covering it through the maximum verifier clock skew.
        let revocation_deadline = access_token_expires_at
            .map(access_token_revocation_deadline)
            .transpose()?;
        let new_revocation = revocation_deadline.map(|deadline| NewAccessTokenRevocation {
            id: Uuid::now_v7(),
            access_token_jti_blake3: blake3_hex(access_token_jti),
            client_id,
            tenant_id,
            revoked_at: Utc::now(),
            expires_at: deadline,
        });
        let Some(family_id) = refresh_token_family_id else {
            // Without a refresh family there is no multi-statement fence: the
            // single upsert is already atomic, and an empty input is a no-op
            // that never touches the pool.
            let Some(new_revocation) = new_revocation else {
                return Ok(());
            };
            let mut connection = get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?;
            return upsert_access_token_revocations(&mut connection, &[new_revocation])
                .await
                .map(|_| ())
                .map_err(map_error);
        };
        // The revocation fact and the refresh-family invalidation must commit
        // atomically under the shared family lock.
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                lock_refresh_family(connection, family_id).await?;
                if let Some(new_revocation) = new_revocation {
                    upsert_access_token_revocations(connection, &[new_revocation]).await?;
                }
                diesel::update(
                    oauth_refresh_families::table
                        .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
                        .filter(oauth_refresh_families::client_id.eq(client_id))
                        .filter(oauth_refresh_families::token_family_id.eq(family_id))
                        .filter(oauth_refresh_families::revoked_at.is_null()),
                )
                .set(oauth_refresh_families::revoked_at.eq(diesel::dsl::now))
                .execute(connection)
                .await?;
                Ok(())
            })
            .await
            .map_err(map_error)
    }
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
