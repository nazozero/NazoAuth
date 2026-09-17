use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, get_conn, schema::oauth_tokens};

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
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                if let Some(family_id) = refresh_token_family_id {
                    lock_refresh_family(connection, family_id).await?;
                }
                if let Some(deadline) = revocation_deadline {
                    upsert_access_token_revocations(
                        connection,
                        &[NewAccessTokenRevocation {
                            id: Uuid::now_v7(),
                            access_token_jti_blake3: blake3_hex(access_token_jti),
                            client_id,
                            tenant_id,
                            revoked_at: Utc::now(),
                            expires_at: deadline,
                        }],
                    )
                    .await?;
                }
                if let Some(family_id) = refresh_token_family_id {
                    diesel::update(
                        oauth_tokens::table
                            .filter(oauth_tokens::tenant_id.eq(tenant_id))
                            .filter(oauth_tokens::client_id.eq(client_id))
                            .filter(oauth_tokens::token_family_id.eq(family_id))
                            .filter(oauth_tokens::revoked_at.is_null()),
                    )
                    .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await?;
                }
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
