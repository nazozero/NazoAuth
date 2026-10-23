use super::MfaRepository;
use crate::{get_conn, schema::user_mfa_remembered_devices};
use diesel::{
    ExpressionMethods, OptionalExtension, PgExpressionMethods, QueryDsl,
    dsl::{exists, now},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{TenantId, UserId, ports::RepositoryError};

impl MfaRepository {
    pub async fn remembered_device_valid(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: &str,
        user_agent_hash: Option<&str>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::select(exists(
            user_mfa_remembered_devices::table
                .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()))
                .filter(user_mfa_remembered_devices::token_hash.eq(token_hash))
                .filter(user_mfa_remembered_devices::expires_at.gt(at))
                .filter(
                    user_mfa_remembered_devices::user_agent_hash
                        .is_not_distinct_from(user_agent_hash),
                ),
        ))
        .get_result::<bool>(&mut connection)
        .await
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: uuid::Uuid,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        {
            let mut guard = crate::pool::DiscardOnDrop(Some(connection));
            let result = guard
                .connection()
                .transaction::<_, diesel::result::Error, _>(async move |connection| {
                    let generation = crate::schema::user_totp_credentials::table
                        .filter(
                            crate::schema::user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()),
                        )
                        .filter(crate::schema::user_totp_credentials::user_id.eq(user_id.as_uuid()))
                        .filter(crate::schema::user_totp_credentials::id.eq(credential_id))
                        .filter(crate::schema::user_totp_credentials::confirmed_at.is_not_null())
                        .for_key_share()
                        .select(crate::schema::user_totp_credentials::id)
                        .first::<uuid::Uuid>(connection)
                        .await
                        .optional()?;
                    if generation.is_none() {
                        return Ok(false);
                    }
                    diesel::delete(
                        user_mfa_remembered_devices::table
                            .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                            .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()))
                            .filter(user_mfa_remembered_devices::expires_at.le(now)),
                    )
                    .execute(connection)
                    .await?;
                    diesel::insert_into(user_mfa_remembered_devices::table)
                        .values((
                            user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()),
                            user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()),
                            user_mfa_remembered_devices::token_hash.eq(token_hash),
                            user_mfa_remembered_devices::user_agent_hash.eq(user_agent_hash),
                            user_mfa_remembered_devices::expires_at.eq(expires_at),
                        ))
                        .execute(connection)
                        .await?;
                    Ok(true)
                })
                .await;
            guard.return_to_pool();
            result
        }
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
}

impl nazo_identity::ports::RememberedMfaDevicePort for MfaRepository {
    fn is_valid<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.remembered_device_valid(tenant_id, user_id, token_hash, user_agent_hash, at)
                .await
        })
    }
}
