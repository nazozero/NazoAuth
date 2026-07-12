use crate::{
    DbPool,
    schema::{user_mfa_backup_codes, user_mfa_remembered_devices, user_totp_credentials, users},
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    TenantId, UserId,
    ports::{MfaRepositoryPort, RepositoryError, RepositoryFuture, TotpCredential},
};

#[derive(Clone)]
pub struct MfaRepository {
    pool: DbPool,
}
impl MfaRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn totp_credential(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<TotpCredential>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_totp_credentials::table
            .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
            .filter(user_totp_credentials::confirmed_at.is_not_null())
            .select((
                user_totp_credentials::secret_base32,
                user_totp_credentials::last_used_step,
            ))
            .first::<(String, Option<i64>)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(|(secret_base32, last_used_step)| TotpCredential {
                    secret_base32,
                    last_used_step,
                })
            })
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn compare_and_set_totp_step(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let changed = diesel::update(
            user_totp_credentials::table
                .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                .filter(user_totp_credentials::confirmed_at.is_not_null())
                .filter(
                    user_totp_credentials::last_used_step
                        .is_null()
                        .or(user_totp_credentials::last_used_step.lt(step)),
                ),
        )
        .set((
            user_totp_credentials::last_used_step.eq(step),
            user_totp_credentials::updated_at.eq(now),
        ))
        .execute(&mut connection)
        .await
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        Ok(changed == 1)
    }
    pub async fn consume_backup_code(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        normalized_code: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let candidates = user_mfa_backup_codes::table
            .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid()))
            .filter(user_mfa_backup_codes::used_at.is_null())
            .select((user_mfa_backup_codes::id, user_mfa_backup_codes::code_hash))
            .limit(25)
            .load::<(uuid::Uuid, String)>(&mut connection)
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        let Some((id, _)) = candidates.into_iter().find(|(_, hash)| {
            PasswordHash::new(hash).ok().is_some_and(|parsed| {
                Argon2::default()
                    .verify_password(normalized_code.as_bytes(), &parsed)
                    .is_ok()
            })
        }) else {
            return Ok(false);
        };
        let changed = diesel::update(
            user_mfa_backup_codes::table
                .find(id)
                .filter(user_mfa_backup_codes::used_at.is_null()),
        )
        .set(user_mfa_backup_codes::used_at.eq(now))
        .execute(&mut connection)
        .await
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        Ok(changed == 1)
    }
    pub async fn replace_backup_code_hashes(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<String>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                for hash in hashes {
                    diesel::insert_into(user_mfa_backup_codes::table)
                        .values((
                            user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()),
                            user_mfa_backup_codes::user_id.eq(user_id.as_uuid()),
                            user_mfa_backup_codes::code_hash.eq(hash),
                        ))
                        .execute(connection)
                        .await?;
                }
                Ok(())
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn clear_mfa_state(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::delete(
                    user_mfa_remembered_devices::table
                        .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::delete(
                    user_totp_credentials::table
                        .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_totp_credentials::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant_id.as_uuid())),
                )
                .set((users::mfa_enabled.eq(false), users::updated_at.eq(now)))
                .execute(connection)
                .await?;
                Ok(())
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
}
impl MfaRepositoryPort for MfaRepository {
    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>> {
        Box::pin(async move { self.totp_credential(tenant_id, user_id).await })
    }
    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.compare_and_set_totp_step(tenant_id, user_id, step)
                .await
        })
    }
    fn consume_backup_code<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        normalized_code: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.consume_backup_code(tenant_id, user_id, normalized_code)
                .await
        })
    }
    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<String>,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.replace_backup_code_hashes(tenant_id, user_id, hashes)
                .await
        })
    }
    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move { self.clear_mfa_state(tenant_id, user_id).await })
    }
}
