use crate::{
    DbPool, convert::identity, rows::identity::PasskeyCredentialRow,
    schema::user_passkey_credentials,
};
use diesel::{
    ExpressionMethods, QueryDsl, SelectableHelper,
    dsl::now,
    result::{DatabaseErrorKind, Error},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    TenantId, UserId,
    ports::{PasskeyCredential, RepositoryError},
};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub struct PasskeyRepository {
    pool: DbPool,
}
impl PasskeyRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<PasskeyCredential>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_passkey_credentials::table
            .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
            .select(PasskeyCredentialRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::passkey)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: String,
        credential: Value,
        label: String,
        sign_count: i64,
    ) -> Result<PasskeyCredential, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::insert_into(user_passkey_credentials::table)
            .values((
                user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()),
                user_passkey_credentials::user_id.eq(user_id.as_uuid()),
                user_passkey_credentials::credential_id.eq(credential_id),
                user_passkey_credentials::credential.eq(credential),
                user_passkey_credentials::label.eq(label),
                user_passkey_credentials::sign_count.eq(sign_count),
            ))
            .returning(PasskeyCredentialRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        identity::passkey(row).map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn update_counter(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::update(
            user_passkey_credentials::table
                .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid()))
                .filter(user_passkey_credentials::credential_id.eq(credential_id)),
        )
        .set((
            user_passkey_credentials::sign_count.eq(sign_count),
            user_passkey_credentials::last_used_at.eq(now),
            user_passkey_credentials::updated_at.eq(now),
        ))
        .execute(&mut connection)
        .await
        .map(|count| count == 1)
        .map_err(map_error)
    }
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::delete(
            user_passkey_credentials::table
                .find(id)
                .filter(user_passkey_credentials::tenant_id.eq(tenant_id.as_uuid()))
                .filter(user_passkey_credentials::user_id.eq(user_id.as_uuid())),
        )
        .execute(&mut connection)
        .await
        .map(|count| count == 1)
        .map_err(map_error)
    }
}
fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
