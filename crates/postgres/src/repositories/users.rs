use crate::{DbPool, convert::identity, rows::identity::UserRow, schema::users};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    Principal, SubjectClaims, TenantContext, UserId,
    ports::{RepositoryError, UserRepositoryPort},
};

#[derive(Clone)]
pub struct UserRepository {
    pool: DbPool,
}
impl UserRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    async fn row_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<UserRow>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
            .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
            .filter(users::organization_id.eq(tenant.organization_id.as_uuid()))
            .select(UserRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn principal_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<Principal>, RepositoryError> {
        self.row_by_id(tenant, user_id)
            .await?
            .map(Principal::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn subject_claims_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
        self.row_by_id(tenant, user_id)
            .await?
            .map(identity::subject_claims)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
}
impl UserRepositoryPort for UserRepository {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<Principal>> {
        Box::pin(async move { self.principal_by_id(tenant, user_id).await })
    }
    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<SubjectClaims>> {
        Box::pin(async move { self.subject_claims_by_id(tenant, user_id).await })
    }
}
