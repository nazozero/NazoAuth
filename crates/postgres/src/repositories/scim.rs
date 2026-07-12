use crate::{DbPool, convert::identity, rows::identity::UserRow, schema::users};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    SubjectClaims, TenantContext, UserId, ports::RepositoryError, scim::NormalizedScimUser,
};

#[derive(Clone)]
pub struct ScimRepository {
    pool: DbPool,
}
impl ScimRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn replace(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
    ) -> Result<SubjectClaims, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = connection
            .transaction::<UserRow, diesel::result::Error, _>(async move |connection| {
                diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                        .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
                        .filter(users::organization_id.eq(tenant.organization_id.as_uuid())),
                )
                .set((
                    users::username.eq(replacement.user_name),
                    users::email.eq(replacement.email),
                    users::is_active.eq(replacement.active),
                    users::display_name.eq(replacement.display_name),
                    users::given_name.eq(replacement.given_name),
                    users::family_name.eq(replacement.family_name),
                    users::updated_at.eq(now),
                ))
                .returning(UserRow::as_returning())
                .get_result(connection)
                .await
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        identity::subject_claims(row).map_err(|error| RepositoryError::Consistency(error.0))
    }
}
