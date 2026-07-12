use crate::{
    DbPool, convert::identity, rows::identity::ExternalIdentityLinkRow,
    schema::external_identity_links,
};
use diesel::{
    ExpressionMethods, QueryDsl, SelectableHelper,
    result::{DatabaseErrorKind, Error},
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    TenantId, UserId,
    ports::{FederationLink, NewFederationLink, RepositoryError},
};

#[derive(Clone)]
pub struct FederationRepository {
    pool: DbPool,
}
impl FederationRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn insert(&self, link: NewFederationLink) -> Result<FederationLink, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::insert_into(external_identity_links::table)
            .values((
                external_identity_links::tenant_id.eq(link.tenant_id.as_uuid()),
                external_identity_links::user_id.eq(link.user_id.as_uuid()),
                external_identity_links::provider_type.eq(link.provider_type),
                external_identity_links::provider_id.eq(link.provider_id),
                external_identity_links::subject.eq(link.subject),
                external_identity_links::email.eq(link.email),
                external_identity_links::claims.eq(link.claims),
            ))
            .returning(ExternalIdentityLinkRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        identity::federation_link(row).map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<FederationLink>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        external_identity_links::table
            .filter(external_identity_links::tenant_id.eq(tenant_id.as_uuid()))
            .filter(external_identity_links::user_id.eq(user_id.as_uuid()))
            .select(ExternalIdentityLinkRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::federation_link)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
}
fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
