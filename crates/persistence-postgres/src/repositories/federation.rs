use crate::{
    DbPool,
    convert::identity,
    get_conn,
    rows::identity::{ExternalIdentityLinkRow, ExternalIdentityLinkSummaryRow, PublicAccountRow},
    schema::{external_identity_links, users},
};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl,
    SelectableHelper,
    result::{DatabaseErrorKind, Error},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    PublicAccount, TenantId, UserId,
    ports::{
        FederationLink, FederationLinkSummary, FederationLogin, NewFederatedIdentity,
        NewFederationLink, RepositoryError,
    },
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
        let mut connection = get_conn(&self.pool)
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
    pub async fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<FederationLinkSummary>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        external_identity_links::table
            .filter(external_identity_links::tenant_id.eq(tenant_id.as_uuid()))
            .filter(external_identity_links::user_id.eq(user_id.as_uuid()))
            .select(ExternalIdentityLinkSummaryRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::federation_link_summary)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        link_id: uuid::Uuid,
    ) -> Result<Option<FederationLinkSummary>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::delete(
            external_identity_links::table
                .find(link_id)
                .filter(external_identity_links::tenant_id.eq(tenant_id.as_uuid()))
                .filter(external_identity_links::user_id.eq(user_id.as_uuid())),
        )
        .returning(ExternalIdentityLinkSummaryRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(identity::federation_link_summary)
        .transpose()
        .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn resolve_existing(
        &self,
        login: &FederationLogin,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let link = external_identity_links::table
                    .inner_join(
                        users::table.on(users::id
                            .eq(external_identity_links::user_id)
                            .and(users::tenant_id.eq(external_identity_links::tenant_id))),
                    )
                    .filter(external_identity_links::tenant_id.eq(login.tenant.tenant_id.as_uuid()))
                    .filter(external_identity_links::provider_type.eq(&login.provider_type))
                    .filter(external_identity_links::provider_id.eq(&login.provider_id))
                    .filter(external_identity_links::subject.eq(&login.subject))
                    .select((
                        external_identity_links::id,
                        external_identity_links::email,
                        PublicAccountRow::as_select(),
                    ))
                    .first::<(uuid::Uuid, String, PublicAccountRow)>(connection)
                    .await
                    .optional()?;
                let Some((link_id, previous_email, user)) = link else {
                    return Ok(None);
                };
                let email = login.email.as_deref().unwrap_or(&previous_email);
                diesel::update(external_identity_links::table.find(link_id))
                    .set((
                        external_identity_links::email.eq(email),
                        external_identity_links::claims.eq(&login.claims),
                        external_identity_links::last_login_at.eq(diesel::dsl::now),
                        external_identity_links::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(connection)
                    .await?;
                Ok(Some(user))
            })
            .await
            .map_err(map_error)?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn create_federated(
        &self,
        new_identity: NewFederatedIdentity,
    ) -> Result<PublicAccount, RepositoryError> {
        let NewFederatedIdentity {
            login,
            email,
            display_name,
            password_hash,
        } = new_identity;
        let borrowed_login = &login;
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let result = connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let tenant = borrowed_login.tenant;
                let user = diesel::insert_into(users::table)
                    .values((
                        users::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        users::realm_id.eq(tenant.realm_id.as_uuid()),
                        users::organization_id.eq(tenant.organization_id.as_uuid()),
                        users::username.eq(&email),
                        users::email.eq(&email),
                        users::password_hash.eq(password_hash.into_persistence_value()),
                        users::email_verified.eq(true),
                        users::display_name.eq(display_name),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result::<PublicAccountRow>(connection)
                    .await?;
                diesel::insert_into(external_identity_links::table)
                    .values((
                        external_identity_links::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        external_identity_links::user_id.eq(user.id),
                        external_identity_links::provider_type.eq(&borrowed_login.provider_type),
                        external_identity_links::provider_id.eq(&borrowed_login.provider_id),
                        external_identity_links::subject.eq(&borrowed_login.subject),
                        external_identity_links::email.eq(email),
                        external_identity_links::claims.eq(&borrowed_login.claims),
                        external_identity_links::last_login_at.eq(diesel::dsl::now),
                    ))
                    .execute(connection)
                    .await?;
                Ok(user)
            })
            .await;
        // Conflict recovery borrows from this pool again after the transaction has ended.
        drop(connection);
        match result {
            Ok(row) => row
                .try_into()
                .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0)),
            Err(Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => self
                .resolve_existing(&login)
                .await?
                .ok_or(RepositoryError::Conflict),
            Err(error) => Err(map_error(error)),
        }
    }
}

impl nazo_identity::ports::FederationLinkRepositoryPort for FederationRepository {
    fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<FederationLinkSummary>> {
        Box::pin(
            async move { FederationRepository::list_summaries(self, tenant_id, user_id).await },
        )
    }

    fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        link_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<FederationLinkSummary>> {
        Box::pin(
            async move { FederationRepository::delete(self, tenant_id, user_id, link_id).await },
        )
    }
}

impl nazo_identity::ports::FederationLoginRepositoryPort for FederationRepository {
    fn resolve_existing<'a>(
        &'a self,
        login: &'a FederationLogin,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move { FederationRepository::resolve_existing(self, login).await })
    }

    fn email_exists<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            super::UserRepository::new(self.pool.clone())
                .email_exists(tenant_id, email)
                .await
        })
    }

    fn create_federated(
        &self,
        identity: NewFederatedIdentity,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move { FederationRepository::create_federated(self, identity).await })
    }
}
fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
