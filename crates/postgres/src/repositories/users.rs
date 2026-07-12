use crate::{
    DbPool,
    convert::identity,
    rows::identity::{AuthenticationIdentityRow, PrincipalRow, PublicAccountRow, SubjectClaimsRow},
    schema::users,
};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    AuthenticationIdentity, Principal, PublicAccount, SubjectClaims, TenantContext, TenantId,
    UserId,
    ports::{
        AdminUserUpdate, NewUser, ProfileUpdate, RepositoryError, UserPage, UserRepositoryPort,
    },
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
    pub async fn principal_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<Principal>, RepositoryError> {
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
            .select(PrincipalRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::principal_row)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(PublicAccountRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn principal_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<Principal>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(PrincipalRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::principal_row)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn active_subject_claims_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .select(SubjectClaimsRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::active_subject_claims)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn public_account_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::email.eq(email.trim()))
            .select(PublicAccountRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn authentication_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<AuthenticationIdentity>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::email.eq(email.trim()))
            .select(AuthenticationIdentityRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::authentication_identity)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn create(&self, new_user: NewUser) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::insert_into(users::table)
            .values((
                users::tenant_id.eq(new_user.tenant.tenant_id.as_uuid()),
                users::realm_id.eq(new_user.tenant.realm_id.as_uuid()),
                users::organization_id.eq(new_user.tenant.organization_id.as_uuid()),
                users::username.eq(new_user.username),
                users::email.eq(new_user.email),
                users::password_hash.eq(new_user.password_hash.into_persistence_value()),
                users::email_verified.eq(new_user.email_verified),
            ))
            .returning(PublicAccountRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn update_profile(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfileUpdate,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let profile = update.profile;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid())),
        )
        .set((
            users::display_name.eq(profile.display_name),
            users::given_name.eq(profile.given_name),
            users::family_name.eq(profile.family_name),
            users::middle_name.eq(profile.middle_name),
            users::nickname.eq(profile.nickname),
            users::profile_url.eq(profile.profile_url),
            users::website_url.eq(profile.website_url),
            users::gender.eq(profile.gender),
            users::birthdate.eq(profile.birthdate),
            users::zoneinfo.eq(profile.zoneinfo),
            users::locale.eq(profile.locale),
            users::address_formatted.eq(profile.address.formatted),
            users::address_street_address.eq(profile.address.street_address),
            users::address_locality.eq(profile.address.locality),
            users::address_region.eq(profile.address.region),
            users::address_postal_code.eq(profile.address.postal_code),
            users::address_country.eq(profile.address.country),
            users::phone_number.eq(profile.phone_number),
            users::phone_number_verified.eq(profile.phone_number_verified),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn update_avatar(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        avatar_url: Option<String>,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid())),
        )
        .set((
            users::avatar_url.eq(avatar_url),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn page(&self, limit: i64, offset: i64) -> Result<UserPage, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let total = users::table
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let rows = users::table
            .select(PublicAccountRow::as_select())
            .order(users::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<PublicAccountRow>(&mut connection)
            .await
            .map_err(map_error)?;
        let users = rows
            .into_iter()
            .map(PublicAccount::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))?;
        Ok(UserPage { total, users })
    }
    pub async fn admin_update(
        &self,
        user_id: UserId,
        update: AdminUserUpdate,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel_async::AsyncConnection::transaction::<_, AdminUpdateError, _>(
            &mut connection,
            async move |connection| {
                let current = users::table
                    .find(user_id.as_uuid())
                    .select(PublicAccountRow::as_select())
                    .for_update()
                    .first::<PublicAccountRow>(connection)
                    .await
                    .optional()?;
                let Some(current) = current else {
                    return Ok(None);
                };
                if update.role.is_none() && update.admin_level.is_none() && update.active.is_none()
                {
                    let user = PublicAccount::try_from(current)
                        .map_err(|error| AdminUpdateError::Consistency(error.0))?;
                    return Ok(Some(user));
                }
                let role = update.role.unwrap_or(current.role);
                let admin_level = update.admin_level.unwrap_or(current.admin_level);
                if !valid_role_admin_level(&role, admin_level) {
                    return Err(AdminUpdateError::Conflict);
                }
                let active = update.active.unwrap_or(current.is_active);
                let updated = diesel::update(users::table.find(user_id.as_uuid()))
                    .set((
                        users::role.eq(role),
                        users::admin_level.eq(admin_level),
                        users::is_active.eq(active),
                        users::updated_at.eq(diesel::dsl::now),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result::<PublicAccountRow>(connection)
                    .await?;
                let user = PublicAccount::try_from(updated)
                    .map_err(|error| AdminUpdateError::Consistency(error.0))?;
                Ok(Some(user))
            },
        )
        .await
        .map_err(|error| match error {
            AdminUpdateError::Diesel(error) => map_error(error),
            AdminUpdateError::Conflict => RepositoryError::Conflict,
            AdminUpdateError::Consistency(message) => RepositoryError::Consistency(message),
        })
    }
    pub async fn subject_claims_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
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
            .filter(users::is_active.eq(true))
            .select(SubjectClaimsRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::active_subject_claims)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
}

fn valid_role_admin_level(role: &str, admin_level: i32) -> bool {
    matches!((role, admin_level), ("user", 0) | ("admin", 1..))
}

enum AdminUpdateError {
    Diesel(diesel::result::Error),
    Conflict,
    Consistency(String),
}

impl From<diesel::result::Error> for AdminUpdateError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}
fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
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
