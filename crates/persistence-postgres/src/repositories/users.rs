use crate::{
    DbPool,
    convert::identity,
    get_conn,
    repositories::{
        audit::insert_identity_security_event,
        audit_ledger::append_fresh_security_audit_on_connection,
    },
    rows::identity::{AuthenticationIdentityRow, PrincipalRow, PublicAccountRow, SubjectClaimsRow},
    schema::{oauth_refresh_families, oauth_subject_bindings, user_client_grants, users},
};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, PgExpressionMethods, QueryDsl,
    SelectableHelper, sql_query, sql_types,
};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use nazo_identity::{
    AdminPolicyError, AdminUserUpdateOutcome, AuthenticationIdentity, IdentitySecurityEvent,
    IdentitySecurityEventType, IdentitySecurityOutcome, IdentitySecurityReason, Principal,
    PublicAccount, SubjectClaims, TenantContext, TenantId, UserId, authorize_admin_update,
    ports::{
        AdminUserUpdate, NewUser, ProfileUpdate, RepositoryError, UserPage, UserRepositoryPort,
    },
};
use uuid::Uuid;

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
        let mut connection = get_conn(&self.pool)
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
        let mut connection = get_conn(&self.pool)
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
        let mut connection = get_conn(&self.pool)
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
        token_subject: &str,
    ) -> Result<Option<(SubjectClaims, i64, bool)>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        // Claims, their epoch and private-subject ownership must share one
        // snapshot. Do not filter by owner: a different owner is a collision,
        // not a missing binding. Public subjects need no binding lookup.
        let private_subject = token_subject != user_id.as_uuid().to_string();
        let bound_user = oauth_subject_bindings::table
            .filter(oauth_subject_bindings::tenant_id.eq(tenant_id.as_uuid()))
            .filter(
                oauth_subject_bindings::subject
                    .eq(token_subject)
                    .and::<_, sql_types::Bool>(private_subject),
            )
            .select(oauth_subject_bindings::user_id)
            .single_value();
        let snapshot = users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .select((
                SubjectClaimsRow::as_select(),
                users::access_token_epoch,
                bound_user,
            ))
            .first::<(SubjectClaimsRow, i64, Option<Uuid>)>(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        drop(connection);
        snapshot
            .map(|(row, epoch, bound_user)| {
                prepare_subject_claims(row, epoch, bound_user)
            })
            .transpose()
    }

    /// Narrow active-principal read: same tenant, same user, `is_active`, and
    /// only the seven principal columns. Deliberately not the count-only
    /// `is_active_by_tenant_id` — the principal conversion still fails closed
    /// on corrupt identity data instead of reporting a live subject.
    pub async fn active_subject_id_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .select(PrincipalRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(|row| identity::principal_row(row).map(|principal| principal.user_id.as_uuid()))
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn is_active_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let count = users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        Ok(count == 1)
    }

    pub async fn public_account_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
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
        let mut connection = get_conn(&self.pool)
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
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Self::create_on_connection(&mut connection, new_user).await
    }

    pub async fn create_with_required_audit(
        &self,
        new_user: NewUser,
        actor_id: UserId,
        source_ip_hash: String,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut guard = crate::pool::DiscardOnDrop(Some(
            get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?,
        ));
        let result = diesel_async::AsyncConnection::transaction::<_, AdminAuthorizedUpdateError, _>(
            guard.connection(), async move |connection| {
                let tenant = new_user.tenant;
                let principals = users::table
                    .filter(users::id.eq(actor_id.as_uuid()))
                    .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                    .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
                    .filter(users::organization_id.eq(tenant.organization_id.as_uuid()))
                    .select(PrincipalRow::as_select()).for_update()
                    .load::<PrincipalRow>(connection).await?
                    .into_iter().map(identity::principal_row)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                if !principals.iter().any(|actor| actor.active
                    && actor.admin_level().is_some_and(|level| level > 0)) {
                    return Err(AdminAuthorizedUpdateError::Consistency(
                        "admin user creation actor is no longer authorized in the target context".to_owned()));
                }
                let written = Self::create_on_connection(connection, new_user).await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                append_admin_user_audit(connection, "admin_user_created", &written, actor_id, &source_ip_hash).await?;
                Ok(written)
            },
        ).await.map_err(AdminAuthorizedUpdateError::into_repository);
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }

    async fn create_on_connection(
        connection: &mut AsyncPgConnection,
        new_user: NewUser,
    ) -> Result<PublicAccount, RepositoryError> {
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
            .load::<PublicAccountRow>(connection)
            .await
            .map_err(map_error)?;
        let mut rows = row;
        if rows.len() != 1 {
            return Err(RepositoryError::Consistency(
                "user insert did not return exactly one complete account".to_owned(),
            ));
        }
        rows.pop()
            .expect("one completely received account")
            .try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn update_profile(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfileUpdate,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let profile = update.profile;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid()))
                .filter(users::is_active.eq(true)),
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
            users::phone_number.eq(profile.phone_number.as_deref()),
            users::phone_number_verified.eq(users::phone_number_verified
                .and(users::phone_number.is_not_distinct_from(profile.phone_number.as_deref()))),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .ok_or(RepositoryError::NotFound)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn compare_and_set_avatar(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&str>,
        avatar_url: Option<String>,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid()))
                .filter(users::avatar_url.is_not_distinct_from(expected_avatar_url)),
        )
        .set((
            users::avatar_url.eq(avatar_url),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?;
        row.map(PublicAccount::try_from)
            .transpose()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn page(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<UserPage, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let total = users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let rows = users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
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
    pub async fn admin_update_authorized(
        &self,
        tenant_id: TenantId,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        self.admin_update_owned(tenant_id, actor_id, target_id, update, None)
            .await
    }

    pub async fn admin_update_with_required_audit(
        &self,
        tenant: TenantContext,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        source_ip_hash: String,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        self.admin_update_owned(
            tenant.tenant_id,
            actor_id,
            target_id,
            update,
            Some((tenant, source_ip_hash)),
        )
        .await
    }

    async fn admin_update_owned(
        &self,
        tenant_id: TenantId,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        required_audit: Option<(TenantContext, String)>,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        let mut guard = crate::pool::DiscardOnDrop(Some(
            get_conn(&self.pool)
                .await
                .map_err(|_| RepositoryError::Unavailable)?,
        ));
        let result =
            diesel_async::AsyncConnection::transaction::<_, AdminAuthorizedUpdateError, _>(
                guard.connection(),
                async move |connection| {
                    // A stable lock order prevents two concurrent hierarchy updates from
                    // deadlocking when their actor and target are reversed.
                    let accounts = users::table
                        .filter(users::id.eq_any([actor_id.as_uuid(), target_id.as_uuid()]))
                        .order(users::id.asc())
                        .select(PublicAccountRow::as_select())
                        .for_update()
                        .load::<PublicAccountRow>(connection)
                        .await?;
                    let mut accounts = accounts
                        .into_iter()
                        .map(PublicAccount::try_from)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                    let actor = accounts
                        .iter()
                        .find(|account| account.id() == actor_id.as_uuid())
                        .cloned();
                    let target = accounts
                        .iter_mut()
                        .find(|account| account.id() == target_id.as_uuid())
                        .cloned();
                    let Some(actor) = actor.filter(|actor| {
                        actor.tenant().tenant_id == tenant_id
                            && required_audit
                                .as_ref()
                                .is_none_or(|(tenant, _)| actor.tenant() == *tenant)
                    }) else {
                        insert_identity_security_event(
                            connection,
                            &admin_event(
                                tenant_id,
                                None,
                                None,
                                IdentitySecurityOutcome::Denied,
                                IdentitySecurityReason::ActorNotAuthorized,
                            ),
                        )
                        .await
                        .map_err(AdminAuthorizedUpdateError::Repository)?;
                        return Ok(AdminUserUpdateOutcome::Denied(
                            AdminPolicyError::ActorNotAuthorized,
                        ));
                    };
                    let Some(target) = target else {
                        insert_identity_security_event(
                            connection,
                            &admin_event(
                                tenant_id,
                                Some(actor_id),
                                None,
                                IdentitySecurityOutcome::Denied,
                                IdentitySecurityReason::TargetNotFound,
                            ),
                        )
                        .await
                        .map_err(AdminAuthorizedUpdateError::Repository)?;
                        return Ok(AdminUserUpdateOutcome::TargetNotFound);
                    };
                    let decision = if required_audit
                        .as_ref()
                        .is_some_and(|(tenant, _)| target.tenant() != *tenant)
                    {
                        Err(AdminPolicyError::CrossTenant)
                    } else {
                        authorize_admin_update(&actor.principal, &target.principal, &update)
                    };
                    let resolved = match decision {
                        Ok(resolved) => resolved,
                        Err(reason) => {
                            let same_tenant = target.tenant().tenant_id == tenant_id;
                            insert_identity_security_event(
                                connection,
                                &admin_event(
                                    tenant_id,
                                    Some(actor_id),
                                    same_tenant.then_some(target_id),
                                    IdentitySecurityOutcome::Denied,
                                    admin_denial_reason(reason),
                                ),
                            )
                            .await
                            .map_err(AdminAuthorizedUpdateError::Repository)?;
                            return Ok(AdminUserUpdateOutcome::Denied(reason));
                        }
                    };
                    if update.role.is_none()
                        && update.admin_level.is_none()
                        && update.active.is_none()
                    {
                        insert_identity_security_event(
                            connection,
                            &admin_event(
                                tenant_id,
                                Some(actor_id),
                                Some(target_id),
                                IdentitySecurityOutcome::Success,
                                IdentitySecurityReason::AdminUpdated,
                            ),
                        )
                        .await
                        .map_err(AdminAuthorizedUpdateError::Repository)?;
                        if let Some((_, source_ip_hash)) = &required_audit {
                            append_admin_user_audit(
                                connection,
                                "admin_user_updated",
                                &target,
                                actor_id,
                                source_ip_hash,
                            )
                            .await?;
                        }
                        return Ok(AdminUserUpdateOutcome::Updated(Box::new(target)));
                    }
                    let updated = diesel::update(users::table.find(target_id.as_uuid()))
                        .set((
                            users::role.eq(resolved.role),
                            users::admin_level.eq(resolved.admin_level),
                            users::is_active.eq(resolved.active),
                            users::updated_at.eq(diesel::dsl::now),
                        ))
                        .returning(PublicAccountRow::as_returning())
                        .load::<PublicAccountRow>(connection)
                        .await?;
                    let mut updated = updated;
                    if updated.len() != 1 {
                        return Err(AdminAuthorizedUpdateError::Consistency(
                            "admin update did not return exactly one complete account".to_owned(),
                        ));
                    }
                    let updated = updated
                        .pop()
                        .expect("one completely received updated account");
                    insert_identity_security_event(
                        connection,
                        &admin_event(
                            tenant_id,
                            Some(actor_id),
                            Some(target_id),
                            IdentitySecurityOutcome::Success,
                            IdentitySecurityReason::AdminUpdated,
                        ),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    let updated = PublicAccount::try_from(updated)
                        .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                    if let Some((_, source_ip_hash)) = &required_audit {
                        append_admin_user_audit(
                            connection,
                            "admin_user_updated",
                            &updated,
                            actor_id,
                            source_ip_hash,
                        )
                        .await?;
                    }
                    Ok(AdminUserUpdateOutcome::Updated(Box::new(updated)))
                },
            )
            .await
            .map_err(AdminAuthorizedUpdateError::into_repository);
        if result.is_ok() {
            guard.return_to_pool();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_tenant_admin_authorized(
        &self,
        control_tenant_id: TenantId,
        actor_id: UserId,
        target_tenant_id: TenantId,
        target_id: UserId,
        admin_level: i32,
        source_ip_hash: String,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        if admin_level < 0 || control_tenant_id == target_tenant_id {
            return Ok(AdminUserUpdateOutcome::Denied(
                AdminPolicyError::InvalidRoleLevel,
            ));
        }
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel_async::AsyncConnection::transaction::<_, AdminAuthorizedUpdateError, _>(
            &mut connection,
            async move |connection| {
                let accounts = users::table
                    .filter(users::id.eq_any([actor_id.as_uuid(), target_id.as_uuid()]))
                    .order(users::id.asc())
                    .select(PublicAccountRow::as_select())
                    .for_update()
                    .load::<PublicAccountRow>(connection)
                    .await?
                    .into_iter()
                    .map(PublicAccount::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                let actor = accounts
                    .iter()
                    .find(|account| account.id() == actor_id.as_uuid());
                let authorized = actor.is_some_and(|actor| {
                    actor.tenant().tenant_id == control_tenant_id
                        && actor.principal.active
                        && actor
                            .principal
                            .admin_level()
                            .is_some_and(|level| level >= 2)
                });
                let (outcome, reason) = if !authorized {
                    let persisted_actor = actor
                        .filter(|account| account.tenant().tenant_id == control_tenant_id)
                        .map(|_| actor_id);
                    insert_identity_security_event(
                        connection,
                        &admin_event(
                            control_tenant_id,
                            persisted_actor,
                            None,
                            IdentitySecurityOutcome::Denied,
                            IdentitySecurityReason::ActorNotAuthorized,
                        ),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    (AdminUserUpdateOutcome::Denied(AdminPolicyError::ActorNotAuthorized), "actor_not_authorized")
                } else if let Some(target) = accounts.iter().find(|account| {
                    account.id() == target_id.as_uuid()
                        && account.tenant().tenant_id == target_tenant_id
                }) {
                    let (role, level) = if admin_level == 0 { ("user", 0) } else { ("admin", admin_level) };
                    let updated = diesel::update(
                        users::table
                            .filter(users::id.eq(target.id()))
                            .filter(users::tenant_id.eq(target_tenant_id.as_uuid())),
                    )
                    .set((users::role.eq(role), users::admin_level.eq(level), users::updated_at.eq(diesel::dsl::now)))
                    .returning(PublicAccountRow::as_returning())
                    .get_result::<PublicAccountRow>(connection)
                    .await?;
                    // Identity events are tenant-local. Cross-tenant actor
                    // attribution belongs to the atomic security ledger below.
                    insert_identity_security_event(
                        connection,
                        &admin_event(target_tenant_id, None, Some(target_id), IdentitySecurityOutcome::Success, IdentitySecurityReason::AdminUpdated),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    (AdminUserUpdateOutcome::Updated(Box::new(
                        PublicAccount::try_from(updated).map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?,
                    )), "admin_updated")
                } else {
                    insert_identity_security_event(
                        connection,
                        &admin_event(target_tenant_id, None, None, IdentitySecurityOutcome::Denied, IdentitySecurityReason::TargetNotFound),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    (AdminUserUpdateOutcome::TargetNotFound, "target_not_found")
                };
                let outcome_name = if matches!(outcome, AdminUserUpdateOutcome::Updated(_)) { "success" } else { "denied" };
                append_fresh_security_audit_on_connection(connection, &nazo_persistence::SecurityAuditEvent {
                    event_id: Uuid::now_v7(),
                    event_type: "system_tenant_admin_updated".to_owned(),
                    event_category: "administration".to_owned(),
                    payload: serde_json::json!({
                        "tenant_id": target_tenant_id.as_uuid(),
                        "control_tenant_id": control_tenant_id.as_uuid(),
                        "actor_tenant_id": actor.map(|account| account.tenant().tenant_id.as_uuid()),
                        "actor_user_id": actor_id.as_uuid(),
                        "target_tenant_id": target_tenant_id.as_uuid(),
                        "target_user_id": target_id.as_uuid(),
                        "admin_level": admin_level,
                        "outcome": outcome_name,
                        "reason": reason,
                        "source_ip_hash": source_ip_hash,
                    }),
                    occurred_at: chrono::Utc::now(),
                }).await?;
                Ok(outcome)
            },
        )
        .await
        .map_err(AdminAuthorizedUpdateError::into_repository)
    }
    pub async fn subject_claims_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
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

/// Caller-owned user creation input for operator management. The persistence
/// boundary owns the role invariant (`user`, level `0`); callers cannot
/// provision an administrator through this path.
pub struct UserInsert<'a> {
    pub tenant: TenantContext,
    pub username: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub email_verified: bool,
    pub display_name: Option<&'a str>,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub middle_name: Option<&'a str>,
    pub nickname: Option<&'a str>,
    pub profile_url: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub website_url: Option<&'a str>,
    pub gender: Option<&'a str>,
    pub birthdate: Option<&'a str>,
    pub zoneinfo: Option<&'a str>,
    pub locale: Option<&'a str>,
    pub address_formatted: Option<&'a str>,
    pub address_street_address: Option<&'a str>,
    pub address_locality: Option<&'a str>,
    pub address_region: Option<&'a str>,
    pub address_postal_code: Option<&'a str>,
    pub address_country: Option<&'a str>,
    pub phone_number: Option<&'a str>,
    pub phone_number_verified: bool,
}

/// Inserts a user on a caller-owned transaction connection.  This is
/// ownership-neutral: no external lifecycle metadata is consulted.
/// The explicit role columns preserve the tenant's ordinary-user boundary.
pub async fn insert_user_on_connection(
    connection: &mut AsyncPgConnection,
    user: UserInsert<'_>,
) -> Result<Uuid, diesel::result::Error> {
    diesel::insert_into(users::table)
        .values((
            users::tenant_id.eq(user.tenant.tenant_id.as_uuid()),
            users::realm_id.eq(user.tenant.realm_id.as_uuid()),
            users::organization_id.eq(user.tenant.organization_id.as_uuid()),
            users::username.eq(user.username),
            users::email.eq(user.email),
            users::password_hash.eq(user.password_hash),
            users::is_active.eq(true),
            users::mfa_enabled.eq(false),
            users::email_verified.eq(user.email_verified),
            users::display_name.eq(user.display_name),
            users::given_name.eq(user.given_name),
            users::family_name.eq(user.family_name),
            users::middle_name.eq(user.middle_name),
            users::nickname.eq(user.nickname),
            users::profile_url.eq(user.profile_url),
            users::avatar_url.eq(user.avatar_url),
            users::website_url.eq(user.website_url),
            users::gender.eq(user.gender),
            users::birthdate.eq(user.birthdate),
            users::zoneinfo.eq(user.zoneinfo),
            users::locale.eq(user.locale),
            users::address_formatted.eq(user.address_formatted),
            users::address_street_address.eq(user.address_street_address),
            users::address_locality.eq(user.address_locality),
            users::address_region.eq(user.address_region),
            users::address_postal_code.eq(user.address_postal_code),
            users::address_country.eq(user.address_country),
            users::phone_number.eq(user.phone_number),
            users::phone_number_verified.eq(user.phone_number_verified),
            users::role.eq("user"),
            users::admin_level.eq(0),
        ))
        .returning(users::id)
        .get_result(connection)
        .await
}

/// Disables a user on a caller-owned transaction connection.  The operation
/// is tenant-bound and idempotent: `false` means the target was already
/// disabled or did not belong to the tenant, and no other state is changed.
pub async fn disable_user_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: TenantId,
    user_id: UserId,
) -> Result<bool, diesel::result::Error> {
    sql_query(
        "UPDATE openid4vci_offers
         SET consumed_at = GREATEST(CURRENT_TIMESTAMP, created_at)
         WHERE tenant_id = $1 AND subject_id = $2 AND consumed_at IS NULL",
    )
    .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
    .bind::<sql_types::Uuid, _>(user_id.as_uuid())
    .execute(connection)
    .await?;
    let changed = diesel::update(
        users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::id.eq(user_id.as_uuid()))
            .filter(users::is_active.eq(true)),
    )
    .set((
        users::is_active.eq(false),
        users::updated_at.eq(diesel::dsl::now),
    ))
    .execute(connection)
    .await?;
    if changed != 1 {
        return Ok(false);
    }
    super::token_issuance::revoke_access_tokens_for_owner_on_connection(
        connection,
        tenant_id.as_uuid(),
        None,
        Some(user_id.as_uuid()),
    )
    .await?;
    diesel::update(
        oauth_refresh_families::table
            .filter(oauth_refresh_families::tenant_id.eq(tenant_id.as_uuid()))
            .filter(oauth_refresh_families::user_id.eq(user_id.as_uuid()))
            .filter(oauth_refresh_families::revoked_at.is_null()),
    )
    .set(oauth_refresh_families::revoked_at.eq(diesel::dsl::now))
    .execute(connection)
    .await?;
    diesel::delete(
        user_client_grants::table
            .filter(user_client_grants::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_client_grants::user_id.eq(user_id.as_uuid())),
    )
    .execute(connection)
    .await?;
    Ok(true)
}

fn admin_event(
    tenant_id: TenantId,
    actor_id: Option<UserId>,
    target_user_id: Option<UserId>,
    outcome: IdentitySecurityOutcome,
    reason: IdentitySecurityReason,
) -> IdentitySecurityEvent {
    IdentitySecurityEvent {
        tenant_id,
        event_type: IdentitySecurityEventType::AdminUserUpdate,
        outcome,
        actor_id,
        target_user_id,
        reason,
        occurred_at: std::time::SystemTime::now(),
    }
}

const fn admin_denial_reason(error: AdminPolicyError) -> IdentitySecurityReason {
    match error {
        AdminPolicyError::ActorNotAuthorized => IdentitySecurityReason::ActorNotAuthorized,
        AdminPolicyError::CrossTenant => IdentitySecurityReason::CrossTenant,
        AdminPolicyError::SelfElevation => IdentitySecurityReason::SelfElevation,
        AdminPolicyError::SelfDemotionOrDisable => IdentitySecurityReason::SelfDemotionOrDisable,
        AdminPolicyError::TargetAtOrAboveActor => IdentitySecurityReason::TargetAtOrAboveActor,
        AdminPolicyError::GrantAtOrAboveActor => IdentitySecurityReason::GrantAtOrAboveActor,
        AdminPolicyError::InvalidRoleLevel => IdentitySecurityReason::InvalidRoleLevel,
    }
}

enum AdminAuthorizedUpdateError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
    Consistency(String),
}

impl From<diesel::result::Error> for AdminAuthorizedUpdateError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl AdminAuthorizedUpdateError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
            Self::Consistency(message) => RepositoryError::Consistency(message),
        }
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

impl nazo_identity::ports::AdminUserRepositoryPort for UserRepository {
    fn page(
        &self,
        tenant_id: nazo_identity::TenantId,
        limit: i64,
        offset: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::UserPage> {
        Box::pin(async move { UserRepository::page(self, tenant_id, limit, offset).await })
    }

    fn update_authorized(
        &self,
        tenant_id: nazo_identity::TenantId,
        actor_id: nazo_identity::UserId,
        target_id: nazo_identity::UserId,
        update: nazo_identity::ports::AdminUserUpdate,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AdminUserUpdateOutcome> {
        Box::pin(async move {
            UserRepository::admin_update_authorized(self, tenant_id, actor_id, target_id, update)
                .await
        })
    }

    fn update_authorized_with_required_audit(
        &self,
        tenant: TenantContext,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(async move {
            self.admin_update_with_required_audit(
                tenant,
                actor_id,
                target_id,
                update,
                source_ip_hash,
            )
            .await
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn set_tenant_admin_authorized(
        &self,
        control_tenant_id: nazo_identity::TenantId,
        actor_id: nazo_identity::UserId,
        target_tenant_id: nazo_identity::TenantId,
        target_id: nazo_identity::UserId,
        admin_level: i32,
        source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AdminUserUpdateOutcome> {
        Box::pin(async move {
            UserRepository::set_tenant_admin_authorized(
                self,
                control_tenant_id,
                actor_id,
                target_tenant_id,
                target_id,
                admin_level,
                source_ip_hash,
            )
            .await
        })
    }
}

impl nazo_identity::ports::ProfileRepositoryPort for UserRepository {
    fn update_profile<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        update: nazo_identity::ports::ProfileUpdate,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::PublicAccount> {
        Box::pin(
            async move { UserRepository::update_profile(self, tenant_id, user_id, update).await },
        )
    }
}

impl nazo_identity::ports::AvatarRepositoryPort for UserRepository {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async move {
            UserRepository::compare_and_set_avatar(
                self,
                tenant_id,
                user_id,
                expected_avatar_url,
                avatar_url,
            )
            .await
        })
    }
}

impl nazo_identity::ports::RegistrationAccountRepositoryPort for UserRepository {
    fn account_by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_email(self, tenant_id, email).await },
        )
    }

    fn create_user(
        &self,
        user: nazo_identity::ports::NewUser,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async move { UserRepository::create(self, user).await })
    }

    fn create_user_with_required_audit(
        &self,
        user: NewUser,
        actor_id: UserId,
        source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move {
            self.create_with_required_audit(user, actor_id, source_ip_hash)
                .await
        })
    }
}

impl nazo_identity::ports::LoginAccountRepositoryPort for UserRepository {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::AuthenticationIdentity>>
    {
        Box::pin(
            async move { UserRepository::authentication_by_email(self, tenant_id, email).await },
        )
    }

    fn public_account_by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

impl nazo_identity::ports::SessionAccountPort for UserRepository {
    fn public_account_by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

impl nazo_persistence::CibaAccountStore for UserRepository {
    fn by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<nazo_identity::PublicAccount>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(
            async move { UserRepository::public_account_by_email(self, tenant_id, email).await },
        )
    }

    fn by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<nazo_identity::PublicAccount>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

impl nazo_persistence::Openid4vcSubjectStore for UserRepository {
    fn is_active(
        &self,
        tenant_id: TenantId,
        subject_id: UserId,
    ) -> futures_util::future::BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(async move {
            UserRepository::is_active_by_tenant_id(self, tenant_id, subject_id).await
        })
    }
}

impl nazo_identity::ports::PasskeyAccountRepositoryPort for UserRepository {
    fn by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_email(self, tenant_id, email).await },
        )
    }

    fn by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

async fn append_admin_user_audit(
    connection: &mut AsyncPgConnection,
    event_type: &str,
    account: &PublicAccount,
    actor_id: UserId,
    source_ip_hash: &str,
) -> Result<(), diesel::result::Error> {
    let tenant = account.tenant();
    let role = match &account.principal.role {
        nazo_identity::UserRole::User => "user",
        nazo_identity::UserRole::Admin { .. } => "admin",
    };
    append_fresh_security_audit_on_connection(connection, &nazo_persistence::SecurityAuditEvent {
        event_id: Uuid::now_v7(), event_type: event_type.to_owned(),
        event_category: "administration".to_owned(),
        payload: serde_json::json!({
            "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
            "event_category": "administration", "tenant_id": tenant.tenant_id.as_uuid(),
            "realm_id": tenant.realm_id.as_uuid(), "organization_id": tenant.organization_id.as_uuid(),
            "admin_user_id": actor_id.as_uuid(), "user_id": account.id(),
            "role": role, "admin_level": account.principal.admin_level().unwrap_or(0),
            "is_active": account.principal.active, "outcome": "success", "source_ip_hash": source_ip_hash,
        }), occurred_at: chrono::Utc::now(),
    }).await
}

/// Shared conversion for active claims read alone or in a refresh statement.
/// An unexpected binding owner is a collision, never an absent binding.
pub(super) fn prepare_subject_claims(
    row: SubjectClaimsRow,
    epoch: i64,
    bound_user: Option<Uuid>,
) -> Result<(SubjectClaims, i64, bool), RepositoryError> {
    let user_id = row.id;
    let claims = identity::active_subject_claims(row)
        .map_err(|error| RepositoryError::Consistency(error.0))?;
    if bound_user.is_some_and(|owner| owner != user_id) {
        return Err(RepositoryError::Consistency("subject ownership collision".to_owned()));
    }
    Ok((claims, epoch, bound_user.is_some()))
}
