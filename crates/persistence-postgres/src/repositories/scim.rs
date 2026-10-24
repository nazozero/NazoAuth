use crate::{
    DbPool,
    convert::identity,
    get_conn,
    rows::identity::PublicAccountRow,
    schema::{oauth_refresh_families, scim_security_events, user_client_grants, users},
};
use chrono::Utc;
use diesel::{
    ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
    dsl::{count_star, now, sql},
    result::{DatabaseErrorKind, Error},
    sql_types::{Bool, Timestamptz, Uuid as SqlUuid},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{
        NewScimUser, RepositoryError, RepositoryFuture, ScimListQuery, ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimPatch},
};
use nazo_scim_events::{MutationContext, StoredEvent};

const DEFAULT_SCIM_EVENT_RETENTION_SECONDS: i64 = 604_800;

#[derive(Clone)]
pub struct ScimRepository {
    pool: DbPool,
    event_retention: chrono::Duration,
}
impl ScimRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            event_retention: chrono::Duration::seconds(DEFAULT_SCIM_EVENT_RETENTION_SECONDS),
        }
    }

    #[must_use]
    pub fn with_event_retention_seconds(pool: DbPool, seconds: u64) -> Self {
        Self {
            pool,
            event_retention: chrono::Duration::seconds(
                i64::try_from(seconds).expect("validated retention seconds fit i64"),
            ),
        }
    }

    pub async fn list(&self, query: ScimListQuery) -> Result<UserPage, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut count_query = users::table
            .filter(users::tenant_id.eq(query.tenant_id.as_uuid()))
            .filter(users::deleted_at.is_null())
            .into_boxed();
        if let Some(email) = &query.email {
            count_query = count_query.filter(users::email.eq(email));
        }
        let total = count_query
            .select(count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        if query.limit == 0 {
            return Ok(UserPage {
                total,
                users: Vec::new(),
            });
        }
        let mut rows_query = users::table
            .filter(users::tenant_id.eq(query.tenant_id.as_uuid()))
            .filter(users::deleted_at.is_null())
            .into_boxed();
        if let Some(email) = query.email {
            rows_query = rows_query.filter(users::email.eq(email));
        }
        if let Some((created_at, id)) = query.after {
            rows_query = rows_query.filter(
                sql::<Bool>("(users.created_at, users.id) > (")
                    .bind::<Timestamptz, _>(created_at)
                    .sql(", ")
                    .bind::<SqlUuid, _>(id)
                    .sql(")"),
            );
        }
        let rows = rows_query
            .select(PublicAccountRow::as_select())
            .order((users::created_at.asc(), users::id.asc()))
            .limit(query.limit)
            .offset(query.offset)
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

    pub async fn get(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
            .filter(users::deleted_at.is_null())
            .select(PublicAccountRow::as_select())
            .first::<PublicAccountRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn create(&self, new_user: NewScimUser) -> Result<PublicAccount, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let input = new_user.input;
        let tenant = new_user.tenant;
        let mutation = new_user.mutation;
        let event_retention = self.event_retention;
        let row = {
            let mut guard = crate::pool::DiscardOnDrop(Some(connection));
            let result = guard
                .connection()
                .transaction::<PublicAccountRow, Error, _>(async move |connection| {
                    let row = diesel::insert_into(users::table)
                        .values((
                            users::tenant_id.eq(tenant.tenant_id.as_uuid()),
                            users::realm_id.eq(tenant.realm_id.as_uuid()),
                            users::organization_id.eq(tenant.organization_id.as_uuid()),
                            users::username.eq(input.user_name),
                            users::email.eq(input.email),
                            users::password_hash
                                .eq(new_user.password_hash.into_persistence_value()),
                            users::email_verified.eq(true),
                            users::is_active.eq(input.active),
                            users::display_name.eq(input.display_name),
                            users::given_name.eq(input.given_name),
                            users::family_name.eq(input.family_name),
                        ))
                        .returning(PublicAccountRow::as_returning())
                        .get_result(connection)
                        .await?;
                    if let Some(transaction_id) = mutation.transaction_id() {
                        insert_event(
                            connection,
                            StoredEvent::create_notice(
                                tenant.tenant_id.as_uuid(),
                                row.id,
                                transaction_id,
                                row.created_at,
                            ),
                            event_retention,
                        )
                        .await?;
                    }
                    Ok(row)
                })
                .await;
            guard.return_to_pool();
            result
        }
        .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn replace(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
    ) -> Result<PublicAccount, RepositoryError> {
        self.replace_with_mutation(tenant, user_id, replacement, MutationContext::disabled())
            .await
    }

    pub async fn replace_with_mutation(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
        mutation: MutationContext,
    ) -> Result<PublicAccount, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let event_retention = self.event_retention;
        let row = {
            let mut guard = crate::pool::DiscardOnDrop(Some(connection));
            let result = guard
                .connection()
                .transaction::<PublicAccountRow, Error, _>(async move |connection| {
                    let current_active = if mutation.transaction_id().is_some() {
                        Some(
                            users::table
                                .find(user_id.as_uuid())
                                .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                                .filter(users::deleted_at.is_null())
                                .for_update()
                                .select(users::is_active)
                                .first::<bool>(connection)
                                .await?,
                        )
                    } else {
                        None
                    };
                    let row = diesel::update(
                        users::table
                            .find(user_id.as_uuid())
                            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                            .filter(users::deleted_at.is_null()),
                    )
                    .set((
                        users::username.eq(replacement.user_name),
                        users::email.eq(replacement.email),
                        users::email_verified.eq(true),
                        users::is_active.eq(replacement.active),
                        users::display_name.eq(replacement.display_name),
                        users::given_name.eq(replacement.given_name),
                        users::family_name.eq(replacement.family_name),
                        users::updated_at.eq(now),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result(connection)
                    .await?;
                    if !row.is_active {
                        revoke(connection, tenant.tenant_id.as_uuid(), row.id).await?;
                    }
                    if let Some(transaction_id) = mutation.transaction_id() {
                        let active_transition =
                            (current_active != Some(row.is_active)).then_some(row.is_active);
                        insert_event(
                            connection,
                            StoredEvent::put_notice(
                                tenant.tenant_id.as_uuid(),
                                row.id,
                                transaction_id,
                                row.updated_at,
                                active_transition,
                            ),
                            event_retention,
                        )
                        .await?;
                    }
                    Ok(row)
                })
                .await;
            guard.return_to_pool();
            result
        }
        .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn patch(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
    ) -> Result<PublicAccount, RepositoryError> {
        self.patch_with_mutation(tenant, user_id, patch, MutationContext::disabled())
            .await
    }

    pub async fn patch_with_mutation(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
        mutation: MutationContext,
    ) -> Result<PublicAccount, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let event_attributes = if mutation.transaction_id().is_some() {
            patch.event_attributes()
        } else {
            Vec::new()
        };
        let event_retention = self.event_retention;
        let row = {
            let mut guard = crate::pool::DiscardOnDrop(Some(connection));
            let result = guard
                .connection()
                .transaction::<PublicAccountRow, Error, _>(async move |connection| {
                    let current_active =
                        if mutation.transaction_id().is_some() && patch.active.is_some() {
                            Some(
                                users::table
                                    .find(user_id.as_uuid())
                                    .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                                    .filter(users::deleted_at.is_null())
                                    .for_update()
                                    .select(users::is_active)
                                    .first::<bool>(connection)
                                    .await?,
                            )
                        } else {
                            None
                        };
                    let row = diesel::update(
                        users::table
                            .find(user_id.as_uuid())
                            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                            .filter(users::deleted_at.is_null()),
                    )
                    .set((
                        patch.user_name.map(|value| users::username.eq(value)),
                        patch.email.map(|value| users::email.eq(value)),
                        users::email_verified.eq(true),
                        patch.active.map(|value| users::is_active.eq(value)),
                        patch
                            .display_name
                            .map(|value| users::display_name.eq(value)),
                        patch.given_name.map(|value| users::given_name.eq(value)),
                        patch.family_name.map(|value| users::family_name.eq(value)),
                        users::updated_at.eq(now),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result(connection)
                    .await?;
                    if !row.is_active {
                        revoke(connection, tenant.tenant_id.as_uuid(), row.id).await?;
                    }
                    if let Some(transaction_id) = mutation.transaction_id() {
                        let active_transition = current_active
                            .and_then(|before| (before != row.is_active).then_some(row.is_active));
                        insert_event(
                            connection,
                            StoredEvent::patch_notice(
                                tenant.tenant_id.as_uuid(),
                                row.id,
                                transaction_id,
                                row.updated_at,
                                &event_attributes,
                                active_transition,
                            ),
                            event_retention,
                        )
                        .await?;
                    }
                    Ok(row)
                })
                .await;
            guard.return_to_pool();
            result
        }
        .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn delete(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<bool, RepositoryError> {
        self.delete_with_mutation(tenant, user_id, MutationContext::disabled())
            .await
    }

    pub async fn delete_with_mutation(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        mutation: MutationContext,
    ) -> Result<bool, RepositoryError> {
        let connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let event_retention = self.event_retention;
        {
            let mut guard = crate::pool::DiscardOnDrop(Some(connection));
            let result = guard
                .connection()
                .transaction::<bool, Error, _>(async move |connection| {
                    let deactivated_at = diesel::update(
                        users::table
                            .find(user_id.as_uuid())
                            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                            .filter(users::deleted_at.is_null()),
                    )
                    .set((
                        users::is_active.eq(false),
                        users::deleted_at.eq(now),
                        users::updated_at.eq(now),
                    ))
                    .returning(users::updated_at)
                    .get_result::<chrono::DateTime<Utc>>(connection)
                    .await
                    .optional()?;
                    let Some(deactivated_at) = deactivated_at else {
                        return Ok(false);
                    };
                    revoke(connection, tenant.tenant_id.as_uuid(), user_id.as_uuid()).await?;
                    if let Some(transaction_id) = mutation.transaction_id() {
                        insert_event(
                            connection,
                            StoredEvent::delete(
                                tenant.tenant_id.as_uuid(),
                                user_id.as_uuid(),
                                transaction_id,
                                deactivated_at,
                            ),
                            event_retention,
                        )
                        .await?;
                    }
                    Ok(true)
                })
                .await;
            guard.return_to_pool();
            result
        }
        .map_err(map_error)
    }
}

impl ScimRepositoryPort for ScimRepository {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(async move { Self::list(self, query).await })
    }

    fn get<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move { Self::get(self, tenant, user_id).await })
    }

    fn create<'a>(&'a self, new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move { Self::create(self, new_user).await })
    }

    fn replace<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            Self::replace_with_mutation(self, tenant, user_id, replacement, mutation).await
        })
    }

    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(
            async move { Self::patch_with_mutation(self, tenant, user_id, patch, mutation).await },
        )
    }

    fn delete<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move { Self::delete_with_mutation(self, tenant, user_id, mutation).await })
    }
}

async fn insert_event(
    connection: &mut diesel_async::AsyncPgConnection,
    event: StoredEvent,
    retention: chrono::Duration,
) -> Result<(), Error> {
    let expires_at = event.occurred_at + retention;
    diesel::insert_into(scim_security_events::table)
        .values((
            scim_security_events::id.eq(event.id),
            scim_security_events::tenant_id.eq(event.tenant_id),
            scim_security_events::transaction_id.eq(event.transaction_id),
            scim_security_events::subject_uri.eq(event.subject_uri),
            scim_security_events::events.eq(serde_json::Value::Object(
                event.events.into_iter().collect(),
            )),
            scim_security_events::occurred_at.eq(event.occurred_at),
            scim_security_events::expires_at.eq(expires_at),
        ))
        .execute(connection)
        .await?;
    Ok(())
}

async fn revoke(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<(), Error> {
    diesel::update(
        oauth_refresh_families::table
            .filter(oauth_refresh_families::tenant_id.eq(tenant_id))
            .filter(oauth_refresh_families::user_id.eq(user_id))
            .filter(oauth_refresh_families::revoked_at.is_null()),
    )
    .set(oauth_refresh_families::revoked_at.eq(now))
    .execute(connection)
    .await?;
    diesel::delete(
        user_client_grants::table
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .filter(user_client_grants::user_id.eq(user_id)),
    )
    .execute(connection)
    .await?;
    Ok(())
}

fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::NotFound => RepositoryError::NotFound,
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
