use chrono::{DateTime, Utc};
use diesel::{
    AggregateExpressionMethods, BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{oauth_clients, user_client_grants, users},
};

#[derive(Clone, Debug, PartialEq)]
pub struct GrantProjection {
    pub user_id: Uuid,
    pub email: String,
    pub client_id: String,
    pub client_name: String,
    pub last_authorized_at: DateTime<Utc>,
    pub authorization_count: i32,
    pub last_scopes: Value,
    pub last_authorization_details: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GrantPage {
    pub total: i64,
    pub grants: Vec<GrantProjection>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GrantAuthorization {
    pub scopes: Value,
    pub resource_indicators: Value,
    pub authorization_details: Value,
    pub authorization_count: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantRevocation {
    pub revoked_refresh_tokens: usize,
    pub removed_grants: usize,
}

#[derive(diesel::Queryable)]
struct GrantRecord {
    user_id: Uuid,
    email: String,
    client_id: String,
    client_name: String,
    last_authorized_at: DateTime<Utc>,
    authorization_count: i32,
    last_scopes: Value,
    last_authorization_details: Value,
}

impl From<GrantRecord> for GrantProjection {
    fn from(record: GrantRecord) -> Self {
        Self {
            user_id: record.user_id,
            email: record.email,
            client_id: record.client_id,
            client_name: record.client_name,
            last_authorized_at: record.last_authorized_at,
            authorization_count: record.authorization_count,
            last_scopes: record.last_scopes,
            last_authorization_details: record.last_authorization_details,
        }
    }
}

#[derive(Clone)]
pub struct GrantRepository {
    pool: DbPool,
}

impl GrantRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn page(&self, limit: i64, offset: i64) -> Result<GrantPage, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let total = user_client_grants::table
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let records = user_client_grants::table
            .inner_join(
                users::table.on(users::id
                    .eq(user_client_grants::user_id)
                    .and(users::tenant_id.eq(user_client_grants::tenant_id))),
            )
            .inner_join(
                oauth_clients::table.on(oauth_clients::id
                    .eq(user_client_grants::client_id)
                    .and(oauth_clients::tenant_id.eq(user_client_grants::tenant_id))),
            )
            .select((
                user_client_grants::user_id,
                users::email,
                oauth_clients::client_id,
                oauth_clients::client_name,
                user_client_grants::last_authorized_at,
                user_client_grants::authorization_count,
                user_client_grants::last_scopes,
                user_client_grants::last_authorization_details,
            ))
            .order(user_client_grants::last_authorized_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<GrantRecord>(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(GrantPage {
            total,
            grants: records.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn upsert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
        resource_indicators: &[String],
        authorization_details: &Value,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let now = Utc::now();
        diesel::insert_into(user_client_grants::table)
            .values((
                user_client_grants::tenant_id.eq(tenant_id),
                user_client_grants::user_id.eq(user_id),
                user_client_grants::client_id.eq(client_id),
                user_client_grants::first_authorized_at.eq(now),
                user_client_grants::last_authorized_at.eq(now),
                user_client_grants::last_scopes.eq(serde_json::json!(scopes)),
                user_client_grants::last_resource_indicators
                    .eq(serde_json::json!(resource_indicators)),
                user_client_grants::last_authorization_details.eq(authorization_details),
                user_client_grants::authorization_count.eq(1),
            ))
            .on_conflict((
                user_client_grants::tenant_id,
                user_client_grants::user_id,
                user_client_grants::client_id,
            ))
            .do_update()
            .set((
                user_client_grants::last_authorized_at.eq(now),
                user_client_grants::last_scopes.eq(serde_json::json!(scopes)),
                user_client_grants::last_resource_indicators
                    .eq(serde_json::json!(resource_indicators)),
                user_client_grants::last_authorization_details.eq(authorization_details),
                user_client_grants::authorization_count
                    .eq(user_client_grants::authorization_count + 1),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(())
    }

    pub async fn authorization(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<Option<GrantAuthorization>, RepositoryError> {
        use diesel::OptionalExtension;

        let mut connection = self.connection().await?;
        user_client_grants::table
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(user_client_grants::client_id.eq(client_id))
            .select((
                user_client_grants::last_scopes,
                user_client_grants::last_resource_indicators,
                user_client_grants::last_authorization_details,
                user_client_grants::authorization_count,
            ))
            .first::<(Value, Value, Value, i32)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(
                    |(scopes, resource_indicators, authorization_details, authorization_count)| {
                        GrantAuthorization {
                            scopes,
                            resource_indicators,
                            authorization_details,
                            authorization_count,
                        }
                    },
                )
            })
            .map_err(map_error)
    }

    pub async fn authorized_client_count(&self, user_id: Uuid) -> Result<i64, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .filter(user_client_grants::user_id.eq(user_id))
            .select(diesel::dsl::count(user_client_grants::client_id).aggregate_distinct())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)
    }

    pub async fn revoke(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<GrantRevocation, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<GrantRevocation, diesel::result::Error, _>(async |connection| {
                let revoked_refresh_tokens = diesel::update(
                    crate::schema::oauth_tokens::table
                        .filter(crate::schema::oauth_tokens::user_id.eq(user_id))
                        .filter(crate::schema::oauth_tokens::client_id.eq(client_id))
                        .filter(crate::schema::oauth_tokens::revoked_at.is_null()),
                )
                .set(crate::schema::oauth_tokens::revoked_at.eq(diesel::dsl::now))
                .execute(connection)
                .await?;
                let removed_grants = diesel::delete(
                    user_client_grants::table
                        .filter(user_client_grants::user_id.eq(user_id))
                        .filter(user_client_grants::client_id.eq(client_id)),
                )
                .execute(connection)
                .await?;
                Ok(GrantRevocation {
                    revoked_refresh_tokens,
                    removed_grants,
                })
            })
            .await
            .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
