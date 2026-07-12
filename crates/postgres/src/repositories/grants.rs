use chrono::{DateTime, Utc};
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl};
use diesel_async::RunQueryDsl;
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
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
