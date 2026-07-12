use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, OptionalExtension,
    PgTextExpressionMethods, QueryDsl,
};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{client_access_requests, users},
};

#[derive(Clone, Debug, PartialEq)]
pub struct AccessRequestProjection {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub site_name: String,
    pub site_url: String,
    pub request_description: String,
    pub status: i16,
    pub admin_note: Option<String>,
    pub approved_client_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(diesel::Queryable)]
struct AccessRequestRecord {
    id: Uuid,
    user_id: Uuid,
    user_email: String,
    site_name: String,
    site_url: String,
    request_description: String,
    status: i16,
    admin_note: Option<String>,
    approved_client_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

impl From<AccessRequestRecord> for AccessRequestProjection {
    fn from(record: AccessRequestRecord) -> Self {
        Self {
            id: record.id,
            user_id: record.user_id,
            user_email: record.user_email,
            site_name: record.site_name,
            site_url: record.site_url,
            request_description: record.request_description,
            status: record.status,
            admin_note: record.admin_note,
            approved_client_id: record.approved_client_id,
            created_at: record.created_at,
            resolved_at: record.resolved_at,
        }
    }
}

#[derive(Clone)]
pub struct AccessRequestRepository {
    pool: DbPool,
}

impl AccessRequestRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn count(
        &self,
        search: Option<&str>,
        status: Option<i16>,
    ) -> Result<i64, RepositoryError> {
        let mut connection = self.connection().await?;
        let mut query = client_access_requests::table
            .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
            .into_boxed();
        if let Some(status) = status {
            query = query.filter(client_access_requests::status.eq(status));
        }
        if let Some(pattern) = search_pattern(search) {
            query = query.filter(
                users::email
                    .ilike(pattern.clone())
                    .or(client_access_requests::site_name.ilike(pattern.clone()))
                    .or(client_access_requests::site_url.ilike(pattern)),
            );
        }
        query
            .select(diesel::dsl::count(client_access_requests::id))
            .first(&mut connection)
            .await
            .map_err(map_error)
    }

    pub async fn page(
        &self,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<i16>,
    ) -> Result<Vec<AccessRequestProjection>, RepositoryError> {
        let mut connection = self.connection().await?;
        let mut query = client_access_requests::table
            .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
            .into_boxed();
        if let Some(status) = status {
            query = query.filter(client_access_requests::status.eq(status));
        }
        if let Some(pattern) = search_pattern(search) {
            query = query.filter(
                users::email
                    .ilike(pattern.clone())
                    .or(client_access_requests::site_name.ilike(pattern.clone()))
                    .or(client_access_requests::site_url.ilike(pattern)),
            );
        }
        query
            .select((
                client_access_requests::id,
                client_access_requests::user_id,
                users::email,
                client_access_requests::site_name,
                client_access_requests::site_url,
                client_access_requests::request_description,
                client_access_requests::status,
                client_access_requests::admin_note,
                client_access_requests::approved_client_id,
                client_access_requests::created_at,
                client_access_requests::resolved_at,
            ))
            .order(client_access_requests::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<AccessRequestRecord>(&mut connection)
            .await
            .map(|records| records.into_iter().map(Into::into).collect())
            .map_err(map_error)
    }

    pub async fn by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<AccessRequestProjection>, RepositoryError> {
        let mut connection = self.connection().await?;
        client_access_requests::table
            .inner_join(users::table.on(users::id.eq(client_access_requests::user_id)))
            .filter(client_access_requests::id.eq(id))
            .select((
                client_access_requests::id,
                client_access_requests::user_id,
                users::email,
                client_access_requests::site_name,
                client_access_requests::site_url,
                client_access_requests::request_description,
                client_access_requests::status,
                client_access_requests::admin_note,
                client_access_requests::approved_client_id,
                client_access_requests::created_at,
                client_access_requests::resolved_at,
            ))
            .first::<AccessRequestRecord>(&mut connection)
            .await
            .optional()
            .map(|record| record.map(Into::into))
            .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

fn search_pattern(search: Option<&str>) -> Option<String> {
    search
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::search_pattern;

    #[test]
    fn search_pattern_trims_and_ignores_blank_queries() {
        assert_eq!(search_pattern(None), None);
        assert_eq!(search_pattern(Some("")), None);
        assert_eq!(search_pattern(Some("   \t")), None);
        assert_eq!(
            search_pattern(Some("  alice@example.com  ")).as_deref(),
            Some("%alice@example.com%")
        );
    }
}
