//! SCIM 2.0 user provisioning endpoints.
use crate::http::prelude::*;

mod auth;
mod cursor;
mod normalization;
mod schema;

use auth::*;
use cursor::*;
use diesel_async::AsyncConnection;
use normalization::*;
use schema::*;

const SCIM_DEFAULT_PAGE_SIZE: i64 = 100;
const SCIM_MAX_PAGE_SIZE: i64 = 200;

#[derive(Deserialize)]
pub(crate) struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    filter: Option<String>,
    cursor: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum ScimPagination {
    Index { start_index: i64, count: i64 },
    Cursor { encoded: Option<String>, count: i64 },
}

fn select_scim_pagination(query: &ScimListQuery) -> Result<ScimPagination, HttpResponse> {
    if let Some(cursor) = &query.cursor {
        if query.start_index.is_some() {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "startIndex and cursor cannot be combined",
            ));
        }
        let count = query.count.unwrap_or(SCIM_DEFAULT_PAGE_SIZE).max(0);
        if count > SCIM_MAX_PAGE_SIZE {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidCount",
                "count exceeds the maximum cursor page size",
            ));
        }
        return Ok(ScimPagination::Cursor {
            encoded: (!cursor.is_empty()).then(|| cursor.clone()),
            count,
        });
    }
    Ok(ScimPagination::Index {
        start_index: query.start_index.unwrap_or(1).max(1),
        count: query
            .count
            .unwrap_or(SCIM_DEFAULT_PAGE_SIZE)
            .clamp(0, SCIM_MAX_PAGE_SIZE),
    })
}

pub(crate) async fn scim_service_provider_config(
    state: Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_service_provider_config_response()
}

fn scim_service_provider_config_response() -> HttpResponse {
    json_response(scim_base(json!({
        "id": "nazo-oauth-scim",
        "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": {"supported": true},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": true, "maxResults": SCIM_MAX_PAGE_SIZE},
        "changePassword": {"supported": false},
        "sort": {"supported": false},
        "etag": {"supported": false},
        "pagination": {
            "cursor": true,
            "index": true,
            "defaultPaginationMethod": "index",
            "defaultPageSize": SCIM_DEFAULT_PAGE_SIZE,
            "maxPageSize": SCIM_MAX_PAGE_SIZE,
            "cursorTimeout": SCIM_CURSOR_TIMEOUT_SECONDS
        },
        "securityEvents": {
            "asyncRequest": "none",
            "eventUris": []
        },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer",
            "description": "Database-backed bearer credential with legacy deployment-token fallback.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }]
    })))
}

pub(crate) async fn scim_schemas(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_schemas_response()
}

fn scim_schemas_response() -> HttpResponse {
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [scim_user_schema()]
    })))
}

pub(crate) async fn scim_resource_types(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    scim_resource_types_response()
}

fn scim_resource_types_response() -> HttpResponse {
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": 1,
        "startIndex": 1,
        "itemsPerPage": 1,
        "Resources": [{
            "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCIM_USER_SCHEMA
        }]
    })))
}

pub(crate) async fn scim_list_users(
    state: Data<AppState>,
    req: HttpRequest,
    Query(query): Query<ScimListQuery>,
) -> HttpResponse {
    let credential = match require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        Ok(credential) => credential,
        Err(response) => return response,
    };
    let pagination = match select_scim_pagination(&query) {
        Ok(pagination) => pagination,
        Err(response) => return response,
    };
    let email_filter = match normalize_scim_user_filter(query.filter.as_deref()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let cursor_position = match &pagination {
        ScimPagination::Cursor {
            encoded: Some(encoded),
            count,
        } => match decode_scim_cursor(
            &state.settings,
            encoded,
            &credential,
            query.filter.as_deref(),
            *count,
            Utc::now(),
        ) {
            Ok(position) => Some(position),
            Err(error) => return scim_cursor_error_response(error),
        },
        _ => None,
    };
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for SCIM user list");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let tenant = default_tenant_context();
    let base = users::table.filter(users::tenant_id.eq(tenant.tenant_id));
    let total_result = if let Some(email) = email_filter.as_deref() {
        base.filter(users::email.eq(email))
            .select(count_star())
            .first::<i64>(&mut conn)
            .await
    } else {
        base.select(count_star()).first::<i64>(&mut conn).await
    };
    let total = match total_result {
        Ok(total) => total,
        Err(error) => {
            tracing::warn!(%error, "failed to count SCIM users");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let count = match &pagination {
        ScimPagination::Index { count, .. } | ScimPagination::Cursor { count, .. } => *count,
    };
    let rows_result = if count == 0 {
        Ok(Vec::new())
    } else {
        let mut rows_query = users::table
            .filter(users::tenant_id.eq(tenant.tenant_id))
            .into_boxed();
        if let Some(email) = email_filter.as_deref() {
            rows_query = rows_query.filter(users::email.eq(email.to_owned()));
        }
        if let Some(position) = &cursor_position {
            rows_query = rows_query.filter(
                users::created_at
                    .gt(position.last_created_at)
                    .or(users::created_at
                        .eq(position.last_created_at)
                        .and(users::id.gt(position.last_id))),
            );
        }
        let (limit, offset) = match &pagination {
            ScimPagination::Index { start_index, count } => (*count, start_index.saturating_sub(1)),
            ScimPagination::Cursor { count, .. } => (count.saturating_add(1), 0),
        };
        rows_query
            .select(UserRow::as_select())
            .order((users::created_at.asc(), users::id.asc()))
            .limit(limit)
            .offset(offset)
            .load::<UserRow>(&mut conn)
            .await
    };
    let mut rows = match rows_result {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "failed to load SCIM users");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    match pagination {
        ScimPagination::Index { start_index, .. } => {
            scim_list_users_response(total, start_index, rows)
        }
        ScimPagination::Cursor { count, .. } => {
            let has_more = rows.len() > count as usize;
            if has_more {
                rows.truncate(count as usize);
            }
            let next_cursor = if has_more {
                let Some(last) = rows.last() else {
                    tracing::warn!("SCIM cursor query reported more rows without a page marker");
                    return scim_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "backend unavailable",
                    );
                };
                match encode_scim_cursor(
                    &state.settings,
                    &ScimCursorContext {
                        credential: &credential,
                        filter: query.filter.as_deref(),
                        count,
                        last_created_at: last.created_at,
                        last_id: last.id,
                    },
                    Utc::now(),
                ) {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        tracing::warn!(%error, "failed to encode SCIM cursor");
                        return scim_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "backend unavailable",
                        );
                    }
                }
            } else {
                None
            };
            scim_cursor_list_users_response(total, rows, next_cursor)
        }
    }
}

fn scim_cursor_error_response(error: ScimCursorError) -> HttpResponse {
    match error {
        ScimCursorError::Invalid => {
            scim_error(StatusCode::BAD_REQUEST, "invalidCursor", "invalid cursor")
        }
        ScimCursorError::Expired => {
            scim_error(StatusCode::BAD_REQUEST, "expiredCursor", "cursor expired")
        }
        ScimCursorError::InvalidCount => scim_error(
            StatusCode::BAD_REQUEST,
            "invalidCount",
            "count does not match cursor",
        ),
    }
}

fn scim_list_users_response(total: i64, start_index: i64, rows: Vec<UserRow>) -> HttpResponse {
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": rows.len(),
        "Resources": rows.into_iter().map(scim_user_json).collect::<Vec<_>>()
    })))
}

fn scim_cursor_list_users_response(
    total: i64,
    rows: Vec<UserRow>,
    next_cursor: Option<String>,
) -> HttpResponse {
    let mut body = scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "itemsPerPage": rows.len(),
        "Resources": rows.into_iter().map(scim_user_json).collect::<Vec<_>>()
    }));
    if let Some(next_cursor) = next_cursor {
        body["nextCursor"] = json!(next_cursor);
    }
    json_response(body)
}

fn scim_create_user_response(user: UserRow) -> HttpResponse {
    json_response_status(StatusCode::CREATED, scim_user_json(user))
}

fn scim_uniqueness_conflict_response() -> HttpResponse {
    scim_error(
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    )
}

pub(crate) async fn scim_create_user(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let password_hash = match hash_password(&random_urlsafe_token()) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(%error, "failed to hash random SCIM bootstrap password");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let tenant = default_tenant_context();
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for SCIM create");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let row = diesel::insert_into(users::table)
        .values((
            users::tenant_id.eq(tenant.tenant_id),
            users::realm_id.eq(tenant.realm_id),
            users::organization_id.eq(tenant.organization_id),
            users::username.eq(input.user_name),
            users::email.eq(input.email),
            users::password_hash.eq(password_hash),
            users::email_verified.eq(true),
            users::is_active.eq(input.active),
            users::display_name.eq(input.display_name),
            users::given_name.eq(input.given_name),
            users::family_name.eq(input.family_name),
        ))
        .returning(UserRow::as_returning())
        .get_result::<UserRow>(&mut conn)
        .await;
    match row {
        Ok(user) => scim_create_user_response(user),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to create SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_get_user(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    match load_scim_user(&state, path.into_inner()).await {
        Ok(Some(user)) => json_response(scim_user_json(user)),
        Ok(None) => scim_user_not_found_response(),
        Err(response) => response,
    }
}

pub(crate) async fn scim_replace_user(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<ScimUserRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let user_id = path.into_inner();
    let input = match normalize_scim_user_payload(payload, true) {
        Ok(input) => input,
        Err(response) => return response,
    };
    let tenant = default_tenant_context();
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for SCIM replace");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let updated = conn
        .transaction::<UserRow, diesel::result::Error, _>(async |conn| {
            let updated = diesel::update(
                users::table
                    .find(user_id)
                    .filter(users::tenant_id.eq(tenant.tenant_id)),
            )
            .set((
                users::username.eq(input.user_name),
                users::email.eq(input.email),
                users::email_verified.eq(true),
                users::is_active.eq(input.active),
                users::display_name.eq(input.display_name),
                users::given_name.eq(input.given_name),
                users::family_name.eq(input.family_name),
                users::updated_at.eq(diesel_now),
            ))
            .returning(UserRow::as_returning())
            .get_result::<UserRow>(conn)
            .await?;
            if !updated.is_active {
                revoke_scim_deprovisioned_user_credentials(conn, tenant.tenant_id, updated.id)
                    .await?;
            }
            Ok(updated)
        })
        .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(diesel::result::Error::NotFound) => scim_user_not_found_response(),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to replace SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_patch_user(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    Json(payload): Json<ScimPatchRequest>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Write).await {
        return response;
    }
    if !payload.schemas.is_empty()
        && !payload
            .schemas
            .iter()
            .any(|schema| schema == SCIM_PATCH_SCHEMA)
    {
        return scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "unsupported PATCH schema",
        );
    }
    let patch = match normalize_patch(payload.operations) {
        Ok(patch) => patch,
        Err(response) => return response,
    };
    let user_id = path.into_inner();
    let current = match load_scim_user(&state, user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return scim_user_not_found_response(),
        Err(response) => return response,
    };
    let tenant = default_tenant_context();
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for SCIM patch");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let updated = conn
        .transaction::<UserRow, diesel::result::Error, _>(async |conn| {
            let updated = diesel::update(
                users::table
                    .find(user_id)
                    .filter(users::tenant_id.eq(tenant.tenant_id)),
            )
            .set((
                users::username.eq(patch.user_name.unwrap_or(current.username)),
                users::email.eq(patch.email.unwrap_or(current.email)),
                users::email_verified.eq(true),
                users::is_active.eq(patch.active.unwrap_or(current.is_active)),
                users::display_name.eq(patch.display_name.or(current.display_name)),
                users::given_name.eq(patch.given_name.or(current.given_name)),
                users::family_name.eq(patch.family_name.or(current.family_name)),
                users::updated_at.eq(diesel_now),
            ))
            .returning(UserRow::as_returning())
            .get_result::<UserRow>(conn)
            .await?;
            if !updated.is_active {
                revoke_scim_deprovisioned_user_credentials(conn, tenant.tenant_id, updated.id)
                    .await?;
            }
            Ok(updated)
        })
        .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_uniqueness_conflict_response(),
        Err(error) => {
            tracing::warn!(%error, "failed to patch SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

pub(crate) async fn scim_delete_user(
    state: Data<AppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Write).await {
        return response;
    }
    let tenant = default_tenant_context();
    let mut conn = match get_conn(&state.diesel_db).await {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for SCIM delete");
            return scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            );
        }
    };
    let user_id = path.into_inner();
    match conn
        .transaction::<usize, diesel::result::Error, _>(async |conn| {
            let updated = diesel::update(
                users::table
                    .find(user_id)
                    .filter(users::tenant_id.eq(tenant.tenant_id)),
            )
            .set((users::is_active.eq(false), users::updated_at.eq(diesel_now)))
            .execute(conn)
            .await?;
            if updated > 0 {
                revoke_scim_deprovisioned_user_credentials(conn, tenant.tenant_id, user_id).await?;
            }
            Ok(updated)
        })
        .await
    {
        Ok(deleted) => scim_delete_user_response(deleted),
        Err(error) => {
            tracing::warn!(%error, "failed to delete SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        }
    }
}

async fn revoke_scim_deprovisioned_user_credentials(
    conn: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<(), diesel::result::Error> {
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::user_id.eq(user_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(diesel_now))
    .execute(conn)
    .await?;
    diesel::delete(
        user_client_grants::table
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .filter(user_client_grants::user_id.eq(user_id)),
    )
    .execute(conn)
    .await?;
    Ok(())
}

fn scim_user_not_found_response() -> HttpResponse {
    scim_error(StatusCode::NOT_FOUND, "notFound", "user not found")
}

fn scim_delete_user_response(updated_count: usize) -> HttpResponse {
    if updated_count == 0 {
        return scim_user_not_found_response();
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn load_scim_user(state: &AppState, user_id: Uuid) -> Result<Option<UserRow>, HttpResponse> {
    let tenant = default_tenant_context();
    let mut conn = get_conn(&state.diesel_db).await.map_err(|error| {
        tracing::warn!(%error, "failed to get database connection for SCIM user read");
        scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "backend unavailable",
        )
    })?;
    users::table
        .find(user_id)
        .filter(users::tenant_id.eq(tenant.tenant_id))
        .select(UserRow::as_select())
        .first::<UserRow>(&mut conn)
        .await
        .optional()
        .map_err(|error| {
            tracing::warn!(%error, "failed to load SCIM user");
            scim_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "backend unavailable",
            )
        })
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/scim.rs"]
mod tests;
