//! SCIM 2.0 user provisioning endpoints.
use crate::http::prelude::*;

mod auth;
mod normalization;
mod schema;

use auth::*;
use normalization::*;
use schema::*;

#[derive(Deserialize)]
pub(crate) struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    filter: Option<String>,
}

pub(crate) async fn scim_service_provider_config(
    state: Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    json_response(scim_base(json!({
        "id": "nazo-oauth-scim",
        "schemas": [SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": {"supported": true},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": true, "maxResults": 200},
        "changePassword": {"supported": false},
        "sort": {"supported": false},
        "etag": {"supported": false},
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
    if let Err(response) = require_scim_bearer(&state, &req, ScimRequiredScope::Read).await {
        return response;
    }
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).clamp(0, 200);
    let offset = start_index.saturating_sub(1);
    let email_filter = match normalize_scim_user_filter(query.filter.as_deref()) {
        Ok(value) => value,
        Err(response) => return response,
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
    let rows_result = if count == 0 {
        Ok(Vec::new())
    } else if let Some(email) = email_filter.as_deref() {
        users::table
            .filter(users::tenant_id.eq(tenant.tenant_id))
            .filter(users::email.eq(email))
            .select(UserRow::as_select())
            .order(users::created_at.asc())
            .limit(count)
            .offset(offset)
            .load::<UserRow>(&mut conn)
            .await
    } else {
        users::table
            .filter(users::tenant_id.eq(tenant.tenant_id))
            .select(UserRow::as_select())
            .order(users::created_at.asc())
            .limit(count)
            .offset(offset)
            .load::<UserRow>(&mut conn)
            .await
    };
    let rows = match rows_result {
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
    json_response(scim_base(json!({
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": rows.len(),
        "Resources": rows.into_iter().map(scim_user_json).collect::<Vec<_>>()
    })))
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
        Ok(user) => json_response_status(StatusCode::CREATED, scim_user_json(user)),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_error(
            StatusCode::CONFLICT,
            "uniqueness",
            "userName or email already exists",
        ),
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
        Ok(None) => scim_error(StatusCode::NOT_FOUND, "notFound", "user not found"),
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
    .get_result::<UserRow>(&mut conn)
    .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(diesel::result::Error::NotFound) => {
            scim_error(StatusCode::NOT_FOUND, "notFound", "user not found")
        }
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_error(
            StatusCode::CONFLICT,
            "uniqueness",
            "userName or email already exists",
        ),
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
        Ok(None) => return scim_error(StatusCode::NOT_FOUND, "notFound", "user not found"),
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
    .get_result::<UserRow>(&mut conn)
    .await;
    match updated {
        Ok(user) => json_response(scim_user_json(user)),
        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => scim_error(
            StatusCode::CONFLICT,
            "uniqueness",
            "userName or email already exists",
        ),
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
    match diesel::update(
        users::table
            .find(path.into_inner())
            .filter(users::tenant_id.eq(tenant.tenant_id)),
    )
    .set((users::is_active.eq(false), users::updated_at.eq(diesel_now)))
    .execute(&mut conn)
    .await
    {
        Ok(0) => scim_error(StatusCode::NOT_FOUND, "notFound", "user not found"),
        Ok(_) => empty_response(StatusCode::NO_CONTENT),
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
#[path = "../../tests/unit/src/http/tests/scim.rs"]
mod tests;
