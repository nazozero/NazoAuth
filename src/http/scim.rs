//! SCIM 2.0 user provisioning endpoints.
use crate::http::prelude::*;

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const SCIM_SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const SCIM_RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

#[derive(Deserialize)]
pub(crate) struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start_index: Option<i64>,
    count: Option<i64>,
    filter: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ScimUserRequest {
    #[serde(rename = "userName")]
    user_name: Option<String>,
    active: Option<bool>,
    name: Option<ScimName>,
    emails: Option<Vec<ScimEmail>>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ScimName {
    #[serde(rename = "givenName")]
    given_name: Option<String>,
    #[serde(rename = "familyName")]
    family_name: Option<String>,
    #[serde(rename = "formatted")]
    formatted: Option<String>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct ScimEmail {
    value: Option<String>,
    primary: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct ScimPatchRequest {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<ScimPatchOperation>,
}

#[derive(Deserialize)]
pub(crate) struct ScimPatchOperation {
    op: String,
    path: Option<String>,
    value: Value,
}

pub(crate) async fn scim_service_provider_config(
    state: Data<AppState>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req) {
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
            "description": "Static deployment bearer token for SCIM provisioning.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }]
    })))
}

pub(crate) async fn scim_schemas(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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
    if let Err(response) = require_scim_bearer(&state, &req) {
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

struct NormalizedScimUser {
    user_name: String,
    email: String,
    active: bool,
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}

#[derive(Default)]
struct ScimPatch {
    user_name: Option<String>,
    email: Option<String>,
    active: Option<bool>,
    display_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
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

fn normalize_scim_user_payload(
    payload: ScimUserRequest,
    require_identity: bool,
) -> Result<NormalizedScimUser, HttpResponse> {
    let user_name = normalize_scim_string(payload.user_name, 120, "userName", require_identity)?;
    let user_name_email = match user_name {
        Some(value) => normalize_email_address(&value).map_err(|_| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "userName must be an email address",
            )
        })?,
        None if require_identity => {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "userName required",
            ));
        }
        None => String::new(),
    };
    let email = primary_email(payload.emails, require_identity)?;
    if require_identity && email != user_name_email {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        ));
    }
    let name = payload.name;
    Ok(NormalizedScimUser {
        user_name: user_name_email,
        email,
        active: payload.active.unwrap_or(true),
        display_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.formatted.clone()),
            80,
            "name.formatted",
            false,
        )?,
        given_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.given_name.clone()),
            80,
            "name.givenName",
            false,
        )?,
        family_name: normalize_scim_string(
            name.as_ref().and_then(|name| name.family_name.clone()),
            80,
            "name.familyName",
            false,
        )?,
    })
}

fn normalize_patch(operations: Vec<ScimPatchOperation>) -> Result<ScimPatch, HttpResponse> {
    let mut patch = ScimPatch::default();
    if operations.is_empty() {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "PATCH Operations required",
        ));
    }
    for operation in operations {
        if !operation.op.eq_ignore_ascii_case("replace") {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "mutability",
                "only replace is supported",
            ));
        }
        let Some(path) = operation.path.as_deref().map(normalize_scim_path) else {
            apply_patch_object(&mut patch, operation.value)?;
            continue;
        };
        match path.as_str() {
            "username" => {
                patch.user_name = Some(required_email_value(operation.value, "userName")?)
            }
            "active" => patch.active = Some(required_bool_value(operation.value, "active")?),
            "name.formatted" => {
                patch.display_name = Some(required_string_value(operation.value, "name.formatted")?)
            }
            "name.givenname" => {
                patch.given_name = Some(required_string_value(operation.value, "name.givenName")?)
            }
            "name.familyname" => {
                patch.family_name = Some(required_string_value(operation.value, "name.familyName")?)
            }
            "emails" => patch.email = Some(primary_email_from_value(operation.value)?),
            _ => {
                return Err(scim_error(
                    StatusCode::BAD_REQUEST,
                    "invalidPath",
                    "unsupported path",
                ));
            }
        }
    }
    sync_scim_identity(&mut patch)?;
    Ok(patch)
}

fn apply_patch_object(patch: &mut ScimPatch, value: Value) -> Result<(), HttpResponse> {
    let object = value.as_object().ok_or_else(|| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "PATCH value must be object",
        )
    })?;
    if let Some(value) = object.get("userName") {
        patch.user_name = Some(required_email_value(value.clone(), "userName")?);
    }
    if let Some(value) = object.get("active") {
        patch.active = Some(required_bool_value(value.clone(), "active")?);
    }
    if let Some(value) = object.get("name") {
        let name = value.as_object().ok_or_else(|| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidSyntax",
                "name must be object",
            )
        })?;
        if let Some(value) = name.get("formatted") {
            patch.display_name = Some(required_string_value(value.clone(), "name.formatted")?);
        }
        if let Some(value) = name.get("givenName") {
            patch.given_name = Some(required_string_value(value.clone(), "name.givenName")?);
        }
        if let Some(value) = name.get("familyName") {
            patch.family_name = Some(required_string_value(value.clone(), "name.familyName")?);
        }
    }
    if let Some(value) = object.get("emails") {
        patch.email = Some(primary_email_from_value(value.clone())?);
    }
    if let (Some(user_name), Some(email)) = (&patch.user_name, &patch.email)
        && user_name != email
    {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        ));
    }
    Ok(())
}

fn sync_scim_identity(patch: &mut ScimPatch) -> Result<(), HttpResponse> {
    match (&patch.user_name, &patch.email) {
        (Some(user_name), Some(email)) if user_name != email => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "primary email must match userName",
        )),
        (Some(user_name), None) => {
            patch.email = Some(user_name.clone());
            Ok(())
        }
        (None, Some(email)) => {
            patch.user_name = Some(email.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

fn require_scim_bearer(state: &AppState, req: &HttpRequest) -> Result<(), HttpResponse> {
    let Some(expected) = state.settings.scim_bearer_token.as_deref() else {
        return Err(scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "disabled",
            "SCIM is not configured",
        ));
    };
    let Some(actual) = bearer_token(req) else {
        return Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ));
    };
    if constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        Ok(())
    } else {
        Err(scim_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid bearer token",
        ))
    }
}

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    let raw = req
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let (scheme, token) = raw.split_once(char::is_whitespace)?;
    (scheme.eq_ignore_ascii_case("Bearer") && !token.trim().is_empty()).then_some(token.trim())
}

fn normalize_scim_user_filter(filter: Option<&str>) -> Result<Option<String>, HttpResponse> {
    let Some(filter) = filter.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((field, value)) = filter.split_once(" eq ") else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "only eq filters are supported",
        ));
    };
    if !field.trim().eq_ignore_ascii_case("userName") {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "only userName filters are supported",
        ));
    }
    let value = value.trim();
    if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidFilter",
            "filter value must be quoted",
        ));
    }
    normalize_email_address(&value[1..value.len() - 1])
        .map(Some)
        .map_err(|_| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "invalidFilter",
                "userName filter is invalid",
            )
        })
}

fn primary_email(values: Option<Vec<ScimEmail>>, required: bool) -> Result<String, HttpResponse> {
    let Some(values) = values else {
        return if required {
            Err(scim_error(
                StatusCode::BAD_REQUEST,
                "invalidValue",
                "email is required",
            ))
        } else {
            Ok(String::new())
        };
    };
    let selected = values
        .iter()
        .find(|email| email.primary.unwrap_or(false))
        .or_else(|| values.as_slice().first())
        .and_then(|email| email.value.as_deref());
    let Some(value) = selected else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "email value is required",
        ));
    };
    normalize_email_address(value)
        .map_err(|_| scim_error(StatusCode::BAD_REQUEST, "invalidValue", "email is invalid"))
}

fn primary_email_from_value(value: Value) -> Result<String, HttpResponse> {
    let emails = serde_json::from_value::<Vec<ScimEmail>>(value).map_err(|_| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            "emails must be an array",
        )
    })?;
    primary_email(Some(emails), true)
}

fn normalize_scim_string(
    value: Option<String>,
    max_bytes: usize,
    field: &str,
    required: bool,
) -> Result<Option<String>, HttpResponse> {
    let value = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    match value {
        Some(value) if value.len() <= max_bytes => Ok(Some(value)),
        Some(_) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} too long"),
        )),
        None if required => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} required"),
        )),
        None => Ok(None),
    }
}

fn required_string_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    normalize_scim_string(value.as_str().map(ToOwned::to_owned), 120, field, true)?
        .ok_or_else(|| scim_error(StatusCode::BAD_REQUEST, "invalidValue", "value required"))
}

fn required_email_value(value: Value, field: &str) -> Result<String, HttpResponse> {
    let value = required_string_value(value, field)?;
    normalize_email_address(&value).map_err(|_| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} must be an email address"),
        )
    })
}

fn required_bool_value(value: Value, field: &str) -> Result<bool, HttpResponse> {
    value.as_bool().ok_or_else(|| {
        scim_error(
            StatusCode::BAD_REQUEST,
            "invalidValue",
            &format!("{field} must be boolean"),
        )
    })
}

fn normalize_scim_path(value: &str) -> String {
    value.trim().replace(' ', "").to_ascii_lowercase()
}

fn scim_user_json(user: UserRow) -> Value {
    scim_base(json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id,
        "userName": user.email,
        "active": user.is_active,
        "name": {
            "formatted": user.display_name,
            "givenName": user.given_name,
            "familyName": user.family_name
        },
        "emails": [{
            "value": user.email,
            "primary": true
        }],
        "meta": {
            "resourceType": "User",
            "created": user.created_at,
            "lastModified": user.updated_at,
            "location": format!("/scim/v2/Users/{}", user.id)
        }
    }))
}

fn scim_user_schema() -> Value {
    scim_base(json!({
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "Core User",
        "attributes": [
            {"name": "userName", "type": "string", "multiValued": false, "required": true},
            {"name": "active", "type": "boolean", "multiValued": false, "required": false},
            {"name": "name", "type": "complex", "multiValued": false, "required": false},
            {"name": "emails", "type": "complex", "multiValued": true, "required": true}
        ]
    }))
}

fn scim_base(value: Value) -> Value {
    value
}

fn scim_error(status: StatusCode, scim_type: &str, detail: &str) -> HttpResponse {
    json_response_status(
        status,
        json!({
            "schemas": [SCIM_ERROR_SCHEMA],
            "status": status.as_u16().to_string(),
            "scimType": scim_type,
            "detail": detail
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_user_filter_accepts_user_name_eq_quoted_email() {
        assert_eq!(
            normalize_scim_user_filter(Some(r#"userName eq "USER@example.com""#))
                .unwrap()
                .as_deref(),
            Some("user@example.com")
        );
    }

    #[test]
    fn scim_user_filter_rejects_other_fields() {
        assert!(normalize_scim_user_filter(Some(r#"email eq "user@example.com""#)).is_err());
    }

    #[test]
    fn patch_requires_replace_operations() {
        let operation = ScimPatchOperation {
            op: "add".to_owned(),
            path: Some("active".to_owned()),
            value: json!(true),
        };

        assert!(normalize_patch(vec![operation]).is_err());
    }

    #[test]
    fn bearer_token_accepts_only_non_empty_bearer_scheme() {
        let req = actix_web::test::TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer scim-secret"))
            .to_http_request();
        assert_eq!(bearer_token(&req), Some("scim-secret"));

        let req = actix_web::test::TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Basic scim-secret"))
            .to_http_request();
        assert_eq!(bearer_token(&req), None);

        let req = actix_web::test::TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer   "))
            .to_http_request();
        assert_eq!(bearer_token(&req), None);
    }

    #[test]
    fn scim_payload_requires_user_name_and_primary_email_to_match() {
        let payload = ScimUserRequest {
            user_name: Some("user@example.com".to_owned()),
            active: Some(true),
            name: None,
            emails: Some(vec![ScimEmail {
                value: Some("other@example.com".to_owned()),
                primary: Some(true),
            }]),
        };

        assert!(normalize_scim_user_payload(payload, true).is_err());
    }

    #[test]
    fn scim_payload_normalizes_primary_email_identity() {
        let payload = ScimUserRequest {
            user_name: Some("USER@example.com".to_owned()),
            active: None,
            name: Some(ScimName {
                given_name: Some(" Alice ".to_owned()),
                family_name: Some(" Example ".to_owned()),
                formatted: Some(" Alice Example ".to_owned()),
            }),
            emails: Some(vec![ScimEmail {
                value: Some("user@example.com".to_owned()),
                primary: Some(true),
            }]),
        };

        let normalized = normalize_scim_user_payload(payload, true).unwrap();
        assert_eq!(normalized.user_name, "user@example.com");
        assert_eq!(normalized.email, "user@example.com");
        assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
        assert!(normalized.active);
    }

    #[test]
    fn patch_syncs_user_name_and_email_identity() {
        let patch = normalize_patch(vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("userName".to_owned()),
            value: json!("USER@example.com"),
        }])
        .unwrap();

        assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
        assert_eq!(patch.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn patch_rejects_conflicting_user_name_and_email_identity() {
        let patch = normalize_patch(vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: None,
            value: json!({
                "userName": "user@example.com",
                "emails": [{"value": "other@example.com", "primary": true}]
            }),
        }]);

        assert!(patch.is_err());
    }
}
