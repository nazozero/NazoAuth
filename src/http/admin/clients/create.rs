//! 管理端客户端创建端点。
// confidential 客户端只在创建响应中返回一次明文 secret。
use crate::http::prelude::*;
use diesel_async::AsyncPgConnection;

#[derive(Deserialize)]
pub(crate) struct CreateClientRequest {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    #[serde(default)]
    pub(crate) require_dpop_bound_tokens: bool,
    #[serde(default)]
    pub(crate) allow_client_assertion_audience_array: bool,
    pub(crate) jwks: Option<Value>,
}

pub(crate) enum InsertClientError {
    InvalidRequest(String),
    Server(String),
}

pub(crate) struct PreparedClientInsert {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
    pub(crate) require_dpop_bound_tokens: bool,
    pub(crate) allow_client_assertion_audience_array: bool,
    pub(crate) jwks: Option<Value>,
    pub(crate) issued_secret: Option<String>,
    client_secret_argon2_hash: Option<String>,
}

/// 创建 OAuth 客户端。
pub(crate) async fn admin_create_client(
    state: Data<AppState>,
    req: HttpRequest,
    Json(payload): Json<CreateClientRequest>,
) -> HttpResponse {
    if !has_valid_csrf_token(&state, &req, None) {
        return csrf_error();
    }
    if let Err(response) = require_admin_or_forbidden(&state, &req).await {
        return response;
    }

    match insert_client_row(&state, payload).await {
        Ok((client, issued_secret)) => {
            audit_event(
                "client_created",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip(&req, &state.settings))),
                    ),
                ]),
            );
            let mut body = client_json(client);
            if let Some(secret) = issued_secret {
                body["client_secret"] = json!(secret);
            }
            json_response_status(StatusCode::CREATED, body)
        }
        Err(error) => insert_client_error_response(error),
    }
}

pub(crate) fn insert_client_error_response(error: InsertClientError) -> HttpResponse {
    match error {
        InsertClientError::InvalidRequest(message) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {message}"),
        ),
        InsertClientError::Server(message) => {
            tracing::warn!(%message, "failed to create oauth client");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端创建失败.",
            )
        }
    }
}

/// 插入客户端行，并在需要时生成一次性返回的 client_secret。
pub(crate) async fn insert_client_row(
    state: &AppState,
    payload: CreateClientRequest,
) -> Result<(ClientRow, Option<String>), InsertClientError> {
    let prepared = prepare_client_insert(payload)?;
    let issued_secret = prepared.issued_secret.clone();
    let mut conn = get_conn(&state.diesel_db)
        .await
        .map_err(|error| InsertClientError::Server(format!("数据库连接失败: {error}")))?;
    let client = insert_prepared_client(&mut conn, &prepared)
        .await
        .map_err(|error| InsertClientError::Server(format!("客户端写入失败: {error}")))?;
    Ok((client, issued_secret))
}

pub(crate) fn prepare_client_insert(
    payload: CreateClientRequest,
) -> Result<PreparedClientInsert, InsertClientError> {
    validate_client_payload(&payload)
        .map_err(|error| InsertClientError::InvalidRequest(error.to_string()))?;
    let mut issued_secret = None;
    let mut secret_hash = None;
    if payload.client_type == "confidential"
        && matches!(
            payload.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        )
    {
        let secret = random_urlsafe_token();
        secret_hash = Some(hash_password(&secret).map_err(|error| {
            InsertClientError::Server(format!("client secret 哈希失败: {error}"))
        })?);
        issued_secret = Some(secret);
    }

    Ok(PreparedClientInsert {
        client_id: format!("client-{}", Uuid::now_v7()),
        client_name: payload.client_name,
        client_type: payload.client_type,
        redirect_uris: payload.redirect_uris,
        scopes: payload.scopes,
        allowed_audiences: payload.allowed_audiences,
        grant_types: payload.grant_types,
        token_endpoint_auth_method: payload.token_endpoint_auth_method,
        require_dpop_bound_tokens: payload.require_dpop_bound_tokens,
        allow_client_assertion_audience_array: payload.allow_client_assertion_audience_array,
        jwks: payload.jwks,
        issued_secret,
        client_secret_argon2_hash: secret_hash,
    })
}

pub(crate) async fn insert_prepared_client(
    conn: &mut AsyncPgConnection,
    prepared: &PreparedClientInsert,
) -> diesel::QueryResult<ClientRow> {
    diesel::insert_into(oauth_clients::table)
        .values((
            oauth_clients::client_id.eq(&prepared.client_id),
            oauth_clients::client_name.eq(&prepared.client_name),
            oauth_clients::client_type.eq(&prepared.client_type),
            oauth_clients::client_secret_argon2_hash.eq(&prepared.client_secret_argon2_hash),
            oauth_clients::redirect_uris.eq(json!(&prepared.redirect_uris)),
            oauth_clients::scopes.eq(json!(&prepared.scopes)),
            oauth_clients::allowed_audiences.eq(json!(&prepared.allowed_audiences)),
            oauth_clients::grant_types.eq(json!(&prepared.grant_types)),
            oauth_clients::token_endpoint_auth_method.eq(&prepared.token_endpoint_auth_method),
            oauth_clients::require_dpop_bound_tokens.eq(prepared.require_dpop_bound_tokens),
            oauth_clients::allow_client_assertion_audience_array
                .eq(prepared.allow_client_assertion_audience_array),
            oauth_clients::jwks.eq(&prepared.jwks),
            oauth_clients::is_active.eq(true),
        ))
        .returning(ClientRow::as_returning())
        .get_result::<ClientRow>(conn)
        .await
}

/// 校验客户端注册请求的协议约束。
fn validate_client_payload(payload: &CreateClientRequest) -> anyhow::Result<()> {
    validate_client_metadata(
        &payload.client_type,
        &payload.redirect_uris,
        &payload.scopes,
        &payload.allowed_audiences,
        &payload.grant_types,
        &payload.token_endpoint_auth_method,
        payload.jwks.as_ref(),
    )
}
