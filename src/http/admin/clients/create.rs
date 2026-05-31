//! 管理端客户端创建端点。
// confidential 客户端只在创建响应中返回一次明文 secret。
use crate::http::prelude::*;

#[derive(Deserialize)]
pub(crate) struct CreateClientRequest {
    pub(crate) client_name: String,
    pub(crate) client_type: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allowed_audiences: Vec<String>,
    pub(crate) grant_types: Vec<String>,
    pub(crate) token_endpoint_auth_method: String,
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
    if require_admin(&state, &req).await.is_none() {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前账号无管理权限.",
        );
    }

    match insert_client_row(&state, payload).await {
        Ok((client, issued_secret)) => {
            let mut body = client_json(client);
            if let Some(secret) = issued_secret {
                body["client_secret"] = json!(secret);
            }
            json_response_status(StatusCode::CREATED, body)
        }
        Err(e) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("客户端创建失败: {e}"),
        ),
    }
}

/// 插入客户端行，并在需要时生成一次性返回的 client_secret。
pub(crate) async fn insert_client_row(
    state: &AppState,
    payload: CreateClientRequest,
) -> anyhow::Result<(ClientRow, Option<String>)> {
    validate_client_payload(&payload)?;
    let client_id = format!("client-{}", Uuid::now_v7());
    let mut issued_secret = None;
    let mut secret_hash = None;
    if payload.client_type == "confidential" {
        let secret = random_urlsafe_token();
        secret_hash = Some(
            hash_password(&secret)
                .map_err(|error| anyhow::anyhow!("client secret 哈希失败: {error}"))?,
        );
        issued_secret = Some(secret);
    }

    let mut conn = get_conn(&state.diesel_db).await?;
    let client = diesel::insert_into(oauth_clients::table)
        .values((
            oauth_clients::client_id.eq(client_id),
            oauth_clients::client_name.eq(payload.client_name),
            oauth_clients::client_type.eq(payload.client_type),
            oauth_clients::client_secret_argon2_hash.eq(secret_hash),
            oauth_clients::redirect_uris.eq(json!(payload.redirect_uris)),
            oauth_clients::scopes.eq(json!(payload.scopes)),
            oauth_clients::allowed_audiences.eq(json!(payload.allowed_audiences)),
            oauth_clients::grant_types.eq(json!(payload.grant_types)),
            oauth_clients::token_endpoint_auth_method.eq(payload.token_endpoint_auth_method),
            oauth_clients::is_active.eq(true),
        ))
        .returning(ClientRow::as_returning())
        .get_result::<ClientRow>(&mut conn)
        .await?;
    Ok((client, issued_secret))
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
    )
}
