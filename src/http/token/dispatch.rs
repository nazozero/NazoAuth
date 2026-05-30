//! /token grant_type 分发入口。
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::{TokenForm, token_authorization_code, token_client_credentials, token_refresh};
use crate::http::prelude::*;

pub(crate) async fn token(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<TokenForm>,
) -> HttpResponse {
    let (client_id, client_secret, method) = extract_client_credentials(
        req.headers(),
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    );
    let Some(client_id) = client_id else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let Some(client) = find_client(&state.diesel_db, &client_id)
        .await
        .ok()
        .flatten()
    else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端不存在或已停用.",
        );
    };
    if !client.is_active || !json_array_to_strings(&client.grant_types).contains(&form.grant_type) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
        );
    }
    if client.client_type == "confidential" {
        let Some(secret) = client_secret else {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "机密客户端必须提供 client_secret.",
            );
        };
        if method != client.token_endpoint_auth_method
            || !verify_password(
                &secret,
                client.client_secret_argon2_hash.as_deref().unwrap_or(""),
            )
        {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
    }
    match form.grant_type.as_str() {
        "authorization_code" => token_authorization_code(&state, &req, &client, &form).await,
        "refresh_token" => token_refresh(&state, &req, &client, &form).await,
        "client_credentials" => token_client_credentials(&state, &req, &client, &form).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
        ),
    }
}
