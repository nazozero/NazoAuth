//! /token grant_type 分发入口。
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::{
    TokenFormError, parse_token_form, token_authorization_code, token_client_credentials,
    token_refresh,
};
use crate::http::prelude::*;

pub(crate) async fn token(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::Token).await {
        return response;
    }

    let form = match parse_token_form(&req, &body) {
        Ok(form) => form,
        Err(TokenFormError::InvalidContentType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求必须使用 application/x-www-form-urlencoded.",
                false,
            );
        }
        Err(TokenFormError::InvalidEncoding) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "token 请求体必须使用 UTF-8 编码.",
                false,
            );
        }
        Err(TokenFormError::DuplicateParameter) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
                false,
            );
        }
        Err(TokenFormError::MissingGrantType) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 grant_type.",
                false,
            );
        }
    };
    let has_basic = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("Basic "));
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        );
    }
    if has_assertion && form.client_secret.is_some() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一 token 请求不能同时使用多种客户端认证方式.",
            false,
        );
    }
    let credentials = extract_client_credentials(
        req.headers(),
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            has_basic,
        );
    };
    let Some(client) = find_client(&state.diesel_db, client_id)
        .await
        .ok()
        .flatten()
    else {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端不存在或已停用.",
            has_basic,
        );
    };
    if !client.is_active || !json_array_to_strings(&client.grant_types).contains(&form.grant_type) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        );
    }
    if client.client_type == "confidential" {
        if credentials.method != client.token_endpoint_auth_method {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
                has_basic,
            );
        }
        match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let Some(assertion) = credentials.client_assertion.as_deref() else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        false,
                    );
                };
                if let Err(error) = validate_private_key_jwt(&state, &req, &client, assertion).await
                {
                    let store_unavailable = matches!(error, ClientAssertionError::StoreUnavailable);
                    let status = if store_unavailable {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::UNAUTHORIZED
                    };
                    let oauth_error_code = if store_unavailable {
                        "server_error"
                    } else {
                        "invalid_client"
                    };
                    return oauth_token_error(status, oauth_error_code, "客户端认证失败.", false);
                }
            }
            "client_secret_basic" | "client_secret_post" => {
                let Some(secret) = credentials.client_secret.as_deref() else {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "机密客户端必须提供 client_secret.",
                        has_basic,
                    );
                };
                if !verify_password(
                    secret,
                    client.client_secret_argon2_hash.as_deref().unwrap_or(""),
                ) {
                    return oauth_token_error(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        has_basic,
                    );
                }
            }
            _ => {
                return oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                    has_basic,
                );
            }
        }
    } else if credentials.method != "none"
        || credentials.client_secret.is_some()
        || credentials.client_assertion.is_some()
    {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "public 客户端不能使用 client_secret.",
            has_basic,
        );
    }
    match form.grant_type.as_str() {
        "authorization_code" => token_authorization_code(&state, &req, &client, &form).await,
        "refresh_token" => token_refresh(&state, &req, &client, &form).await,
        "client_credentials" => token_client_credentials(&state, &req, &client, &form).await,
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}
