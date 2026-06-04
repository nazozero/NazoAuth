//! /token grant_type 分发入口。
// 只负责客户端认证与 grant_type 分派，不直接签发令牌。
use super::{
    TokenForm, TokenFormError, parse_token_form, token_authorization_code,
    token_client_credentials, token_refresh,
};
use crate::http::prelude::*;

fn pending_authorization_code_payload(raw: &str) -> Result<Option<CodePayload>, serde_json::Error> {
    match serde_json::from_str::<AuthorizationCodeState>(raw)? {
        AuthorizationCodeState::Pending { payload } => Ok(Some(payload)),
        _ => Ok(None),
    }
}

async fn missing_client_authorization_code_holder_error(
    state: &AppState,
    form: &TokenForm,
) -> Option<HttpResponse> {
    if form.grant_type != "authorization_code" {
        return None;
    }
    let code = form.code.as_deref()?;
    let raw = match valkey_get(&state.valkey, authorization_code_key(code)).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to read authorization code before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let payload = match pending_authorization_code_payload(&raw) {
        Ok(Some(payload)) => payload,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "authorization code state is malformed before client authentication");
            return Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码状态无效.",
                false,
            ));
        }
    };
    if payload.dpop_jkt.is_some() {
        return Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ));
    }
    match find_client(&state.diesel_db, &payload.client_id).await {
        Ok(Some(client)) if client.require_dpop_bound_tokens => Some(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        )),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization code client before client authentication");
            Some(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            ))
        }
    }
}

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
    let has_basic = has_basic_authorization_scheme(req.headers());
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
        if let Some(response) = missing_client_authorization_code_holder_error(&state, &form).await
        {
            return response;
        }
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            has_basic,
        );
    };
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端不存在或已停用.",
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token request");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
                false,
            );
        }
    };
    if !client.is_active || !json_array_to_strings(&client.grant_types).contains(&form.grant_type) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用当前授权类型.",
            false,
        );
    }
    let mut client_assertion = None;
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
                match verify_private_key_jwt_claims(&state, &req, &client, assertion) {
                    Ok(assertion) => client_assertion = Some(assertion),
                    Err(error) => {
                        let store_unavailable =
                            matches!(error, ClientAssertionError::StoreUnavailable);
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
                        return oauth_token_error(
                            status,
                            oauth_error_code,
                            "客户端认证失败.",
                            false,
                        );
                    }
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
        "authorization_code" => {
            token_authorization_code(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        "refresh_token" => {
            token_refresh(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        "client_credentials" => {
            token_client_credentials(&state, &req, &client, &form, client_assertion.as_ref()).await
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "不支持的 grant_type.",
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
        CodePayload {
            code_id: "code-id".to_owned(),
            user_id: Uuid::nil(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            redirect_uri_was_supplied: true,
            scopes: vec!["openid".to_owned()],
            nonce: None,
            auth_time: 1,
            amr: vec!["pwd".to_owned()],
            acr: None,
            userinfo_claims: Vec::new(),
            id_token_claims: Vec::new(),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    #[test]
    fn pending_authorization_code_detects_dpop_binding() {
        let raw = serde_json::to_string(&AuthorizationCodeState::Pending {
            payload: code_payload(Some("thumbprint")),
        })
        .expect("pending code should serialize");

        assert!(
            pending_authorization_code_payload(&raw)
                .expect("state should parse")
                .is_some_and(|payload| payload.dpop_jkt.is_some())
        );
    }

    #[test]
    fn non_dpop_or_non_pending_authorization_code_is_not_holder_bound() {
        let pending = serde_json::to_string(&AuthorizationCodeState::Pending {
            payload: code_payload(None),
        })
        .expect("pending code should serialize");
        let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
            failed_at: Utc::now(),
            error: "invalid_grant".to_owned(),
        })
        .expect("failed code should serialize");

        assert!(
            pending_authorization_code_payload(&pending)
                .expect("state should parse")
                .is_some_and(|payload| payload.dpop_jkt.is_none())
        );
        assert!(
            pending_authorization_code_payload(&failed)
                .expect("state should parse")
                .is_none()
        );
    }
}
