//! authorization_code grant 处理。
// 只消费授权码并转入统一令牌签发逻辑。
use super::{TokenForm, issue_token_response, revoke_issued_authorization_code_tokens};
use crate::http::prelude::*;

fn redirect_uri_matches_authorization_request(
    payload: &CodePayload,
    token_redirect_uri: Option<&str>,
) -> bool {
    match (payload.redirect_uri_was_supplied, token_redirect_uri) {
        (true, Some(value)) => value == payload.redirect_uri.as_str(),
        (true, None) => false,
        (false, Some(value)) => value == payload.redirect_uri.as_str(),
        (false, None) => true,
    }
}

async fn revoke_replayed_authorization_code(
    state: &AppState,
    code: &str,
) -> Result<bool, HttpResponse> {
    let raw = match valkey_get(&state.valkey, consumed_authorization_code_key(code)).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to read consumed authorization code marker");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码重放状态读取失败.",
                false,
            ));
        }
    };
    let Some(raw) = raw else {
        return Ok(false);
    };
    let payload = match serde_json::from_str::<ConsumedAuthorizationCode>(&raw) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(%error, "consumed authorization code marker is malformed");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码重放状态无效.",
                false,
            ));
        }
    };
    if let Err(error) = revoke_issued_authorization_code_tokens(
        state,
        payload.client_id,
        &payload.access_token_jti,
        payload.access_token_expires_at,
        payload.refresh_token_family_id,
    )
    .await
    {
        tracing::warn!(%error, "failed to revoke tokens after authorization code replay");
        return Err(oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码重放撤销失败.",
            false,
        ));
    }
    Ok(true)
}

pub(crate) async fn token_authorization_code(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    let Some(code) = &form.code else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code.",
            false,
        );
    };
    let key = authorization_code_key(code);
    let raw = match valkey_get(&state.valkey, &key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to consume authorization code");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            );
        }
    };
    let Some(payload) = raw.and_then(|v| serde_json::from_str::<CodePayload>(&v).ok()) else {
        match revoke_replayed_authorization_code(state, code).await {
            Ok(true) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码已被使用，相关令牌已撤销.",
                    false,
                );
            }
            Ok(false) => {}
            Err(response) => return response,
        }
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码无效或已过期.",
            false,
        );
    };
    if payload.client_id != client.client_id
        || !redirect_uri_matches_authorization_request(&payload, form.redirect_uri.as_deref())
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码与客户端或 redirect_uri 不匹配.",
            false,
        );
    }
    let Some(verifier) = &form.code_verifier else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code_verifier.",
            false,
        );
    };
    if payload.code_challenge_method != "S256"
        || !is_valid_pkce_value(verifier)
        || pkce_s256(verifier) != payload.code_challenge
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE 校验失败.",
            false,
        );
    }
    match valkey_getdel(&state.valkey, &key).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "授权码无效或已过期.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to consume authorization code");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            );
        }
    }
    let audience = form
        .audience
        .clone()
        .unwrap_or_else(|| state.settings.default_audience.clone());
    if !audience_allowed(client, &audience) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    issue_token_response(
        state,
        client,
        TokenIssue {
            user_id: Some(payload.user_id),
            subject: payload.user_id.to_string(),
            scopes: payload.scopes,
            audience,
            nonce: payload.nonce,
            include_refresh: true,
            rotation: None,
            dpop_jkt,
            authorization_code_hash: Some(blake3_hex(code)),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_payload(redirect_uri_was_supplied: bool) -> CodePayload {
        let now = Utc::now();
        CodePayload {
            code_id: "code-1".to_owned(),
            user_id: Uuid::now_v7(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            redirect_uri_was_supplied,
            scopes: vec!["openid".to_owned()],
            nonce: None,
            code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned(),
            code_challenge_method: "S256".to_owned(),
            issued_at: now,
            expires_at: now + Duration::seconds(300),
        }
    }

    #[test]
    fn token_redirect_uri_is_required_when_authorize_request_supplied_it() {
        let payload = code_payload(true);

        assert!(!redirect_uri_matches_authorization_request(&payload, None));
        assert!(redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback")
        ));
        assert!(!redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback/")
        ));
    }

    #[test]
    fn token_redirect_uri_may_be_omitted_when_authorize_request_used_single_registered_uri() {
        let payload = code_payload(false);

        assert!(redirect_uri_matches_authorization_request(&payload, None));
        assert!(redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback")
        ));
        assert!(!redirect_uri_matches_authorization_request(
            &payload,
            Some("https://client.example/callback/")
        ));
    }
}
