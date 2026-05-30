//! authorization_code grant 处理。
// 只消费授权码并转入统一令牌签发逻辑。
use super::{TokenForm, issue_token_response};
use crate::http::prelude::*;

pub(crate) async fn token_authorization_code(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error),
    };
    let Some(code) = &form.code else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "缺少 code.");
    };
    let key = format!("oauth:auth_code:{code}");
    let raw = match valkey_getdel(&state.valkey, &key).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to consume authorization code");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
            );
        }
    };
    let Some(payload) = raw.and_then(|v| serde_json::from_str::<CodePayload>(&v).ok()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码无效或已过期.",
        );
    };
    if payload.client_id != client.client_id
        || form.redirect_uri.as_deref() != Some(payload.redirect_uri.as_str())
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "授权码与客户端或 redirect_uri 不匹配.",
        );
    }
    let Some(verifier) = &form.code_verifier else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code_verifier.",
        );
    };
    if pkce_s256(verifier) != payload.code_challenge {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE 校验失败.");
    }
    let audience = form
        .audience
        .clone()
        .unwrap_or_else(|| state.settings.default_audience.clone());
    if !audience_allowed(client, &audience) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
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
        },
    )
    .await
}
