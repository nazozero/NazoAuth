//! client_credentials grant 处理。
// 只为机密客户端签发无用户主体的访问令牌。
use super::{TokenForm, issue_token_response};
use crate::http::prelude::*;

pub(crate) async fn token_client_credentials(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    if client.client_type != "confidential" {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "client_credentials 只允许机密客户端使用.",
            false,
        );
    }
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
    let allowed = json_array_to_strings(&client.scopes);
    if !requested.is_empty() && !is_subset(&requested, &allowed) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
            false,
        );
    }
    let scopes = if requested.is_empty() {
        allowed
    } else {
        requested
    };
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
            user_id: None,
            subject: client.client_id.clone(),
            scopes,
            audience,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            include_refresh: false,
            rotation: None,
            dpop_jkt,
            authorization_code_hash: None,
        },
    )
    .await
}
