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
    let dpop_jkt = match validate_dpop_proof(state, req, None, None).await {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error),
    };
    let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
    let allowed = json_array_to_strings(&client.scopes);
    if !requested.is_empty() && !is_subset(&requested, &allowed) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
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
            user_id: None,
            subject: client.client_id.clone(),
            scopes,
            audience,
            nonce: None,
            include_refresh: false,
            rotation: None,
            dpop_jkt,
        },
    )
    .await
}
