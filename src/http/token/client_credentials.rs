//! client_credentials grant 处理。
// 只为机密客户端签发无用户主体的访问令牌。
use super::{TokenForm, consume_token_client_assertion, issue_token_response};
use crate::http::prelude::*;

pub(crate) async fn token_client_credentials(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
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
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint(req, &state.settings) {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client_credentials requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
    };
    if let Err(response) = consume_token_client_assertion(state, client, client_assertion).await {
        return response;
    }
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
    let audiences = if form.audiences.is_empty() {
        vec![state.settings.default_audience.clone()]
    } else {
        form.audiences.clone()
    };
    if !audiences_allowed(client, &audiences) {
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
            authorization_details: json!([]),
            audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: false,
            rotation: None,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
        },
    )
    .await
}
