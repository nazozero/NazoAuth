//! token introspection 端点。
// 只处理 access/refresh token 活跃性查询。
use super::{
    TokenManagementClientAuthError, authenticate_introspection_client, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use crate::domain::Claims;
use crate::http::prelude::*;

pub(crate) async fn introspect(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    let form = match parse_token_management_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };

    let has_basic = has_basic_authorization_scheme(req.headers());
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    let credentials = extract_client_credentials(
        &req,
        &state.settings,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return token_management_client_auth_error(
            TokenManagementClientAuthError::InvalidClient,
            has_basic,
        );
    };
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return token_management_client_auth_error(
                TokenManagementClientAuthError::InvalidClient,
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token introspection");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_introspection_client(&state, &req, &client, &credentials).await
    {
        return token_management_client_auth_error(error, has_basic);
    }
    if let Some(claims) = decode_access_claims(&state, &form.token) {
        if claims.client_id != client.client_id && !token_audience_allowed(&client, &claims.aud) {
            return json_response_no_store(json!({"active": false}));
        }
        if access_token_tenant_id(&claims) != Some(client.tenant_id) {
            return json_response_no_store(json!({"active": false}));
        }
        let revoked = match get_conn(&state.diesel_db).await {
            Ok(mut conn) => match access_token_revocations::table
                .filter(access_token_revocations::tenant_id.eq(client.tenant_id))
                .filter(
                    access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                )
                .select(count_star())
                .first::<i64>(&mut conn)
                .await
            {
                Ok(count) => count > 0,
                Err(error) => {
                    tracing::warn!(%error, "failed to query access token revocation state");
                    return token_management_oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "token 状态查询失败.",
                    );
                }
            },
            Err(error) => {
                tracing::warn!(%error, "failed to get database connection for introspection");
                return token_management_oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 状态查询失败.",
                );
            }
        };
        let active = !revoked && claims.exp > Utc::now().timestamp();
        if !active {
            return json_response_no_store(json!({"active": false}));
        }
        return json_response_no_store(json!({
            "active": active,
            "scope": claims.scope,
            "client_id": claims.client_id,
            "token_type": introspection_access_token_type(&claims),
            "exp": claims.exp,
            "iat": claims.iat,
            "nbf": claims.nbf,
            "sub": claims.sub,
            "aud": claims.aud,
            "iss": claims.iss,
            "jti": claims.jti
        }));
    }
    let hash = blake3_hex(&form.token);
    let token = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
            .filter(oauth_tokens::refresh_token_blake3.eq(hash))
            .select(TokenRow::as_select())
            .first::<TokenRow>(&mut conn)
            .await
            .optional()
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to query refresh token introspection state");
                return token_management_oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 状态查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for introspection");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 状态查询失败.",
            );
        }
    };
    if let Some(token) = token {
        if token.client_id != client.id {
            return json_response_no_store(json!({"active": false}));
        }
        let active = token.revoked_at.is_none() && token.expires_at > Utc::now();
        if !active {
            return json_response_no_store(json!({"active": false}));
        }
        return json_response_no_store(active_refresh_token_introspection_body(
            &token,
            &client.client_id,
        ));
    }
    json_response_no_store(json!({"active": false}))
}

fn introspection_access_token_type(claims: &Claims) -> &'static str {
    if claims
        .cnf
        .as_ref()
        .and_then(|cnf| cnf.jkt.as_ref())
        .is_some()
    {
        "DPoP"
    } else {
        "Bearer"
    }
}

fn active_refresh_token_introspection_body(token: &TokenRow, client_id: &str) -> Value {
    json!({
        "active": true,
        "scope": json_array_to_strings(&token.scopes).join(" "),
        "client_id": client_id,
        "exp": token.expires_at.timestamp(),
        "iat": token.issued_at.timestamp(),
        "sub": token.subject
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/src/http/token/tests/introspect.rs"]
mod tests;
