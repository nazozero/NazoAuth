//! token introspection 端点。
// 只处理 access/refresh token 活跃性查询。
use super::{TokenOnlyForm, authenticate_token_management_client, token_management_auth_error};
use crate::http::prelude::*;

pub(crate) async fn introspect(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<TokenOnlyForm>,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }

    let has_basic = has_basic_authorization_scheme(req.headers());
    let has_assertion = form.client_assertion_type.is_some() || form.client_assertion.is_some();
    if has_basic && (form.client_id.is_some() || form.client_secret.is_some() || has_assertion)
        || has_assertion && form.client_secret.is_some()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
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
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    let Some(client) = find_client(&state.diesel_db, client_id)
        .await
        .ok()
        .flatten()
    else {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
    };
    if let Err(error) =
        authenticate_token_management_client(&state, &req, &client, &credentials).await
    {
        return token_management_auth_error(error);
    }
    if let Some(claims) = decode_access_claims(&state, &form.token) {
        if claims.client_id != client.client_id {
            return json_response(json!({"active": false}));
        }
        let revoked = match get_conn(&state.diesel_db).await {
            Ok(mut conn) => access_token_revocations::table
                .filter(
                    access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)),
                )
                .select(count_star())
                .first::<i64>(&mut conn)
                .await
                .map(|count| count > 0)
                .unwrap_or(false),
            Err(_) => false,
        };
        let active = !revoked && claims.exp > Utc::now().timestamp();
        return json_response(json!({
            "active": active,
            "scope": claims.scope,
            "client_id": claims.client_id,
            "token_type": "access_token",
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
        Ok(mut conn) => oauth_tokens::table
            .filter(oauth_tokens::refresh_token_blake3.eq(hash))
            .select(TokenRow::as_select())
            .first::<TokenRow>(&mut conn)
            .await
            .optional()
            .ok()
            .flatten(),
        Err(_) => None,
    };
    if let Some(token) = token {
        let active = token.client_id == client.id
            && token.revoked_at.is_none()
            && token.expires_at > Utc::now();
        return json_response(json!({
            "active": active,
            "scope": json_array_to_strings(&token.scopes).join(" "),
            "client_id": client.client_id,
            "token_type": "refresh_token",
            "exp": token.expires_at.timestamp(),
            "iat": token.issued_at.timestamp(),
            "sub": token.subject
        }));
    }
    json_response(json!({"active": false}))
}
