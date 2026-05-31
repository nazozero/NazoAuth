//! token introspection 端点。
// 只处理 access/refresh token 活跃性查询。
use super::TokenOnlyForm;
use crate::http::prelude::*;

pub(crate) async fn introspect(
    state: Data<AppState>,
    req: HttpRequest,
    Form(form): Form<TokenOnlyForm>,
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
            "客户端认证失败.",
        );
    };
    if client.client_type == "confidential"
        && (method != client.token_endpoint_auth_method
            || !verify_password(
                client_secret.as_deref().unwrap_or(""),
                client.client_secret_argon2_hash.as_deref().unwrap_or(""),
            ))
    {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        );
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
