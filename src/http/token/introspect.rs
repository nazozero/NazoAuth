//! token introspection 端点。
// 只处理 access/refresh token 活跃性查询。
use super::{
    authenticate_introspection_client, parse_token_management_form, token_management_auth_error,
    token_management_form_error,
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
    let client = match find_client(&state.diesel_db, client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token introspection");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_introspection_client(&state, &req, &client, &credentials).await
    {
        return token_management_auth_error(error);
    }
    if let Some(claims) = decode_access_claims(&state, &form.token) {
        if claims.client_id != client.client_id && !audience_allowed(&client, &claims.aud) {
            return json_response_no_store(json!({"active": false}));
        }
        let revoked = match get_conn(&state.diesel_db).await {
            Ok(mut conn) => match access_token_revocations::table
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
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "token 状态查询失败.",
                    );
                }
            },
            Err(error) => {
                tracing::warn!(%error, "failed to get database connection for introspection");
                return oauth_error(
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
            .filter(oauth_tokens::refresh_token_blake3.eq(hash))
            .select(TokenRow::as_select())
            .first::<TokenRow>(&mut conn)
            .await
            .optional()
        {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to query refresh token introspection state");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 状态查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to get database connection for introspection");
            return oauth_error(
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
        return json_response_no_store(json!({
            "active": active,
            "scope": json_array_to_strings(&token.scopes).join(" "),
            "client_id": client.client_id,
            "token_type": "refresh_token",
            "exp": token.expires_at.timestamp(),
            "iat": token.issued_at.timestamp(),
            "sub": token.subject
        }));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ConfirmationClaims;

    fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
        Claims {
            iss: "https://as.example".to_owned(),
            sub: "subject".to_owned(),
            user_id: None,
            subject_type: "client".to_owned(),
            aud: "resource://default".to_owned(),
            client_id: "client-1".to_owned(),
            scope: "openid".to_owned(),
            token_use: "access".to_owned(),
            jti: "jti-1".to_owned(),
            iat: 1,
            nbf: 1,
            exp: 2,
            cnf,
            userinfo_claims: Vec::new(),
        }
    }

    #[test]
    fn access_token_introspection_type_matches_issued_bearer_token_type() {
        assert_eq!(
            introspection_access_token_type(&access_claims(None)),
            "Bearer"
        );
    }

    #[test]
    fn access_token_introspection_type_matches_issued_dpop_token_type() {
        let claims = access_claims(Some(ConfirmationClaims {
            jkt: Some("thumbprint".to_owned()),
            x5t_s256: None,
        }));

        assert_eq!(introspection_access_token_type(&claims), "DPoP");
    }

    #[test]
    fn mtls_bound_access_token_introspection_type_remains_bearer() {
        let claims = access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("certificate-thumbprint".to_owned()),
        }));

        assert_eq!(introspection_access_token_type(&claims), "Bearer");
    }
}
