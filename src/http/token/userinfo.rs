//! OIDC userinfo 端点。
// 根据 Bearer/DPoP access token 返回用户声明；DPoP-bound token 必须携带有效 proof。
use crate::http::prelude::*;

pub(crate) async fn userinfo(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    let Some((scheme, token)) = userinfo_access_token(&req, &body) else {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
    };
    let Some(claims) = decode_access_claims(&state, &token) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        );
    };
    let revoked = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match access_token_revocations::table
            .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)))
            .select(count_star())
            .first::<i64>(&mut conn)
            .await
        {
            Ok(count) => count > 0,
            Err(error) => {
                tracing::warn!(%error, "failed to query userinfo token revocation state");
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "userinfo 查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to check userinfo token revocation");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    if revoked {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已撤销.");
    }
    let mut next_dpop_nonce = None;
    match (scheme, claims.cnf.as_ref()) {
        (AccessTokenAuthScheme::DPoP, Some(cnf)) if cnf.jkt.is_some() => {
            if let Err(error) =
                validate_dpop_proof(&state, &req, Some(&token), cnf.jkt.as_deref()).await
            {
                return dpop_error_response(error, DpopErrorContext::ProtectedResource);
            }
            next_dpop_nonce = match issue_dpop_nonce(&state).await {
                Ok(nonce) => Some(nonce),
                Err(error) => {
                    return dpop_error_response(error, DpopErrorContext::ProtectedResource);
                }
            };
        }
        (AccessTokenAuthScheme::DPoP, _) => {
            return dpop_error_response(
                DpopError::TokenNotBound,
                DpopErrorContext::ProtectedResource,
            );
        }
        (AccessTokenAuthScheme::Bearer, Some(cnf)) if cnf.x5t_s256.is_some() => {
            let expected = cnf.x5t_s256.as_deref().unwrap_or_default();
            let Some(actual) = request_mtls_thumbprint(&req) else {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token requires a verified client certificate.",
                );
            };
            if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                return oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token certificate mismatch.",
                );
            }
        }
        (AccessTokenAuthScheme::Bearer, Some(_)) => {
            return dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::ProtectedResource,
            );
        }
        (AccessTokenAuthScheme::Bearer, None) => {}
    }
    if !claims
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
        || claims.subject_type != "user"
    {
        return oauth_bearer_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "userinfo 需要 openid scope.",
        );
    }
    let scopes = parse_scope(&claims.scope);
    let user_identifier = claims.user_id.as_deref().unwrap_or(&claims.sub);
    let user_id = match Uuid::parse_str(user_identifier) {
        Ok(user_id) => user_id,
        Err(_) => {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌主体无效.",
            );
        }
    };
    let user = match find_user_by_id(&state.diesel_db, user_id).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌主体不存在或已停用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load userinfo subject");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    let mut response = json_response_no_store(oidc_user_claims(
        &user,
        &scopes,
        &claims.sub,
        &claims.userinfo_claims,
    ));
    if let Some(nonce) = next_dpop_nonce
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

fn userinfo_access_token(
    req: &HttpRequest,
    body: &Bytes,
) -> Option<(AccessTokenAuthScheme, String)> {
    if let Some((scheme, token)) = authorization_access_token(req.headers()) {
        return Some((scheme, token));
    }
    if req.method() != actix_web::http::Method::POST || body.is_empty() {
        return None;
    }
    let mut access_token = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "access_token" {
            if access_token.is_some() {
                return None;
            }
            let token = value.into_owned();
            if token.trim().is_empty() {
                return None;
            }
            access_token = Some(token);
        }
    }
    access_token.map(|token| (AccessTokenAuthScheme::Bearer, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_body_access_token_accepts_single_value() {
        let req = actix_web::test::TestRequest::post().to_http_request();
        let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

        let Some((AccessTokenAuthScheme::Bearer, token)) = token else {
            panic!("expected bearer token from form body");
        };
        assert_eq!(token, "token-1");
    }

    #[test]
    fn post_body_access_token_rejects_duplicate_value() {
        let req = actix_web::test::TestRequest::post().to_http_request();
        let token = userinfo_access_token(
            &req,
            &Bytes::from_static(b"access_token=token-1&access_token=token-2"),
        );

        assert!(token.is_none());
    }
}
