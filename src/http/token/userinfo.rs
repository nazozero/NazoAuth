//! OIDC userinfo 端点。
// 根据 Bearer/DPoP access token 返回用户声明；DPoP-bound token 必须携带有效 proof。
use crate::http::prelude::*;

pub(crate) async fn userinfo(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let Some((scheme, token)) = authorization_access_token(req.headers()) else {
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
    match (scheme, claims.cnf.as_ref()) {
        (AccessTokenAuthScheme::DPoP, Some(cnf)) => {
            if let Err(error) =
                validate_dpop_proof(&state, &req, Some(&token), Some(&cnf.jkt)).await
            {
                return dpop_error_response(error, DpopErrorContext::ProtectedResource);
            }
        }
        (AccessTokenAuthScheme::DPoP, None) => {
            return dpop_error_response(
                DpopError::TokenNotBound,
                DpopErrorContext::ProtectedResource,
            );
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
    let user_id = match Uuid::parse_str(&claims.sub) {
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
    json_response(oidc_user_claims(&user, &scopes, &claims.sub))
}
