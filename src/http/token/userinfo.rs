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
    match (scheme, claims.cnf.as_ref()) {
        (AccessTokenAuthScheme::DPoP, Some(cnf)) => {
            if let Err(error) =
                validate_dpop_proof(&state, &req, Some(&token), Some(&cnf.jkt)).await
            {
                return dpop_error_response(error);
            }
        }
        (AccessTokenAuthScheme::DPoP, None) => {
            return dpop_error_response(DpopError::TokenNotBound);
        }
        (AccessTokenAuthScheme::Bearer, Some(_)) => {
            return dpop_error_response(DpopError::MissingProof);
        }
        (AccessTokenAuthScheme::Bearer, None) => {}
    }
    if !claims
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        return oauth_bearer_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "userinfo 需要 openid scope.",
        );
    }
    let preferred_username = match Uuid::parse_str(&claims.sub) {
        Ok(user_id) => match find_user_by_id(&state.diesel_db, user_id).await {
            Ok(user) => user.map(|user| user.email),
            Err(error) => {
                tracing::warn!(%error, "failed to load userinfo subject");
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "userinfo 查询失败.",
                );
            }
        },
        Err(_) => None,
    };
    json_response(json!({
        "sub": claims.sub,
        "preferred_username": preferred_username
    }))
}
