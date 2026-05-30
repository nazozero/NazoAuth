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
    if let Some(cnf) = claims.cnf.as_ref() {
        if !matches!(scheme, AccessTokenAuthScheme::DPoP) {
            return dpop_error_response(DpopError::MissingProof);
        }
        if let Err(error) = validate_dpop_proof(&state, &req, Some(&token), Some(&cnf.jkt)).await {
            return dpop_error_response(error);
        }
    }
    if !claims.scope.split_whitespace().any(|scope| scope == "openid") {
        return oauth_bearer_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "userinfo 需要 openid scope.",
        );
    }
    let preferred_username = match Uuid::parse_str(&claims.sub) {
        Ok(user_id) => find_user_by_id(&state.diesel_db, user_id)
            .await
            .ok()
            .flatten()
            .map(|user| user.email),
        Err(_) => None,
    };
    json_response(json!({
        "sub": claims.sub,
        "preferred_username": preferred_username
    }))
}
