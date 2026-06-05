//! Minimal FAPI protected resource used by conformance runs.
use crate::domain::Claims;
use crate::http::prelude::*;

pub(crate) async fn fapi_resource(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let Some((scheme, token)) = resource_access_token(&req, &body) else {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
    };
    let Some(claims) = decode_access_claims(&state, &token) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        );
    };
    if let Err(response) =
        validate_access_token_binding(&state, &req, &token, scheme, &claims).await
    {
        return response;
    }
    let revoked = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match access_token_revocations::table
            .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(&claims.jti)))
            .select(count_star())
            .first::<i64>(&mut conn)
            .await
        {
            Ok(count) => count > 0,
            Err(error) => {
                tracing::warn!(%error, "failed to query FAPI resource token revocation state");
                return oauth_bearer_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "resource 查询失败.",
                );
            }
        },
        Err(error) => {
            tracing::warn!(%error, "failed to check FAPI resource token revocation");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "resource 查询失败.",
            );
        }
    };
    if revoked || claims.exp <= Utc::now().timestamp() {
        return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已失效.");
    }
    json_response_no_store(json!({
        "sub": claims.sub,
        "client_id": claims.client_id,
        "scope": claims.scope,
        "aud": claims.aud
    }))
}

async fn validate_access_token_binding(
    state: &AppState,
    req: &HttpRequest,
    token: &str,
    scheme: AccessTokenAuthScheme,
    claims: &Claims,
) -> Result<(), HttpResponse> {
    match (scheme, claims.cnf.as_ref()) {
        (AccessTokenAuthScheme::DPoP, Some(cnf)) if cnf.jkt.is_some() => {
            validate_dpop_proof(state, req, Some(token), cnf.jkt.as_deref())
                .await
                .map_err(|error| dpop_error_response(error, DpopErrorContext::ProtectedResource))?;
        }
        (AccessTokenAuthScheme::DPoP, _) => {
            return Err(dpop_error_response(
                DpopError::TokenNotBound,
                DpopErrorContext::ProtectedResource,
            ));
        }
        (AccessTokenAuthScheme::Bearer, Some(cnf)) if cnf.x5t_s256.is_some() => {
            let expected = cnf.x5t_s256.as_deref().unwrap_or_default();
            let Some(actual) = request_mtls_thumbprint(req) else {
                return Err(oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token requires a verified client certificate.",
                ));
            };
            if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                return Err(oauth_bearer_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "mTLS-bound access token certificate mismatch.",
                ));
            }
        }
        (AccessTokenAuthScheme::Bearer, Some(_)) => {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::ProtectedResource,
            ));
        }
        (AccessTokenAuthScheme::Bearer, None) => {}
    }
    Ok(())
}

fn resource_access_token(
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
