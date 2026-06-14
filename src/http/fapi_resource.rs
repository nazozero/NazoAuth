//! FAPI-style protected resource endpoint.
//! Enforces RFC 6750 access-token transport rules plus sender-constrained token binding.
use crate::domain::Claims;
use crate::http::prelude::*;

pub(crate) async fn fapi_resource(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (scheme, token) = match resource_access_token(&req, &body) {
        ResourceAccessToken::Present(scheme, token) => (scheme, token),
        ResourceAccessToken::Missing => {
            return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
        }
        ResourceAccessToken::InvalidRequest => {
            return oauth_bearer_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Only one access token transport method may be used.",
            );
        }
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
    if !fapi_resource_audience_allowed(&state.settings, &claims.aud) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于该资源.",
        );
    }
    let Some(tenant_id) = access_token_tenant_id(&claims) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        );
    };
    let revoked = match get_conn(&state.diesel_db).await {
        Ok(mut conn) => match access_token_revocations::table
            .filter(access_token_revocations::tenant_id.eq(tenant_id))
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
            let Some(actual) = request_mtls_thumbprint(req, &state.settings) else {
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

fn fapi_resource_audience_allowed(settings: &Settings, audience: &Value) -> bool {
    let resource_url = format!("{}/fapi/resource", settings.issuer.trim_end_matches('/'));
    token_audience_contains(audience, &settings.default_audience)
        || token_audience_contains(audience, &resource_url)
}

enum ResourceAccessToken {
    Present(AccessTokenAuthScheme, String),
    Missing,
    InvalidRequest,
}

fn resource_access_token(req: &HttpRequest, body: &Bytes) -> ResourceAccessToken {
    let header_token = authorization_access_token(req.headers());
    let body_token = resource_form_body_access_token(req, body);

    match (header_token, body_token) {
        (Some(_), ResourceFormBodyAccessToken::Present(_)) => ResourceAccessToken::InvalidRequest,
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, token),
        (None, ResourceFormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, ResourceFormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, ResourceFormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    }
}

enum ResourceFormBodyAccessToken {
    Present(String),
    Missing,
    InvalidRequest,
}

fn resource_form_body_access_token(req: &HttpRequest, body: &Bytes) -> ResourceFormBodyAccessToken {
    if req.method() != actix_web::http::Method::POST
        || body.is_empty()
        || !request_uses_form_urlencoded(req)
    {
        return ResourceFormBodyAccessToken::Missing;
    }
    let mut access_token = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "access_token" {
            if access_token.is_some() {
                return ResourceFormBodyAccessToken::InvalidRequest;
            }
            let token = value.into_owned();
            if token.trim().is_empty() {
                return ResourceFormBodyAccessToken::Missing;
            }
            access_token = Some(token);
        }
    }
    access_token
        .map(ResourceFormBodyAccessToken::Present)
        .unwrap_or(ResourceFormBodyAccessToken::Missing)
}

#[cfg(test)]
#[path = "tests/fapi_resource.rs"]
mod tests;
