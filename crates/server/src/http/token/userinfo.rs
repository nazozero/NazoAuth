//! OIDC userinfo 端点。
use super::ServerTokenService;
use crate::domain::AppState;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
use crate::settings::Settings;
use crate::support::{
    AccessTokenAuthScheme, DpopError, DpopErrorContext, JwePayloadKind, access_token_tenant_id,
    blake3_hex, client_jwe_key, constant_time_eq, dpop_error_response, encrypt_compact_jwe,
    issue_dpop_nonce, oidc_user_claims, parse_scope, request_mtls_thumbprint, sign_response_jwt,
    signing_algorithm_from_name, token_audience_contains, validate_dpop_proof,
};
#[cfg(test)]
use crate::support::{
    AccessTokenJwtInput, DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID,
    IssuedAccessToken, jwt_decoding_key_from_jwk, make_jwt,
};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::{Duration, Utc};
use nazo_auth::{Claims, OAuthClient};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{ResourceAccessToken, resource_access_token};
use nazo_http_actix::{json_response_no_store, oauth_bearer_error};
use serde_json::{Value, json};
use uuid::Uuid;
// 根据 Bearer/DPoP access token 返回用户声明；DPoP-bound token 必须携带有效 proof。
#[cfg(test)]
use super::access_token_subject_key;

pub(crate) async fn userinfo(
    state: Data<AppState>,
    token_service: Data<ServerTokenService>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (scheme, token) = match resource_access_token(&req, &body, false) {
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
    let claims = match token_service
        .decode_access_token(&state.settings.endpoint.issuer, &token)
        .await
    {
        Ok(Some(claims)) => claims,
        Ok(None) => {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌无效或已过期.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to decode userinfo access token");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    if !userinfo_audience_allowed(&state.settings, &claims.aud) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于 userinfo.",
        );
    }
    let Some(tenant_id) = access_token_tenant_id(&claims) else {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        );
    };
    let revoked = match token_service
        .access_token_revoked(tenant_id, &claims.jti)
        .await
    {
        Ok(revoked) => revoked,
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
            let Some(actual) = request_mtls_thumbprint(&req, &state.settings) else {
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
    let user_id = match access_token_user_id(&token_service, tenant_id, &claims).await {
        Ok(Some(user_id)) => user_id,
        Ok(None) => {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌主体无效.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load access token subject mapping");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    if nazo_identity::TenantId::new(tenant_id).is_err()
        || nazo_identity::UserId::new(user_id).is_err()
    {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌主体不存在或已停用.",
        );
    }
    let subject_claims = match token_service
        .active_subject_claims(tenant_id, user_id)
        .await
    {
        Ok(Some(claims)) => claims,
        Ok(None) => {
            return oauth_bearer_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "访问令牌主体不存在或已停用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load userinfo subject claims");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    let client = match token_service
        .client_by_protocol_id(tenant_id, &claims.client_id)
        .await
    {
        Ok(Some(client)) if client.is_active => client,
        Ok(_) => {
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 客户端状态不可用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to load userinfo client response policy");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 查询失败.",
            );
        }
    };
    let response_claims = oidc_user_claims(
        &subject_claims,
        &scopes,
        &claims.sub,
        &claims.userinfo_claims,
        &claims.userinfo_claim_requests,
        None,
    );
    let mut response = match userinfo_success_response(&state, &client, response_claims).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, client_id_hash = %blake3_hex(&client.client_id), "failed to protect userinfo response");
            return oauth_bearer_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "userinfo 响应生成失败.",
            );
        }
    };
    if let Some(nonce) = next_dpop_nonce
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

async fn userinfo_success_response(
    state: &AppState,
    client: &OAuthClient,
    mut claims: Value,
) -> anyhow::Result<HttpResponse> {
    let signing_alg = match client.userinfo_signed_response_alg.as_deref() {
        Some(value) => Some(
            signing_algorithm_from_name(value)
                .ok_or_else(|| anyhow::anyhow!("unsupported UserInfo signing algorithm"))?,
        ),
        None => None,
    };
    let encryption_key = client_jwe_key(
        client.jwks.as_ref(),
        client.userinfo_encrypted_response_alg.as_deref(),
        client.userinfo_encrypted_response_enc.as_deref(),
        "userinfo",
    )?;
    if signing_alg.is_none() && encryption_key.is_none() {
        return Ok(json_response_no_store(claims));
    }

    let body = if let Some(signing_alg) = signing_alg {
        let object = claims
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("UserInfo claims must be a JSON object"))?;
        object.insert("iss".to_owned(), json!(state.settings.endpoint.issuer));
        object.insert("aud".to_owned(), json!(client.client_id));
        let signed = sign_response_jwt(
            state,
            nazo_auth::SigningPurpose::IdToken,
            &claims,
            "JWT",
            Some(signing_alg),
        )
        .await?;
        match encryption_key {
            Some(key) => encrypt_compact_jwe(&key, signed.as_bytes(), JwePayloadKind::NestedJwt)?,
            None => signed,
        }
    } else {
        let key = encryption_key.expect("checked UserInfo encryption key is present");
        encrypt_compact_jwe(&key, &serde_json::to_vec(&claims)?, JwePayloadKind::Claims)?
    };

    Ok(HttpResponse::Ok()
        .insert_header((
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/jwt"),
        ))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .body(body))
}

async fn access_token_user_id(
    token_service: &ServerTokenService,
    tenant_id: Uuid,
    claims: &Claims,
) -> anyhow::Result<Option<Uuid>> {
    if let Some(user_id) = claims
        .user_id
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        return Ok(Some(user_id));
    }
    token_service
        .load_access_token_subject(tenant_id, &claims.jti)
        .await
        .map_err(anyhow::Error::from)
}

fn userinfo_audience_allowed(settings: &Settings, audience: &Value) -> bool {
    let userinfo_url = format!(
        "{}/userinfo",
        settings.endpoint.issuer.trim_end_matches('/')
    );
    token_audience_contains(audience, &settings.protocol.default_audience)
        || token_audience_contains(audience, &userinfo_url)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/userinfo.rs"]
mod tests;
