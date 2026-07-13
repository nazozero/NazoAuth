//! token introspection 端点。
use crate::domain::ClientRow;
#[cfg(test)]
use crate::support::{
    AccessTokenJwtInput, DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, IssuedAccessToken, blake3_hex,
    jwt_decoding_key_from_jwk, make_jwt,
};
use crate::support::{
    ClientJweKey, JwePayloadKind, client_ip_with_config, client_jwe_key, encrypt_compact_jwe,
    extract_client_credentials_with_trusted_proxies, has_basic_authorization_scheme,
    rate_limited_response,
};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Duration;
use chrono::Utc;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::json_response_no_store;
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;
// 只处理 access/refresh token 活跃性查询。
use super::{
    ServerTokenService, TokenManagementClientAuthError,
    authenticate_introspection_client_with_dependencies, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use nazo_auth::{IntrospectionSignInput, TokenInspection};

use crate::http::authorization::{AuthorizationHttpConfig, ServerAuthorizationService};

const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub(crate) async fn introspect(
    token_service: Data<ServerTokenService>,
    authorization_service: Data<ServerAuthorizationService>,
    config: Data<AuthorizationHttpConfig>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let subject = client_ip_with_config(&req, &config.client_ip);
    match token_service
        .increment_token_management_rate(&subject, config.rate_limit_window_seconds)
        .await
    {
        Ok(count) if count > config.token_management_max_requests => {
            return rate_limited_response(config.rate_limit_window_seconds);
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "token introspection rate limit increment failed");
            return nazo_http_actix::oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            );
        }
    }
    introspect_after_rate_limit_with_dependencies(
        &token_service,
        &authorization_service,
        &config,
        req,
        body,
    )
    .await
}

async fn introspect_after_rate_limit_with_dependencies(
    token_service: &ServerTokenService,
    authorization_service: &ServerAuthorizationService,
    config: &AuthorizationHttpConfig,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let form = match parse_token_management_form(&req, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };

    let has_basic = has_basic_authorization_scheme(req.headers());
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    let credentials = extract_client_credentials_with_trusted_proxies(
        &req,
        &config.trusted_proxy_cidrs,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    let Some(client_id) = credentials.client_id.as_deref() else {
        return token_management_client_auth_error(
            TokenManagementClientAuthError::InvalidClient,
            has_basic,
        );
    };
    let client = match authorization_service.client_by_id(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            super::client_auth::perform_dummy_client_secret_verification(
                &credentials,
                &config.client_secret_pepper,
            );
            return token_management_client_auth_error(
                TokenManagementClientAuthError::InvalidClient,
                has_basic,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client for token introspection");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_introspection_client_with_dependencies(
        authorization_service,
        super::client_auth::ClientAuthConfig::new(
            &config.issuer,
            &config.client_secret_pepper,
            &config.trusted_proxy_cidrs,
        ),
        &req,
        &client,
        &credentials,
    )
    .await
    {
        return token_management_client_auth_error(error, has_basic);
    }
    let use_signed_response =
        signed_introspection_requested(&req) && config.profile.requires_signed_introspection();
    let inspection = match token_service
        .inspect_token(&config.issuer, &form.token, &client, Utc::now())
        .await
    {
        Ok(inspection) => inspection,
        Err(error) => {
            tracing::warn!(%error, "failed to inspect token state");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 状态查询失败.",
            );
        }
    };
    let response_body = inspection_body(inspection);
    introspection_response(
        token_service,
        &config.issuer,
        &client,
        response_body,
        use_signed_response,
    )
    .await
}

fn inspection_body(inspection: TokenInspection) -> Value {
    match inspection {
        TokenInspection::Inactive => json!({"active": false}),
        TokenInspection::ActiveAccess {
            scope,
            client_id,
            token_type,
            expires_at,
            issued_at,
            not_before,
            subject,
            audience,
            issuer,
            jti,
        } => json!({
            "active": true,
            "scope": scope,
            "client_id": client_id,
            "token_type": token_type,
            "exp": expires_at,
            "iat": issued_at,
            "nbf": not_before,
            "sub": subject,
            "aud": audience,
            "iss": issuer,
            "jti": jti,
        }),
        TokenInspection::ActiveRefresh {
            scope,
            client_id,
            expires_at,
            issued_at,
            subject,
        } => json!({
            "active": true,
            "scope": scope,
            "client_id": client_id,
            "exp": expires_at,
            "iat": issued_at,
            "sub": subject,
        }),
    }
}

fn signed_introspection_requested(req: &HttpRequest) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim() == TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
                })
            })
        })
}

async fn introspection_response(
    token_service: &ServerTokenService,
    issuer: &str,
    resource_server: &ClientRow,
    body: Value,
    signed: bool,
) -> HttpResponse {
    if !signed {
        return json_response_no_store(body);
    }
    match signed_introspection_response_with_service(token_service, issuer, resource_server, body)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "failed to build token introspection JWT response");
            token_management_oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "token introspection JWT response build failed.",
            )
        }
    }
}

async fn signed_introspection_response_with_service(
    token_service: &ServerTokenService,
    issuer: &str,
    resource_server: &ClientRow,
    body: Value,
) -> anyhow::Result<HttpResponse> {
    let token = token_service
        .sign_introspection_response(IntrospectionSignInput {
            issuer,
            audience: &resource_server.client_id,
            body: &body,
        })
        .await?;
    let token = match introspection_encryption_key(resource_server)? {
        Some(key) => encrypt_compact_jwe(&key, token.as_bytes(), JwePayloadKind::NestedJwt)?,
        None => token,
    };
    Ok(HttpResponse::Ok()
        .insert_header((
            header::CONTENT_TYPE,
            HeaderValue::from_static(TOKEN_INTROSPECTION_JWT_MEDIA_TYPE),
        ))
        .insert_header((header::CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .insert_header((header::PRAGMA, HeaderValue::from_static("no-cache")))
        .body(token))
}

fn introspection_encryption_key(
    resource_server: &ClientRow,
) -> anyhow::Result<Option<ClientJweKey<'_>>> {
    client_jwe_key(
        resource_server.jwks.as_ref(),
        resource_server
            .introspection_encrypted_response_alg
            .as_deref(),
        resource_server
            .introspection_encrypted_response_enc
            .as_deref(),
        "introspection",
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/introspect.rs"]
mod tests;
