//! token introspection 端点。
use crate::domain::{AppState, ClientRow, TokenRow};
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::{
    AccessTokenJwtInput, DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, IssuedAccessToken, blake3_hex,
    jwt_decoding_key_from_jwk, make_jwt,
};
use crate::support::{
    ClientJweKey, DEFAULT_TENANT_ID, JwePayloadKind, RateLimitPolicy, access_token_tenant_id,
    client_jwe_key, decode_access_claims, encrypt_compact_jwe, enforce_rate_limit,
    extract_client_credentials, has_basic_authorization_scheme, json_array_to_strings,
    token_audience_allowed,
};
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
#[cfg(test)]
use chrono::{DateTime, Duration};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::json_response_no_store;
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;
// 只处理 access/refresh token 活跃性查询。
use super::{
    TokenManagementClientAuthError, authenticate_introspection_client, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use nazo_auth::Claims;

const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub(crate) async fn introspect(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    introspect_after_rate_limit(state, req, body).await
}

pub(crate) async fn introspect_after_rate_limit(
    state: Data<AppState>,
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
    let credentials = extract_client_credentials(
        &req,
        &state.settings,
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
    let client = match nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
        .by_client_id(DEFAULT_TENANT_ID, client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => {
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
    if let Err(error) = authenticate_introspection_client(&state, &req, &client, &credentials).await
    {
        return token_management_client_auth_error(error, has_basic);
    }
    let use_signed_response = signed_introspection_requested(&req)
        && state
            .settings
            .protocol
            .authorization_server_profile
            .requires_signed_introspection();
    let token_repository = nazo_postgres::TokenRepository::new(state.diesel_db.clone());
    if let Some(claims) = decode_access_claims(&state, &form.token) {
        if claims.client_id != client.client_id && !token_audience_allowed(&client, &claims.aud) {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        if access_token_tenant_id(&claims) != Some(client.tenant_id) {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        let revoked = match token_repository
            .access_token_revoked(client.tenant_id, &claims.jti)
            .await
        {
            Ok(revoked) => revoked,
            Err(error) => {
                tracing::warn!(%error, "failed to query access token revocation state");
                return token_management_oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "token 状态查询失败.",
                );
            }
        };
        let active = !revoked && claims.exp > Utc::now().timestamp();
        if !active {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        return introspection_response(
            &state,
            &client,
            json!({
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
            }),
            use_signed_response,
        )
        .await;
    }
    let token = match token_repository
        .by_raw_refresh_token(client.tenant_id, &form.token)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "failed to query refresh token introspection state");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 状态查询失败.",
            );
        }
    };
    if let Some(token) = token {
        if token.client_id != client.id {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        let active = token.revoked_at.is_none() && token.expires_at > Utc::now();
        if !active {
            return introspection_response(
                &state,
                &client,
                json!({"active": false}),
                use_signed_response,
            )
            .await;
        }
        return introspection_response(
            &state,
            &client,
            active_refresh_token_introspection_body(&token, &client.client_id),
            use_signed_response,
        )
        .await;
    }
    introspection_response(
        &state,
        &client,
        json!({"active": false}),
        use_signed_response,
    )
    .await
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
    state: &AppState,
    resource_server: &ClientRow,
    body: Value,
    signed: bool,
) -> HttpResponse {
    if !signed {
        return json_response_no_store(body);
    }
    match signed_introspection_response(state, resource_server, body).await {
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

async fn signed_introspection_response(
    state: &AppState,
    resource_server: &ClientRow,
    body: Value,
) -> anyhow::Result<HttpResponse> {
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("token-introspection+jwt".to_owned());
    header.kid = Some(keyset.active_kid.clone());
    let claims = json!({
        "iss": state.settings.endpoint.issuer,
        "aud": resource_server.client_id,
        "iat": Utc::now().timestamp(),
        "token_introspection": body
    });
    let token = state
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::AccessToken, &header, &claims)
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

fn active_refresh_token_introspection_body(token: &TokenRow, client_id: &str) -> Value {
    json!({
        "active": true,
        "scope": json_array_to_strings(&token.scopes).join(" "),
        "client_id": client_id,
        "exp": token.expires_at.timestamp(),
        "iat": token.issued_at.timestamp(),
        "sub": token.subject
    })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/introspect.rs"]
mod tests;
