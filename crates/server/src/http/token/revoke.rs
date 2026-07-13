//! token revoke 端点。
use crate::domain::AppState;
#[cfg(test)]
use crate::domain::ClientRow;
#[cfg(test)]
use crate::schema::{access_token_revocations, oauth_tokens};
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::{
    AccessTokenJwtInput, DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, IssuedAccessToken,
    OAuthJsonErrorFields, make_jwt,
};
use crate::support::{
    DEFAULT_TENANT_ID, RateLimitPolicy, audit_event, audit_fields, blake3_hex, client_ip,
    decode_access_claims, empty_response_no_store, enforce_rate_limit, extract_client_credentials,
    has_basic_authorization_scheme,
};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
#[cfg(test)]
use diesel::prelude::*;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::{
    TokenManagementClientAuthError, authenticate_revocation_client, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};

pub(crate) async fn revoke(state: Data<AppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    if let Err(response) = enforce_rate_limit(&state, &req, RateLimitPolicy::TokenManagement).await
    {
        return response;
    }
    revoke_after_rate_limit(state, req, body).await
}

pub(crate) async fn revoke_after_rate_limit(
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
            tracing::warn!(%error, "failed to query oauth client for token revocation");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_revocation_client(&state, &req, &client, &credentials).await {
        return token_management_client_auth_error(error, has_basic);
    }
    let token_repository = nazo_postgres::TokenRepository::new(state.diesel_db.clone());
    let updated = match token_repository
        .revoke_refresh_token(client.tenant_id, client.id, &form.token)
        .await
    {
        Ok(updated) => updated,
        Err(error) => {
            tracing::warn!(%error, "failed to revoke refresh token");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "token 撤销失败.",
            );
        }
    };
    if updated == 0
        && let Some(claims) = decode_access_claims(&state, &form.token)
        && claims.client_id == client.client_id
        && let Some(expires_at) = DateTime::<Utc>::from_timestamp(claims.exp, 0)
        && let Err(error) = token_repository
            .revoke_access_token(client.tenant_id, client.id, &claims.jti, expires_at)
            .await
    {
        tracing::warn!(%error, "failed to revoke access token");
        return token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 撤销失败.",
        );
    }
    audit_event(
        "token_revoked",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("token_hash", json!(blake3_hex(&form.token))),
            ("updated", json!(updated)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip(&req, &state.settings))),
            ),
        ]),
    );
    empty_response_no_store(StatusCode::OK)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/revoke.rs"]
mod tests;
