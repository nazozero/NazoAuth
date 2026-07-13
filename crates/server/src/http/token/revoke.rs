//! token revoke 端点。
use crate::support::{
    audit::audit_event, audit::audit_fields, client_ip::client_ip_with_config,
    rate_limit::rate_limited_response, security::blake3_hex,
    security::extract_client_credentials_with_trusted_proxies,
    security::has_basic_authorization_scheme,
};
#[cfg(test)]
use crate::support::{
    security::AccessTokenJwtInput, security::IssuedAccessToken, security::make_jwt,
    tenancy::DEFAULT_ORGANIZATION_ID, tenancy::DEFAULT_REALM_ID,
};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::empty_response_no_store;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;
// 只处理 refresh token 撤销和 access token jti 黑名单写入。
use super::{
    ServerTokenService, TokenManagementClientAuthError,
    authenticate_revocation_client_with_dependencies, parse_token_management_form,
    token_management_client_auth_error, token_management_form_error,
    token_management_has_conflicting_client_auth, token_management_oauth_error,
};
use crate::http::authorization::{AuthorizationHttpConfig, ServerAuthorizationService};

pub(crate) async fn revoke(
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
            tracing::warn!(%error, "token revocation rate limit increment failed");
            return nazo_http_actix::oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            );
        }
    }
    revoke_after_rate_limit_with_dependencies(
        &token_service,
        &authorization_service,
        &config,
        req,
        body,
    )
    .await
}

async fn revoke_after_rate_limit_with_dependencies(
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
            tracing::warn!(%error, "failed to query oauth client for token revocation");
            return token_management_oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if let Err(error) = authenticate_revocation_client_with_dependencies(
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
    let updated = match token_service
        .revoke_token(&config.issuer, &form.token, &client)
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
    audit_event(
        "token_revoked",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("token_hash", json!(blake3_hex(&form.token))),
            ("updated", json!(updated)),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_config(&req, &config.client_ip))),
            ),
        ]),
    );
    empty_response_no_store(StatusCode::OK)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/revoke.rs"]
mod tests;
