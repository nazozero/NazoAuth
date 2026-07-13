//! token 管理端点复用的客户端认证。
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{oauth_error, oauth_token_error};

use crate::domain::{AppState, ClientRow};
#[cfg(test)]
use crate::settings::Settings;
use crate::support::{
    ClientAssertionError, ClientCredentials, ValidatedClientAssertion, blake3_hex,
    client_mtls_certificate_matches, client_secret_digest, consume_private_key_jwt,
    request_mtls_client_certificate_from_headers, verify_private_key_jwt_claims_for_issuer,
};
#[cfg(test)]
use crate::support::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;

pub(crate) enum TokenManagementClientAuthError {
    InvalidClient,
    StoreUnavailable,
}

async fn authenticate_confidential_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = verify_confidential_client(state, req, client, credentials).await?;
    consume_token_management_client_assertion(state, client, assertion.as_ref()).await
}

pub(crate) async fn verify_confidential_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let endpoint = state.settings.endpoint();
    let connection = state.valkey_connection();
    let service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            crate::support::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    verify_confidential_client_with_dependencies(
        &service,
        &state.settings.issuer,
        state.settings.protocol().client_secret_pepper,
        endpoint.trusted_proxy_cidrs,
        req,
        client,
        credentials,
    )
    .await
}

pub(crate) async fn verify_confidential_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    issuer: &str,
    client_secret_pepper: &str,
    trusted_proxy_cidrs: &[crate::support::IpCidr],
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    if client.client_type != "confidential" {
        log_client_auth_rejection(req, client, credentials, "client_type");
        return Err(TokenManagementClientAuthError::InvalidClient);
    }
    if credentials.method != client.token_endpoint_auth_method {
        log_client_auth_rejection(req, client, credentials, "auth_method");
        return Err(TokenManagementClientAuthError::InvalidClient);
    }

    match client.token_endpoint_auth_method.as_str() {
        "private_key_jwt" => {
            let Some(assertion) = credentials.client_assertion.as_deref() else {
                log_client_auth_rejection(req, client, credentials, "missing_client_assertion");
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            verify_private_key_jwt_claims_for_issuer(issuer, req, client, assertion)
                .map(Some)
                .map_err(|error| {
                    log_client_auth_rejection(
                        req,
                        client,
                        credentials,
                        client_assertion_error_reason(&error),
                    );
                    token_management_client_assertion_error(error)
                })
        }
        "client_secret_basic" | "client_secret_post" => {
            let Some(secret) = credentials.client_secret.as_deref() else {
                log_client_auth_rejection(req, client, credentials, "client_secret");
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            let secret_match = match service.client_secret_salt(client.id).await {
                Ok(Some(salt)) => {
                    let candidate_digest =
                        client_secret_digest(secret, client_secret_pepper, &salt);
                    service
                        .client_secret_digest_matches(client.id, &candidate_digest)
                        .await
                }
                Ok(None) => Ok(false),
                Err(error) => Err(error),
            };
            if client_secret_auth_result(secret_match)? {
                Ok(None)
            } else {
                log_client_auth_rejection(req, client, credentials, "client_secret");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
        "tls_client_auth" | "self_signed_tls_client_auth" => {
            let trusted = crate::support::client_ip::request_from_trusted_proxy_cidrs(
                req,
                trusted_proxy_cidrs,
            );
            let Some(certificate) = trusted
                .then(|| request_mtls_client_certificate_from_headers(req.headers()))
                .flatten()
            else {
                log_client_auth_rejection(req, client, credentials, "missing_mtls_certificate");
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            if client_mtls_certificate_matches(client, &certificate) {
                Ok(None)
            } else {
                log_client_auth_rejection(req, client, credentials, "mtls_certificate");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
        _ => {
            log_client_auth_rejection(req, client, credentials, "unsupported_auth_method");
            Err(TokenManagementClientAuthError::InvalidClient)
        }
    }
}

fn client_secret_auth_result<E: std::fmt::Display>(
    result: Result<bool, E>,
) -> Result<bool, TokenManagementClientAuthError> {
    result.map_err(|error| {
        tracing::warn!(%error, "failed to verify management client secret");
        TokenManagementClientAuthError::StoreUnavailable
    })
}

fn client_assertion_error_reason(error: &ClientAssertionError) -> &'static str {
    match error {
        ClientAssertionError::Invalid => "client_assertion",
        ClientAssertionError::ReplayDetected => "client_assertion_replay",
        ClientAssertionError::StoreUnavailable => "client_assertion_store",
    }
}

fn log_client_auth_rejection(
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
    reason: &'static str,
) {
    tracing::warn!(
        target: "client_auth",
        "client_auth_rejected reason={} path={} client_id_hash={} expected_method={} presented_method={}",
        reason,
        req.uri().path(),
        blake3_hex(&client.client_id),
        client.token_endpoint_auth_method,
        credentials.method
    );
}

pub(crate) async fn authenticate_introspection_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    authenticate_confidential_client(state, req, client, credentials).await
}

pub(crate) async fn authenticate_revocation_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    if client.client_type == "confidential" {
        return authenticate_confidential_client(state, req, client, credentials).await;
    }
    revocation_public_client_allows_credentials(credentials)
        .then_some(())
        .ok_or(TokenManagementClientAuthError::InvalidClient)
}

fn revocation_public_client_allows_credentials(credentials: &ClientCredentials) -> bool {
    credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none()
}

pub(crate) fn token_management_auth_error(error: TokenManagementClientAuthError) -> HttpResponse {
    match error {
        TokenManagementClientAuthError::InvalidClient => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        ),
        TokenManagementClientAuthError::StoreUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
        ),
    }
}

pub(crate) fn token_management_client_auth_error(
    error: TokenManagementClientAuthError,
    basic_challenge: bool,
) -> HttpResponse {
    match error {
        TokenManagementClientAuthError::InvalidClient => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            basic_challenge,
        ),
        TokenManagementClientAuthError::StoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
    }
}

pub(crate) async fn consume_token_management_client_assertion(
    state: &AppState,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    consume_private_key_jwt(state, client, assertion)
        .await
        .map_err(token_management_client_assertion_error)
}

pub(crate) async fn consume_token_management_client_assertion_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::support::consume_private_key_jwt_with_authorization_service(service, client, assertion)
        .await
        .map_err(token_management_client_assertion_error)
}

fn token_management_client_assertion_error(
    error: ClientAssertionError,
) -> TokenManagementClientAuthError {
    match error {
        ClientAssertionError::StoreUnavailable => TokenManagementClientAuthError::StoreUnavailable,
        ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => {
            TokenManagementClientAuthError::InvalidClient
        }
    }
}

pub(crate) async fn consume_token_client_assertion(
    state: &AppState,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), HttpResponse> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    consume_private_key_jwt(state, client, assertion)
        .await
        .map_err(|error| match error {
            ClientAssertionError::StoreUnavailable => oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端认证状态存储不可用.",
                false,
            ),
            ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => {
                oauth_token_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                    false,
                )
            }
        })
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/client_auth.rs"]
mod tests;
