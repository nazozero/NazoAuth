//! token 管理端点复用的客户端认证。
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{oauth_error, oauth_token_error};

#[cfg(test)]
use crate::domain::AppState;
use crate::domain::ClientRow;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::support::security::consume_private_key_jwt;
use crate::support::{
    mtls::client_mtls_certificate_matches, mtls::request_mtls_client_certificate_from_headers,
    security::ClientAssertionError, security::ClientCredentials,
    security::ValidatedClientAssertion, security::blake3_hex, security::client_secret_digest,
    security::verify_private_key_jwt_claims_for_issuer,
};
#[cfg(test)]
use crate::support::{
    tenancy::DEFAULT_ORGANIZATION_ID, tenancy::DEFAULT_REALM_ID, tenancy::DEFAULT_TENANT_ID,
};
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Utc;
use nazo_auth::{
    ClientAuthenticationContext, ClientAuthenticationPolicyError, ClientAuthenticationRequirement,
    client_authentication_requirement,
};
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;

pub(crate) enum TokenManagementClientAuthError {
    InvalidClient,
    PublicClientCredentialsForbidden,
    StoreUnavailable,
}

#[derive(Clone, Copy)]
pub(crate) struct ClientAuthConfig<'a> {
    issuer: &'a str,
    client_secret_pepper: &'a str,
    trusted_proxy_cidrs: &'a [crate::support::client_ip::IpCidr],
}

impl<'a> ClientAuthConfig<'a> {
    pub(crate) fn new(
        issuer: &'a str,
        client_secret_pepper: &'a str,
        trusted_proxy_cidrs: &'a [crate::support::client_ip::IpCidr],
    ) -> Self {
        Self {
            issuer,
            client_secret_pepper,
            trusted_proxy_cidrs,
        }
    }
}

fn dummy_client_secret_salt(client_id: Option<&str>) -> String {
    blake3_hex(client_id.unwrap_or(""))
}

/// Equalizes the CPU work for an unknown secret-authenticated client without touching storage.
/// The result is deliberately consumed so release optimization cannot remove the calculation.
pub(crate) fn perform_dummy_client_secret_verification(
    credentials: &ClientCredentials,
    client_secret_pepper: &str,
) {
    if matches!(
        credentials.method.as_str(),
        "client_secret_basic" | "client_secret_post"
    ) && let Some(secret) = credentials.client_secret.as_deref()
    {
        let dummy_salt = dummy_client_secret_salt(credentials.client_id.as_deref());
        drop(std::hint::black_box(client_secret_digest(
            secret,
            client_secret_pepper,
            &dummy_salt,
        )));
    }
}

pub(crate) async fn authenticate_introspection_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        req,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
    )
    .await
    .map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

pub(crate) async fn authenticate_revocation_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        req,
        client,
        credentials,
        ClientAuthenticationContext::AllowPublicNone,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
    )
    .await
}

#[cfg(test)]
pub(crate) async fn verify_confidential_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let connection = state.valkey_connection();
    let service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            crate::support::tenancy::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let result = authenticate_client_with_dependencies(
        &service,
        ClientAuthConfig::new(
            &state.settings.endpoint.issuer,
            &state.settings.protocol.client_secret_pepper,
            &state.settings.endpoint.trusted_proxy_cidrs,
        ),
        req,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await;
    result.map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

#[cfg(test)]
fn revocation_public_client_allows_credentials(credentials: &ClientCredentials) -> bool {
    credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none()
}

pub(crate) async fn authenticate_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
    context: ClientAuthenticationContext,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let requirement =
        client_authentication_requirement(client, credentials, context).map_err(|error| {
            log_client_auth_rejection(req, client, credentials, "policy");
            match error {
                ClientAuthenticationPolicyError::InvalidClient => {
                    TokenManagementClientAuthError::InvalidClient
                }
                ClientAuthenticationPolicyError::PublicClientCredentialsForbidden => {
                    TokenManagementClientAuthError::PublicClientCredentialsForbidden
                }
            }
        })?;

    match requirement {
        ClientAuthenticationRequirement::PublicClient => Ok(None),
        ClientAuthenticationRequirement::PrivateKeyJwt { assertion } => {
            verify_private_key_jwt_claims_for_issuer(config.issuer, req, client, assertion)
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
        ClientAuthenticationRequirement::ClientSecret { secret, .. } => {
            let secret_match = match service.client_secret_salt(client.id).await {
                Ok(Some(salt)) => {
                    let candidate_digest =
                        client_secret_digest(secret, config.client_secret_pepper, &salt);
                    service
                        .client_secret_digest_matches(client.id, &candidate_digest)
                        .await
                }
                Ok(None) => {
                    perform_dummy_client_secret_verification(
                        credentials,
                        config.client_secret_pepper,
                    );
                    Ok(false)
                }
                Err(error) => Err(error),
            };
            if client_secret_auth_result(secret_match)? {
                Ok(None)
            } else {
                log_client_auth_rejection(req, client, credentials, "client_secret");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
        ClientAuthenticationRequirement::MutualTls { .. } => {
            let trusted = crate::support::client_ip::request_from_trusted_proxy_cidrs(
                req,
                config.trusted_proxy_cidrs,
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

pub(crate) fn token_management_auth_error(error: TokenManagementClientAuthError) -> HttpResponse {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => oauth_error(
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
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => oauth_token_error(
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

pub(crate) async fn consume_token_management_client_assertion_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::support::security::consume_private_key_jwt_with_authorization_service(
        service, client, assertion,
    )
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

pub(crate) async fn consume_token_client_assertion_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), HttpResponse> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::support::security::consume_private_key_jwt_with_authorization_service(
        service, client, assertion,
    )
    .await
    .map_err(token_client_assertion_error)
}

fn token_client_assertion_error(error: ClientAssertionError) -> HttpResponse {
    match error {
        ClientAssertionError::StoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
        ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            false,
        ),
    }
}

#[cfg(test)]
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
        .map_err(token_client_assertion_error)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/client_auth.rs"]
mod tests;
