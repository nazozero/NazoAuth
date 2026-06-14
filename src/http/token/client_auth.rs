//! token 管理端点复用的客户端认证。

use crate::http::prelude::*;

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
    let assertion = verify_confidential_client(state, req, client, credentials)?;
    consume_token_management_client_assertion(state, client, assertion.as_ref()).await
}

pub(crate) fn verify_confidential_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    if client.client_type != "confidential"
        || credentials.method != client.token_endpoint_auth_method
    {
        return Err(TokenManagementClientAuthError::InvalidClient);
    }

    match client.token_endpoint_auth_method.as_str() {
        "private_key_jwt" => {
            let Some(assertion) = credentials.client_assertion.as_deref() else {
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            verify_private_key_jwt_claims(state, req, client, assertion)
                .map(Some)
                .map_err(token_management_client_assertion_error)
        }
        "client_secret_basic" | "client_secret_post" => {
            let valid_secret = credentials.client_secret.as_deref().is_some_and(|secret| {
                verify_password(
                    secret,
                    client.client_secret_argon2_hash.as_deref().unwrap_or(""),
                )
            });
            valid_secret
                .then_some(None)
                .ok_or(TokenManagementClientAuthError::InvalidClient)
        }
        "tls_client_auth" | "self_signed_tls_client_auth" => {
            let certificate = request_mtls_client_certificate(req, &state.settings)
                .ok_or(TokenManagementClientAuthError::InvalidClient)?;
            client_mtls_certificate_matches(client, &certificate)
                .then_some(None)
                .ok_or(TokenManagementClientAuthError::InvalidClient)
        }
        _ => Err(TokenManagementClientAuthError::InvalidClient),
    }
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
    (credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none())
    .then_some(())
    .ok_or(TokenManagementClientAuthError::InvalidClient)
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
#[path = "tests/client_auth.rs"]
mod tests;
