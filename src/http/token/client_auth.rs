//! token 管理端点复用的客户端认证。

use crate::http::prelude::*;

pub(crate) enum TokenManagementClientAuthError {
    InvalidClient,
    StoreUnavailable,
}

pub(crate) async fn authenticate_token_management_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    if client.client_type == "confidential" {
        if credentials.method != client.token_endpoint_auth_method {
            return Err(TokenManagementClientAuthError::InvalidClient);
        }
        return match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let Some(assertion) = credentials.client_assertion.as_deref() else {
                    return Err(TokenManagementClientAuthError::InvalidClient);
                };
                validate_private_key_jwt(state, req, client, assertion)
                    .await
                    .map_err(|error| match error {
                        ClientAssertionError::StoreUnavailable => {
                            TokenManagementClientAuthError::StoreUnavailable
                        }
                        ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => {
                            TokenManagementClientAuthError::InvalidClient
                        }
                    })
            }
            "client_secret_basic" | "client_secret_post" => {
                let valid_secret = credentials.client_secret.as_deref().is_some_and(|secret| {
                    verify_password(
                        secret,
                        client.client_secret_argon2_hash.as_deref().unwrap_or(""),
                    )
                });
                valid_secret
                    .then_some(())
                    .ok_or(TokenManagementClientAuthError::InvalidClient)
            }
            _ => Err(TokenManagementClientAuthError::InvalidClient),
        };
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
