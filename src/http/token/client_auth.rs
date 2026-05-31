//! token 管理端点复用的客户端认证。

use crate::http::prelude::*;

pub(crate) async fn authenticate_token_management_client(
    state: &AppState,
    req: &HttpRequest,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> bool {
    if client.client_type == "confidential" {
        if credentials.method != client.token_endpoint_auth_method {
            return false;
        }
        return match client.token_endpoint_auth_method.as_str() {
            "private_key_jwt" => {
                let Some(assertion) = credentials.client_assertion.as_deref() else {
                    return false;
                };
                validate_private_key_jwt(state, req, client, assertion)
                    .await
                    .is_ok()
            }
            "client_secret_basic" | "client_secret_post" => {
                credentials.client_secret.as_deref().is_some_and(|secret| {
                    verify_password(
                        secret,
                        client.client_secret_argon2_hash.as_deref().unwrap_or(""),
                    )
                })
            }
            _ => false,
        };
    }

    credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none()
}
