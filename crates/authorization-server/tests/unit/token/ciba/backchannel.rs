use super::*;

#[test]
fn ciba_client_authentication_errors_preserve_http_method_and_store_failure() {
    for basic in [false, true] {
        for error in [
            TokenManagementClientAuthError::InvalidClient,
            TokenManagementClientAuthError::PublicClientCredentialsForbidden,
        ] {
            assert!(matches!(
                token_management_auth_error(error, basic),
                OAuthEndpointError::Token { fields, basic_challenge }
                    if fields.status == if basic { StatusCode::UNAUTHORIZED } else { StatusCode::BAD_REQUEST }
                        && fields.error == "invalid_client"
                        && basic_challenge == basic
            ));
        }
        assert_eq!(
            token_management_auth_error(TokenManagementClientAuthError::StoreUnavailable, basic),
            OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端认证状态存储不可用.",
            )
        );
    }
}
