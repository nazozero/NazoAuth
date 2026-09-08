use super::*;

#[test]
fn authentication_store_failures_are_not_mapped_to_invalid_client() {
    assert!(matches!(
        map_auth_error(TokenManagementClientAuthError::StoreUnavailable, false,),
        TokenManagementError::AuthenticationStoreUnavailable
    ));
}

#[test]
fn invalid_client_mapping_preserves_basic_challenge() {
    assert!(matches!(
        map_auth_error(TokenManagementClientAuthError::InvalidClient, true),
        TokenManagementError::InvalidClient {
            basic_challenge: true
        }
    ));
    assert!(matches!(
        map_auth_error(
            TokenManagementClientAuthError::PublicClientCredentialsForbidden,
            false,
        ),
        TokenManagementError::InvalidClient {
            basic_challenge: false
        }
    ));
}
