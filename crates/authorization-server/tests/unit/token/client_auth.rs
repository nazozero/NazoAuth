use super::*;

#[test]
fn client_assertion_failures_keep_typed_security_classification() {
    assert!(matches!(
        token_management_client_assertion_error(ClientAssertionError::ReplayDetected),
        TokenManagementClientAuthError::InvalidClient
    ));
    assert!(matches!(
        token_management_client_assertion_error(ClientAssertionError::StoreUnavailable),
        TokenManagementClientAuthError::StoreUnavailable
    ));
}

#[test]
fn confidential_client_secret_auth_fails_closed_when_store_is_unavailable() {
    assert!(matches!(
        client_secret_auth_result(Err(nazo_identity::ports::RepositoryError::Unavailable)),
        Err(TokenManagementClientAuthError::StoreUnavailable)
    ));
}

#[test]
fn client_secret_match_result_preserves_true_and_false() {
    assert!(matches!(
        client_secret_auth_result::<nazo_identity::ports::RepositoryError>(Ok(true)),
        Ok(true)
    ));
    assert!(matches!(
        client_secret_auth_result::<nazo_identity::ports::RepositoryError>(Ok(false)),
        Ok(false)
    ));
}
