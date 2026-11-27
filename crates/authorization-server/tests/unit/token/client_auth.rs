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
