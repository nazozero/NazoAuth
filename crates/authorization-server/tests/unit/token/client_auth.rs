use super::*;

#[test]
fn dummy_client_secret_salt_is_deterministic_but_not_global() {
    assert_eq!(
        dummy_client_secret_salt(Some("unknown-client")),
        dummy_client_secret_salt(Some("unknown-client"))
    );
    assert_ne!(
        dummy_client_secret_salt(Some("unknown-client-a")),
        dummy_client_secret_salt(Some("unknown-client-b"))
    );
}

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
