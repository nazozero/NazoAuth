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

#[test]
fn security_cloud_global_introspection_profile_cannot_be_downgraded_by_client_metadata() {
    use crate::{authorization::config::AuthorizationConfig, policy::AuthorizationServerProfile};
    let mut config = AuthorizationConfig {
        issuer: "https://issuer.test".into(),
        mtls_endpoint_base_url: "https://mtls.test".into(),
        frontend_base_url: "https://issuer.test".into(),
        profile: AuthorizationServerProfile::Fapi2MessageSigningIntrospection,
        dpop_nonce_policy: nazo_auth::DpopNoncePolicy::Optional,
        request_object_jti_policy: crate::policy::RequestObjectJtiPolicy::Optional,
        auth_code_ttl_seconds: 60,
        par_ttl_seconds: 60,
        require_pushed_authorization_requests: false,
        client_secret_pepper: "test-only-pepper".into(),
        rate_limit_window_seconds: 60,
        token_management_max_requests: 60,
    };
    let mut client = nazo_auth::ClientSecurityPolicy::default();
    assert!(config.requires_signed_introspection_response(&client));
    config.profile = AuthorizationServerProfile::Oauth2Baseline;
    assert!(!config.requires_signed_introspection_response(&client));
    client.require_signed_introspection_response = true;
    assert!(config.requires_signed_introspection_response(&client));
}
