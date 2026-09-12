use crate::policy::{AuthorizationServerProfile, RequestObjectJtiPolicy};
use nazo_auth::DpopNoncePolicy;

#[derive(Clone)]
pub struct AuthorizationConfig {
    pub issuer: Box<str>,
    pub mtls_endpoint_base_url: Box<str>,
    pub frontend_base_url: Box<str>,
    pub profile: AuthorizationServerProfile,
    pub dpop_nonce_policy: DpopNoncePolicy,
    pub request_object_jti_policy: RequestObjectJtiPolicy,
    pub auth_code_ttl_seconds: u64,
    pub par_ttl_seconds: u64,
    pub require_pushed_authorization_requests: bool,
    pub client_secret_pepper: Box<str>,
    pub rate_limit_window_seconds: u64,
    pub token_management_max_requests: u64,
}

impl AuthorizationConfig {
    pub fn requires_fapi2_security(&self, client: &nazo_auth::ClientSecurityPolicy) -> bool {
        self.profile.requires_fapi2_security() || client.requires_fapi2_security()
    }

    pub fn requires_signed_authorization_request(
        &self,
        client: &nazo_auth::ClientSecurityPolicy,
    ) -> bool {
        self.profile.requires_signed_authorization_request()
            || client.require_signed_authorization_request
    }

    pub fn requires_signed_authorization_response(
        &self,
        client: &nazo_auth::ClientSecurityPolicy,
    ) -> bool {
        self.profile.requires_signed_authorization_response()
            || client.require_signed_authorization_response
    }
}
