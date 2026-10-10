//! Wire request models and conversion into the core client-create request.

use serde::Deserialize;
use serde_json::Value;

use crate::CreateClientRequest;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub subject_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub backchannel_token_delivery_mode: Option<String>,
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg: Option<String>,
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub backchannel_user_code_parameter: Option<bool>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_ip: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_email: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_signing_alg: Option<String>,
    #[serde(default)]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_alg: Option<String>,
    #[serde(default)]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_enc: Option<String>,
    #[serde(default)]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub authorization_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub introspection_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_signed_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_uris: Option<Vec<String>>,
    #[serde(default)]
    pub initiate_login_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub software_statement: Option<String>,
}
/// Negotiated metadata ready for the shared client-creation validation path.
/// Registration response choices are not a second client metadata model.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedDynamicClientRegistration {
    pub request: CreateClientRequest,
    pub response_types: Vec<String>,
}
