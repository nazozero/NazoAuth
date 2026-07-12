use serde_json::Value;
use uuid::Uuid;

/// Validated OAuth client registration ready for persistence.
///
/// Secret material is retained only because PostgreSQL must atomically create
/// the client during access-request approval. It is never serializable.
pub struct PreparedClientRegistration {
    pub tenant_id: Uuid,
    pub realm_id: Uuid,
    pub organization_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub subject_type: String,
    pub sector_identifier_uri: Option<String>,
    pub sector_identifier_host: Option<String>,
    pub require_dpop_bound_tokens: bool,
    pub allow_client_assertion_audience_array: bool,
    pub allow_client_assertion_endpoint_audience: bool,
    pub require_par_request_object: bool,
    pub allow_authorization_code_without_pkce: bool,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Vec<String>,
    pub tls_client_auth_san_uri: Vec<String>,
    pub tls_client_auth_san_ip: Vec<String>,
    pub tls_client_auth_san_email: Vec<String>,
    pub jwks: Option<Value>,
    pub introspection_encrypted_response_alg: Option<String>,
    pub introspection_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
    pub issued_secret: Option<String>,
    pub client_secret_hash: Option<String>,
    pub registration_access_token_blake3: Option<String>,
}

impl std::fmt::Debug for PreparedClientRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientRegistration")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedClient {
    pub id: Uuid,
    pub client_id: String,
}
