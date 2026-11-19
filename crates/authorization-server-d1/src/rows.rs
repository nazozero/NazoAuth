use super::db::DbError;
use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Deserialize)]
pub(super) struct ClientRow {
    pub tenant_id: Uuid,
    pub id: Uuid,
    pub client_id: String,
    pub realm_id: Uuid,
    pub organization_id: Uuid,
    pub registration: String,
    pub secret_digest: Option<String>,
    pub epoch: i64,
    pub active: i64,
}

#[derive(Deserialize, Serialize)]
struct StoredPresentation {
    logo_uri: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
}

#[derive(Deserialize)]
struct StoredRegistration {
    client_id: String,
    client_name: String,
    client_type: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    scopes: Vec<String>,
    allowed_audiences: Vec<String>,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    sector_identifier_host: Option<String>,
    require_dpop_bound_tokens: bool,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    backchannel_token_delivery_mode: String,
    backchannel_client_notification_endpoint: Option<String>,
    backchannel_authentication_request_signing_alg: Option<String>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Vec<String>,
    tls_client_auth_san_uri: Vec<String>,
    tls_client_auth_san_ip: Vec<String>,
    tls_client_auth_san_email: Vec<String>,
    jwks_uri: Option<String>,
    jwks: Option<std::sync::Arc<Value>>,
    request_uris: Vec<String>,
    initiate_login_uri: Option<String>,
    presentation: StoredPresentation,
    id_token_signed_response_alg: Option<String>,
    id_token_encrypted_response_alg: Option<String>,
    id_token_encrypted_response_enc: Option<String>,
    request_object_signing_alg: Option<String>,
    request_object_encryption_alg: Option<String>,
    request_object_encryption_enc: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
    introspection_signed_response_alg: Option<String>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    security_policy: nazo_auth::ClientSecurityPolicy,
}

impl ClientRow {
    pub fn into_domain(self) -> Result<OAuthClient, DbError> {
        let value: StoredRegistration =
            serde_json::from_str(&self.registration).map_err(|_| DbError::CorruptData)?;
        if value.client_id != self.client_id {
            return Err(DbError::CorruptData);
        }
        value
            .security_policy
            .validate()
            .map_err(|_| DbError::CorruptData)?;
        Ok(OAuthClient {
            id: self.id,
            tenant_id: self.tenant_id,
            realm_id: self.realm_id,
            organization_id: self.organization_id,
            is_active: self.active != 0,
            require_mtls_bound_tokens: false,
            registration: ValidatedClientRegistration {
                client_id: value.client_id,
                client_name: value.client_name,
                client_type: value.client_type,
                redirect_uris: value.redirect_uris,
                post_logout_redirect_uris: value.post_logout_redirect_uris,
                scopes: value.scopes,
                allowed_audiences: value.allowed_audiences,
                grant_types: value.grant_types,
                token_endpoint_auth_method: value.token_endpoint_auth_method,
                subject_type: value.subject_type,
                sector_identifier_uri: value.sector_identifier_uri,
                sector_identifier_host: value.sector_identifier_host,
                require_dpop_bound_tokens: value.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: value.allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: value
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: value.require_par_request_object,
                backchannel_token_delivery_mode: value.backchannel_token_delivery_mode,
                backchannel_client_notification_endpoint: value
                    .backchannel_client_notification_endpoint,
                backchannel_authentication_request_signing_alg: value
                    .backchannel_authentication_request_signing_alg,
                backchannel_logout_uri: value.backchannel_logout_uri,
                backchannel_logout_session_required: value.backchannel_logout_session_required,
                frontchannel_logout_uri: value.frontchannel_logout_uri,
                frontchannel_logout_session_required: value.frontchannel_logout_session_required,
                tls_client_auth_subject_dn: value.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: value.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: value.tls_client_auth_san_dns,
                tls_client_auth_san_uri: value.tls_client_auth_san_uri,
                tls_client_auth_san_ip: value.tls_client_auth_san_ip,
                tls_client_auth_san_email: value.tls_client_auth_san_email,
                jwks_uri: value.jwks_uri,
                jwks: value.jwks,
                request_uris: value.request_uris,
                initiate_login_uri: value.initiate_login_uri,
                presentation: nazo_auth::ClientPresentationMetadata {
                    logo_uri: value.presentation.logo_uri,
                    policy_uri: value.presentation.policy_uri,
                    tos_uri: value.presentation.tos_uri,
                },
                id_token_signed_response_alg: value.id_token_signed_response_alg,
                id_token_encrypted_response_alg: value.id_token_encrypted_response_alg,
                id_token_encrypted_response_enc: value.id_token_encrypted_response_enc,
                request_object_signing_alg: value.request_object_signing_alg,
                request_object_encryption_alg: value.request_object_encryption_alg,
                request_object_encryption_enc: value.request_object_encryption_enc,
                token_endpoint_auth_signing_alg: value.token_endpoint_auth_signing_alg,
                introspection_signed_response_alg: value.introspection_signed_response_alg,
                introspection_encrypted_response_alg: value.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: value.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: value.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: value.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: value.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: value.authorization_signed_response_alg,
                authorization_encrypted_response_alg: value.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: value.authorization_encrypted_response_enc,
                security_policy: value.security_policy,
            },
        })
    }
}
