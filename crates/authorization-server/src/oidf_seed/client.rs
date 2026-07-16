//! Deterministic construction of conformance-only OAuth client records.
//!
//! Database writes remain in seed binaries/persistence adapters. This module
//! owns the shared mapping so the OIDC/FAPI and OpenID4VC seed paths cannot
//! drift into subtly different client defaults.

use nazo_auth::{OAuthClient, ValidatedClientRegistration};
use serde_json::Value;
use uuid::Uuid;

pub const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
pub const DEFAULT_REALM_ID: &str = "00000000-0000-0000-0000-000000000002";
pub const DEFAULT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000003";

pub struct OidfClientSpec<'a> {
    pub client_id: &'a str,
    pub client_name: &'a str,
    pub auth_method: &'a str,
    pub redirect_uris: &'a Value,
    pub post_logout_redirect_uris: &'a Value,
    pub scopes: &'a Value,
    pub allowed_audiences: &'a Value,
    pub grant_types: &'a Value,
    pub require_dpop_bound_tokens: bool,
    pub allow_client_assertion_audience_array: bool,
    pub allow_client_assertion_endpoint_audience: bool,
    pub require_par_request_object: bool,
    pub require_mtls_bound_tokens: bool,
    pub tls_client_auth_subject_dn: Option<&'a str>,
    pub tls_client_auth_cert_sha256: Option<&'a str>,
    pub frontchannel_logout_uri: Option<&'a str>,
    pub frontchannel_logout_session_required: bool,
    pub jwks: Option<&'a Value>,
    pub authorization_signed_response_alg: Option<&'a str>,
    pub backchannel_token_delivery_mode: &'a str,
    pub backchannel_client_notification_endpoint: Option<&'a str>,
    pub backchannel_authentication_request_signing_alg: Option<&'a str>,
}

pub fn oauth_client(spec: OidfClientSpec<'_>) -> anyhow::Result<OAuthClient> {
    let string_array = |value: &Value| -> anyhow::Result<Vec<String>> {
        serde_json::from_value(value.clone()).map_err(Into::into)
    };
    Ok(OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID.parse()?,
        realm_id: DEFAULT_REALM_ID.parse()?,
        organization_id: DEFAULT_ORGANIZATION_ID.parse()?,
        registration: ValidatedClientRegistration {
            client_id: spec.client_id.to_owned(),
            client_name: spec.client_name.to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: string_array(spec.redirect_uris)?,
            post_logout_redirect_uris: string_array(spec.post_logout_redirect_uris)?,
            scopes: string_array(spec.scopes)?,
            allowed_audiences: string_array(spec.allowed_audiences)?,
            grant_types: string_array(spec.grant_types)?,
            token_endpoint_auth_method: spec.auth_method.to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: spec.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: spec.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience: spec.allow_client_assertion_endpoint_audience,
            require_par_request_object: spec.require_par_request_object,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: true,
            backchannel_token_delivery_mode: spec.backchannel_token_delivery_mode.to_owned(),
            backchannel_client_notification_endpoint: spec
                .backchannel_client_notification_endpoint
                .map(ToOwned::to_owned),
            backchannel_authentication_request_signing_alg: spec
                .backchannel_authentication_request_signing_alg
                .map(ToOwned::to_owned),
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: spec.frontchannel_logout_uri.map(ToOwned::to_owned),
            frontchannel_logout_session_required: spec.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: spec.tls_client_auth_subject_dn.map(ToOwned::to_owned),
            tls_client_auth_cert_sha256: spec.tls_client_auth_cert_sha256.map(ToOwned::to_owned),
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: spec.jwks.cloned(),
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: nazo_auth::ClientPresentationMetadata::default(),
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: spec
                .authorization_signed_response_alg
                .map(ToOwned::to_owned),
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
        },
        require_mtls_bound_tokens: spec.require_mtls_bound_tokens,
        is_active: true,
    })
}
