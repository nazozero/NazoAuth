use crate::{
    empty_response_no_store, json_response_no_store, json_response_status_no_store,
    oauth_endpoint_error_response,
};
use actix_web::{HttpResponse, http::StatusCode};
use chrono::Utc;
use nazo_oauth_server::{
    contracts::oauth_error::OAuthEndpointError,
    domain::dynamic_registration::{DynamicRegistrationResponse, DynamicRegistrationResult},
};
use serde::{Serialize, Serializer, ser::SerializeMap};

pub(super) fn dynamic_registration_result_response(
    result: Result<DynamicRegistrationResult, OAuthEndpointError>,
) -> HttpResponse {
    match result {
        Ok(DynamicRegistrationResult::Created(result)) => json_response_status_no_store(
            StatusCode::CREATED,
            RegistrationDocument {
                result: &result,
                issued_at: Some(Utc::now().timestamp()),
            },
        ),
        Ok(
            DynamicRegistrationResult::Read(result) | DynamicRegistrationResult::Updated(result),
        ) => json_response_no_store(RegistrationDocument {
            result: &result,
            issued_at: None,
        }),
        Ok(DynamicRegistrationResult::Deleted) => empty_response_no_store(StatusCode::NO_CONTENT),
        Err(error) => oauth_endpoint_error_response(error),
    }
}

struct RegistrationDocument<'a> {
    result: &'a DynamicRegistrationResponse,
    issued_at: Option<i64>,
}

impl Serialize for RegistrationDocument<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let client = &self.result.client;
        let mut body = serializer.serialize_map(None)?;
        body.serialize_entry("client_id", &client.client_id)?;
        body.serialize_entry("client_name", &client.client_name)?;
        body.serialize_entry(
            "registration_access_token",
            &self.result.registration_access_token,
        )?;
        body.serialize_entry(
            "registration_client_uri",
            &format!(
                "{}/register/{}",
                self.result.issuer,
                encode_path_segment(&client.client_id)
            ),
        )?;
        body.serialize_entry("redirect_uris", &client.redirect_uris)?;
        body.serialize_entry("grant_types", &client.grant_types)?;
        body.serialize_entry("response_types", &self.result.response_types)?;
        body.serialize_entry("scope", &client.scopes.join(" "))?;
        body.serialize_entry(
            "token_endpoint_auth_method",
            &client.token_endpoint_auth_method,
        )?;
        body.serialize_entry(
            "dpop_bound_access_tokens",
            &client.require_dpop_bound_tokens,
        )?;
        body.serialize_entry(
            "tls_client_certificate_bound_access_tokens",
            &client.require_mtls_bound_tokens,
        )?;
        body.serialize_entry("subject_type", &client.subject_type)?;
        body.serialize_entry(
            "post_logout_redirect_uris",
            &client.post_logout_redirect_uris,
        )?;
        body.serialize_entry(
            "backchannel_logout_session_required",
            &client.backchannel_logout_session_required,
        )?;
        body.serialize_entry(
            "backchannel_token_delivery_mode",
            &client.backchannel_token_delivery_mode,
        )?;
        body.serialize_entry("backchannel_user_code_parameter", &false)?;
        body.serialize_entry(
            "frontchannel_logout_session_required",
            &client.frontchannel_logout_session_required,
        )?;
        if let Some(uri) = &client.backchannel_logout_uri {
            body.serialize_entry("backchannel_logout_uri", &uri)?;
        }
        if let Some(uri) = &client.backchannel_client_notification_endpoint {
            body.serialize_entry("backchannel_client_notification_endpoint", &uri)?;
        }
        if let Some(alg) = &client.backchannel_authentication_request_signing_alg {
            body.serialize_entry("backchannel_authentication_request_signing_alg", &alg)?;
        }
        if let Some(uri) = &client.frontchannel_logout_uri {
            body.serialize_entry("frontchannel_logout_uri", &uri)?;
        }
        if let Some(subject_dn) = &client.tls_client_auth_subject_dn {
            body.serialize_entry("tls_client_auth_subject_dn", &subject_dn)?;
        }
        for (field, values) in [
            ("tls_client_auth_san_dns", &client.tls_client_auth_san_dns),
            ("tls_client_auth_san_uri", &client.tls_client_auth_san_uri),
            ("tls_client_auth_san_ip", &client.tls_client_auth_san_ip),
            (
                "tls_client_auth_san_email",
                &client.tls_client_auth_san_email,
            ),
        ] {
            if let [value] = values.as_slice() {
                body.serialize_entry(field, &value)?;
            }
        }
        if let Some(jwks_uri) = &client.jwks_uri {
            body.serialize_entry("jwks_uri", &jwks_uri)?;
        } else if let Some(jwks) = &client.jwks {
            body.serialize_entry("jwks", jwks.as_ref())?;
        }
        if !client.request_uris.is_empty() {
            body.serialize_entry("request_uris", &client.request_uris)?;
        }
        if let Some(initiate_login_uri) = &client.initiate_login_uri {
            body.serialize_entry("initiate_login_uri", &initiate_login_uri)?;
        }
        if let Some(logo_uri) = &client.presentation.logo_uri {
            body.serialize_entry("logo_uri", &logo_uri)?;
        }
        if let Some(policy_uri) = &client.presentation.policy_uri {
            body.serialize_entry("policy_uri", &policy_uri)?;
        }
        if let Some(tos_uri) = &client.presentation.tos_uri {
            body.serialize_entry("tos_uri", &tos_uri)?;
        }
        for (field, value) in [
            (
                "id_token_signed_response_alg",
                client.id_token_signed_response_alg.as_ref(),
            ),
            (
                "id_token_encrypted_response_alg",
                client.id_token_encrypted_response_alg.as_ref(),
            ),
            (
                "id_token_encrypted_response_enc",
                client.id_token_encrypted_response_enc.as_ref(),
            ),
            (
                "request_object_signing_alg",
                client.request_object_signing_alg.as_ref(),
            ),
            (
                "request_object_encryption_alg",
                client.request_object_encryption_alg.as_ref(),
            ),
            (
                "request_object_encryption_enc",
                client.request_object_encryption_enc.as_ref(),
            ),
            (
                "token_endpoint_auth_signing_alg",
                client.token_endpoint_auth_signing_alg.as_ref(),
            ),
            (
                "introspection_signed_response_alg",
                client.introspection_signed_response_alg.as_ref(),
            ),
            (
                "introspection_encrypted_response_alg",
                client.introspection_encrypted_response_alg.as_ref(),
            ),
            (
                "introspection_encrypted_response_enc",
                client.introspection_encrypted_response_enc.as_ref(),
            ),
            (
                "userinfo_signed_response_alg",
                client.userinfo_signed_response_alg.as_ref(),
            ),
            (
                "userinfo_encrypted_response_alg",
                client.userinfo_encrypted_response_alg.as_ref(),
            ),
            (
                "userinfo_encrypted_response_enc",
                client.userinfo_encrypted_response_enc.as_ref(),
            ),
            (
                "authorization_signed_response_alg",
                client.authorization_signed_response_alg.as_ref(),
            ),
            (
                "authorization_encrypted_response_alg",
                client.authorization_encrypted_response_alg.as_ref(),
            ),
            (
                "authorization_encrypted_response_enc",
                client.authorization_encrypted_response_enc.as_ref(),
            ),
        ] {
            if let Some(value) = value {
                body.serialize_entry(field, &value)?;
            }
        }
        if let Some(secret) = &self.result.issued_secret {
            body.serialize_entry("client_secret", &secret)?;
            body.serialize_entry("client_secret_expires_at", &0)?;
        }
        if let Some(issued_at) = self.issued_at {
            body.serialize_entry("client_id_issued_at", &issued_at)?;
        }
        body.end()
    }
}

pub(super) fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}
