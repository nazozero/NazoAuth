use crate::{
    empty_response_no_store, json_response_no_store, json_response_status_no_store,
    oauth_endpoint_error_response,
};
use actix_web::{HttpResponse, http::StatusCode};
use chrono::Utc;
use nazo_auth::OAuthClient;
use nazo_oauth_server::{
    contracts::oauth_error::OAuthEndpointError,
    domain::dynamic_registration::DynamicRegistrationResult,
};
use serde_json::{Value, json};

pub(super) fn dynamic_registration_result_response(
    result: Result<DynamicRegistrationResult, OAuthEndpointError>,
) -> HttpResponse {
    match result {
        Ok(DynamicRegistrationResult::Created(result)) => dynamic_registration_created_response(
            &result.client,
            &result.response_types,
            result.issued_secret,
            &result.issuer,
            &result.registration_access_token,
        ),
        Ok(
            DynamicRegistrationResult::Read(result) | DynamicRegistrationResult::Updated(result),
        ) => json_response_no_store(dynamic_registration_response(
            &result.client,
            &result.response_types,
            result.issued_secret,
            &result.issuer,
            &result.registration_access_token,
        )),
        Ok(DynamicRegistrationResult::Deleted) => empty_response_no_store(StatusCode::NO_CONTENT),
        Err(error) => oauth_endpoint_error_response(error),
    }
}

pub(super) fn dynamic_registration_created_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> HttpResponse {
    let mut body = dynamic_registration_response(
        client,
        response_types,
        issued_secret,
        issuer,
        registration_access_token,
    );
    body["client_id_issued_at"] = json!(Utc::now().timestamp());
    json_response_status_no_store(StatusCode::CREATED, body)
}

pub(super) fn dynamic_registration_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "registration_access_token": registration_access_token,
        "registration_client_uri": format!("{issuer}/register/{}", encode_path_segment(&client.client_id)),
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": response_types,
        "scope": client.scopes.join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "dpop_bound_access_tokens": client.require_dpop_bound_tokens,
        "tls_client_certificate_bound_access_tokens": client.require_mtls_bound_tokens,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "backchannel_token_delivery_mode": client.backchannel_token_delivery_mode,
        "backchannel_user_code_parameter": client.backchannel_user_code_parameter,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
    });
    if let Some(uri) = &client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(uri) = &client.backchannel_client_notification_endpoint {
        body["backchannel_client_notification_endpoint"] = json!(uri);
    }
    if let Some(alg) = &client.backchannel_authentication_request_signing_alg {
        body["backchannel_authentication_request_signing_alg"] = json!(alg);
    }
    if let Some(uri) = &client.frontchannel_logout_uri {
        body["frontchannel_logout_uri"] = json!(uri);
    }
    if let Some(subject_dn) = &client.tls_client_auth_subject_dn {
        body["tls_client_auth_subject_dn"] = json!(subject_dn);
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
            body[field] = json!(value);
        }
    }
    if let Some(jwks_uri) = &client.jwks_uri {
        body["jwks_uri"] = json!(jwks_uri);
    } else if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    if !client.request_uris.is_empty() {
        body["request_uris"] = json!(client.request_uris);
    }
    if let Some(initiate_login_uri) = &client.initiate_login_uri {
        body["initiate_login_uri"] = json!(initiate_login_uri);
    }
    if let Some(logo_uri) = &client.presentation.logo_uri {
        body["logo_uri"] = json!(logo_uri);
    }
    if let Some(policy_uri) = &client.presentation.policy_uri {
        body["policy_uri"] = json!(policy_uri);
    }
    if let Some(tos_uri) = &client.presentation.tos_uri {
        body["tos_uri"] = json!(tos_uri);
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
            body[field] = json!(value);
        }
    }
    if let Some(secret) = issued_secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    body
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
