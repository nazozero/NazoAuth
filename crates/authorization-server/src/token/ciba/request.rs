use super::{
    policy::{ciba_algorithm_name, ciba_invalid_request, ciba_jwt_signing_algorithm_supported},
    state::{
        CIBA_BINDING_MESSAGE_MAX_CHARS, CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS,
        CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS, CibaConfig,
    },
};
use crate::{
    contracts::{
        ciba::{
            BackchannelAuthenticationForm, CibaAuthenticationRequestClaims,
            CibaRequestObjectReplay, UnverifiedCibaAuthenticationRequestClaims,
        },
        oauth_error::OAuthEndpointError,
    },
    crypto::client_jwt_decoding_key,
    domain::rows::ClientRow,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use http::StatusCode;
use serde_json::Value;
pub(crate) fn validate_and_apply_ciba_request_object_claims_with_config(
    config: &CibaConfig,
    client: &ClientRow,
    form: &mut BackchannelAuthenticationForm,
) -> Result<Option<CibaRequestObjectReplay>, OAuthEndpointError> {
    let Some(request_object) = form.request.as_deref() else {
        return Ok(None);
    };
    if form.has_outer_authentication_parameters() {
        return Err(ciba_invalid_request(
            "CIBA signed requests must not include outer authentication parameters.",
        ));
    }
    let claims = signed_ciba_request_object_claims(request_object, client)?;
    let now = Utc::now().timestamp();
    if claims.iss.as_deref() != Some(client.client_id.as_str())
        || !ciba_request_object_audience_valid(&claims, &config.issuer)
        || !ciba_request_object_times_valid(&claims, now)
        || !ciba_request_object_jti_valid(claims.jti.as_deref())
        || ciba_request_object_hint_count(&claims) != 1
        || claims.login_hint.as_deref().is_none_or(str::is_empty)
    {
        return Err(ciba_invalid_request(
            "CIBA request object claims are invalid.",
        ));
    }
    let replay = CibaRequestObjectReplay {
        jti: claims
            .jti
            .clone()
            .expect("validated CIBA request object has jti"),
        expires_at: claims.exp.expect("validated CIBA request object has exp"),
    };
    if let Some(binding_message) = claims.binding_message.as_deref()
        && !ciba_binding_message_is_supported(binding_message)
    {
        return Err(OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_binding_message",
            "CIBA binding_message is unsupported.",
        ));
    }
    form.scope = request_object_string(claims.scope)?;
    form.login_hint = request_object_string(claims.login_hint)?;
    form.id_token_hint = request_object_string(claims.id_token_hint)?;
    form.login_hint_token = request_object_string(claims.login_hint_token)?;
    form.binding_message = request_object_string(claims.binding_message)?;
    form.acr_values = request_object_string(claims.acr_values)?;
    form.client_notification_token = request_object_string(claims.client_notification_token)?;
    form.requested_expiry_seconds = match claims.requested_expiry {
        Some(value) => Some(ciba_requested_expiry_seconds(&value).ok_or_else(|| {
            ciba_invalid_request("CIBA request object requested_expiry is invalid.")
        })?),
        None => None,
    };
    Ok(Some(replay))
}

pub(crate) fn signed_ciba_request_object_claims(
    request_object: &str,
    client: &ClientRow,
) -> Result<CibaAuthenticationRequestClaims, OAuthEndpointError> {
    let Some((header_part, _payload_part, signature_part)) = split_compact_jwt(request_object)
    else {
        return Err(ciba_invalid_request(
            "CIBA request object is not a compact JWT.",
        ));
    };
    if signature_part.is_empty() {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header_value = decode_jwt_header_value(header_part)?;
    if header_value.get("alg").and_then(Value::as_str) == Some("none") {
        return Err(ciba_invalid_request("CIBA request object must be signed."));
    }
    let header = nazo_crypto::jwt::decode_header(request_object)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    if !ciba_jwt_signing_algorithm_supported(header.alg) {
        return Err(ciba_invalid_request(
            "CIBA request object signing algorithm is unsupported.",
        ));
    }
    if let Some(expected) = client
        .backchannel_authentication_request_signing_alg
        .as_deref()
        && ciba_algorithm_name(header.alg) != Some(expected)
    {
        return Err(ciba_invalid_request(
            "CIBA request object signing algorithm does not match client registration.",
        ));
    }
    let Some(kid) = header.kid.as_deref() else {
        return Err(ciba_invalid_request("CIBA request object is missing kid."));
    };
    let Some(decoding_key) = client_jwt_decoding_key(client, kid, header.alg) else {
        return Err(ciba_invalid_request(
            "CIBA request object signing key is invalid.",
        ));
    };
    let mut validation = nazo_crypto::jwt::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_required_spec_claims::<&str>(&[]);
    validation.set_issuer(&[client.client_id.as_str()]);
    nazo_crypto::jwt::decode::<CibaAuthenticationRequestClaims>(
        request_object,
        &decoding_key,
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| ciba_invalid_request("CIBA request object signature is invalid."))
}

pub(crate) fn apply_ciba_request_object_client_id_hint(
    form: &mut BackchannelAuthenticationForm,
    has_basic: bool,
    has_assertion: bool,
) {
    if form.client_id.is_some() || has_basic || has_assertion {
        return;
    }
    if let Some(client_id) = form
        .request
        .as_deref()
        .and_then(unverified_signed_ciba_request_object_client_id)
    {
        form.client_id = Some(client_id);
    }
}

pub(crate) fn unverified_signed_ciba_request_object_client_id(
    request_object: &str,
) -> Option<String> {
    let (header_part, payload_part, signature_part) = split_compact_jwt(request_object)?;
    if signature_part.is_empty() {
        return None;
    }
    let header_value = decode_jwt_header_value(header_part).ok()?;
    if header_value.get("alg").and_then(Value::as_str) == Some("none") {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload_part).ok()?;
    let claims: UnverifiedCibaAuthenticationRequestClaims = serde_json::from_slice(&bytes).ok()?;
    let issuer = claims.iss?.trim().to_owned();
    if issuer.is_empty() {
        return None;
    }
    let subject_matches = claims
        .sub
        .as_deref()
        .is_none_or(|subject| subject == issuer);
    subject_matches.then_some(issuer)
}

pub(crate) fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

pub(crate) fn decode_jwt_header_value(header: &str) -> Result<Value, OAuthEndpointError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ciba_invalid_request("CIBA request object header is invalid."))
}

pub(crate) fn ciba_request_object_audience_valid(
    claims: &CibaAuthenticationRequestClaims,
    issuer: &str,
) -> bool {
    let Some(aud) = claims.aud.as_ref() else {
        return false;
    };
    match aud {
        Value::String(value) => value == issuer,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(issuer)),
        _ => false,
    }
}

pub(crate) fn ciba_request_object_times_valid(
    claims: &CibaAuthenticationRequestClaims,
    now: i64,
) -> bool {
    let Some(exp) = claims.exp else {
        return false;
    };
    let Some(nbf) = claims.nbf else {
        return false;
    };
    let Some(iat) = claims.iat else {
        return false;
    };
    if exp <= now || nbf > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if now.saturating_sub(nbf) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS {
        return false;
    }
    if exp <= nbf
        || exp.saturating_sub(nbf)
            > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
                .saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
    {
        return false;
    }
    if iat > now.saturating_add(CIBA_REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        || now.saturating_sub(iat) > CIBA_REQUEST_OBJECT_MAX_TTL_SECONDS
    {
        return false;
    }
    true
}

pub(crate) fn ciba_request_object_jti_valid(jti: Option<&str>) -> bool {
    let Some(jti) = jti else {
        return false;
    };
    let trimmed = jti.trim();
    !trimmed.is_empty() && trimmed.len() <= 128
}

pub(crate) fn ciba_request_object_hint_count(claims: &CibaAuthenticationRequestClaims) -> usize {
    [
        claims.login_hint.as_deref(),
        claims.id_token_hint.as_deref(),
        claims.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

pub(crate) fn ciba_hint_count(form: &BackchannelAuthenticationForm) -> usize {
    [
        form.login_hint.as_deref(),
        form.id_token_hint.as_deref(),
        form.login_hint_token.as_deref(),
    ]
    .into_iter()
    .filter(|value| value.is_some_and(|value| !value.trim().is_empty()))
    .count()
}

pub(crate) fn ciba_selected_acr(acr_values: Option<&str>) -> Option<String> {
    acr_values?
        .split_ascii_whitespace()
        .find(|value| *value == "1")
        .map(ToOwned::to_owned)
}

pub(crate) fn ciba_binding_message_is_supported(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.chars().count() <= CIBA_BINDING_MESSAGE_MAX_CHARS
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii() && !ch.is_ascii_control())
}

pub(crate) fn validate_ciba_binding_message(
    form: &BackchannelAuthenticationForm,
) -> Result<(), OAuthEndpointError> {
    if form
        .binding_message
        .as_deref()
        .is_some_and(|value| !ciba_binding_message_is_supported(value))
    {
        return Err(OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_binding_message",
            "CIBA binding_message is unsupported.",
        ));
    }
    Ok(())
}

fn request_object_string(value: Option<String>) -> Result<Option<String>, OAuthEndpointError> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                return Err(ciba_invalid_request(
                    "CIBA request object parameter is empty.",
                ));
            }
            Ok(value)
        })
        .transpose()
}

pub(crate) fn ciba_requested_expiry_seconds(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => parse_requested_expiry_string(value),
        _ => None,
    }
    .filter(|seconds| *seconds > 0)
}

pub fn parse_requested_expiry_string(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
}

#[cfg(test)]
#[path = "../../../tests/unit/token/ciba/request.rs"]
mod tests;
