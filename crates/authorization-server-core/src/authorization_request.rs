use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_crypto::jwt::{Algorithm, Validation, decode};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorizationPortError, RedirectUriError, parse_resource_indicator_parameter,
    resolve_registered_redirect_uri,
};
use crate::{
    OAuthClient,
    client_assertion::{client_jwt_decoding_key, supported_client_jwt_algorithm_name},
};

pub const REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
pub const REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;

const AUTHORIZATION_REQUEST_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "resource",
    "authorization_details",
    "issuer_state",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request_uri",
    "request",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

/// Claims obtained after the protocol core has decoded and, for signed
/// request objects, cryptographically verified the compact JWT.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RequestObjectClaims {
    pub client_id: String,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<Value>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub parameters: HashMap<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestObjectPolicy<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub jti_policy: RequestObjectJtiPolicy,
    pub require_integrity_protected_parameters: bool,
    pub now: i64,
}

#[derive(Clone, Copy)]
pub struct RequestObjectVerificationInput<'a> {
    pub request_object: &'a str,
    pub client: &'a OAuthClient,
    pub expected_signing_algorithm: Option<&'a str>,
    pub require_fapi2: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRequestObject {
    pub claims: RequestObjectClaims,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectVerificationError {
    InvalidCompact,
    InvalidHeader,
    InvalidAlgorithm,
    MissingKeyId,
    InvalidKey,
    InvalidSignature,
}

#[derive(Deserialize)]
struct RequestObjectHeader {
    alg: String,
    kid: Option<String>,
    #[serde(
        rename = "crit",
        default,
        deserialize_with = "nazo_crypto::jwt::deserialize_present_header"
    )]
    critical_extension_present: bool,
}

#[derive(Deserialize)]
struct RequestObjectClient {
    client_id: String,
    iss: Option<String>,
    sub: Option<String>,
}

/// Parses and verifies a compact authorization Request Object.
///
/// All protocol cryptography and JWK policy live here. The caller supplies an
/// already loaded client and remains responsible for runtime-module admission
/// and committing the replay marker through [`crate::AuthorizationService`].
pub fn verify_request_object(
    input: RequestObjectVerificationInput<'_>,
) -> Result<VerifiedRequestObject, RequestObjectVerificationError> {
    let (header_part, payload_part, signature_part) = split_compact_jwt(input.request_object)
        .ok_or(RequestObjectVerificationError::InvalidCompact)?;
    let header = decode_request_object_header(header_part)?;
    if payload_part.is_empty() || signature_part.is_empty() {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    }
    let algorithm: Algorithm = header
        .alg
        .parse()
        .map_err(|_| RequestObjectVerificationError::InvalidAlgorithm)?;
    let Some(algorithm_name) = supported_client_jwt_algorithm_name(algorithm) else {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    };
    if (input.require_fapi2 || input.client.security_policy.requires_fapi2_security())
        && !crate::FAPI2_JWT_SIGNING_ALGS.contains(&algorithm_name)
    {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    }
    if input
        .expected_signing_algorithm
        .is_some_and(|expected| expected != algorithm_name)
    {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or(RequestObjectVerificationError::MissingKeyId)?;
    if kid.trim().is_empty() || kid.trim() != kid {
        return Err(RequestObjectVerificationError::InvalidKey);
    }
    let decoding_key = client_jwt_decoding_key(input.client, kid, algorithm)
        .ok_or(RequestObjectVerificationError::InvalidKey)?;
    let mut validation = Validation::new(algorithm);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_required_spec_claims::<&str>(&[]);
    let claims = decode::<RequestObjectClaims>(input.request_object, &decoding_key, &validation)
        .map_err(|_| RequestObjectVerificationError::InvalidSignature)?
        .claims;
    Ok(VerifiedRequestObject { claims })
}

#[must_use]
pub fn unverified_signed_request_object_client_id(request_object: &str) -> Option<String> {
    let (header, payload, signature) = split_compact_jwt(request_object)?;
    let header = decode_request_object_header(header).ok()?;
    if header.alg == "none" || signature.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: RequestObjectClient = serde_json::from_slice(&bytes).ok()?;
    let issuer_matches = claims
        .iss
        .as_deref()
        .is_none_or(|issuer| issuer == claims.client_id);
    let subject_matches = claims
        .sub
        .as_deref()
        .is_none_or(|subject| subject == claims.client_id);
    (issuer_matches && subject_matches && !claims.client_id.trim().is_empty())
        .then_some(claims.client_id)
}

/// Extracts the untrusted `kid` header from a signed request object.
///
/// This is only a key-selection hint.  Callers must still run
/// [`verify_request_object`] against the selected client keys before accepting
/// any claims or parameters.
#[must_use]
pub fn unverified_signed_request_object_kid(request_object: &str) -> Option<String> {
    let (header, _payload, signature) = split_compact_jwt(request_object)?;
    if signature.is_empty() {
        return None;
    }
    let header = decode_request_object_header(header).ok()?;
    header.alg.parse::<Algorithm>().ok()?;
    header.kid
}

fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

fn decode_request_object_header(
    header: &str,
) -> Result<RequestObjectHeader, RequestObjectVerificationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| RequestObjectVerificationError::InvalidHeader)?;
    let header: RequestObjectHeader = serde_json::from_slice(&bytes)
        .map_err(|_| RequestObjectVerificationError::InvalidHeader)?;
    if header.critical_extension_present {
        return Err(RequestObjectVerificationError::InvalidHeader);
    }
    Ok(header)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestObjectReplay {
    pub client_id: String,
    pub jti: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRequestObject {
    pub parameters: HashMap<String, String>,
    pub replay: Option<RequestObjectReplay>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRequestError {
    InvalidRequest,
    InvalidRequestObject,
    RequestObjectClaims,
    RequestObjectContainsRequestUri,
    RequestObjectParameterType,
    OuterClientIdConflict,
    SignedRequestObjectMissingRedirectUri,
    OuterAuthorizationParametersConflict,
    InvalidRequestObjectReplay,
    InvalidTarget,
    UnsupportedResponseType,
    UnauthorizedClient,
    InvalidClient,
    Dependency(AuthorizationPortError),
}

impl AuthorizationRequestError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::OuterClientIdConflict => "invalid_request",
            Self::InvalidRequestObject
            | Self::RequestObjectClaims
            | Self::RequestObjectContainsRequestUri
            | Self::RequestObjectParameterType
            | Self::SignedRequestObjectMissingRedirectUri
            | Self::OuterAuthorizationParametersConflict
            | Self::InvalidRequestObjectReplay => "invalid_request_object",
            Self::InvalidTarget => "invalid_target",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidClient => "invalid_client",
            Self::Dependency(_) => "server_error",
        }
    }
}

/// Applies request-object policy while reusing the verified claims and outer map.
/// Policy failures leave the caller's outer parameters untouched.
pub fn normalize_request_object(
    outer: &mut HashMap<String, String>,
    claims: RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
    if claims.client_id != policy.client_id
        || !request_object_party_claims_valid(&claims, policy)
        || !request_object_audience_valid(&claims, policy)
        || !request_object_times_valid(&claims, policy)
        || !request_object_jti_valid(&claims, policy)
    {
        return Err(AuthorizationRequestError::RequestObjectClaims);
    }

    let mut request_parameters = request_object_parameters(claims.parameters)?;
    if outer
        .get("client_id")
        .is_some_and(|outer_client_id| outer_client_id != &claims.client_id)
    {
        return Err(AuthorizationRequestError::OuterClientIdConflict);
    }
    if !request_parameters.contains_key("redirect_uri") {
        return Err(AuthorizationRequestError::SignedRequestObjectMissingRedirectUri);
    }
    if policy.require_integrity_protected_parameters
        && outer_authorization_parameters_conflict(outer, &request_parameters)
    {
        return Err(AuthorizationRequestError::OuterAuthorizationParametersConflict);
    }

    let replay = claims.jti.map(|jti| RequestObjectReplay {
        client_id: claims.client_id.clone(),
        jti,
        expires_at: claims
            .exp
            .expect("request object time policy already validated"),
    });
    request_parameters.insert("client_id".to_owned(), claims.client_id);
    let mut parameters = std::mem::take(outer);
    if policy.require_integrity_protected_parameters {
        parameters.retain(|key, _| matches!(key.as_str(), "request" | "client_id"));
    } else {
        parameters.retain(|key, _| key == "request" || !request_parameters.contains_key(key));
    }
    parameters.extend(request_parameters);
    Ok(NormalizedRequestObject { parameters, replay })
}

fn request_object_party_claims_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    claims.iss.as_deref() == Some(policy.client_id)
        && claims
            .sub
            .as_deref()
            .is_none_or(|subject| subject == policy.client_id)
}

fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    match &claims.aud {
        Some(Value::String(audience)) => {
            audience == policy.issuer || audience.strip_suffix("/authorize") == Some(policy.issuer)
        }
        Some(Value::Array(audiences)) => audiences.iter().any(|audience| {
            audience.as_str().is_some_and(|audience| {
                audience == policy.issuer
                    || audience.strip_suffix("/authorize") == Some(policy.issuer)
            })
        }),
        _ => false,
    }
}

fn request_object_times_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    let now = policy.now;
    let expiry = match claims.exp {
        Some(expiry) if expiry <= now => return false,
        Some(expiry) => expiry,
        None => return false,
    };
    let not_before = match claims.nbf {
        Some(not_before) => not_before,
        None => return false,
    };
    if not_before > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if now.saturating_sub(not_before) > REQUEST_OBJECT_MAX_TTL_SECONDS
        || expiry <= not_before
        || expiry.saturating_sub(not_before)
            > REQUEST_OBJECT_MAX_TTL_SECONDS.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
    {
        return false;
    }
    !claims.iat.is_some_and(|issued_at| {
        issued_at > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(issued_at) > REQUEST_OBJECT_MAX_TTL_SECONDS
    })
}

fn request_object_jti_valid(claims: &RequestObjectClaims, policy: RequestObjectPolicy<'_>) -> bool {
    match &claims.jti {
        Some(jti) => {
            let jti = jti.trim();
            !jti.is_empty() && jti.len() <= 128
        }
        None if policy.jti_policy == RequestObjectJtiPolicy::RequiredForSignedJar => false,
        None => true,
    }
}

fn request_object_parameters(
    claims: HashMap<String, Value>,
) -> Result<HashMap<String, String>, AuthorizationRequestError> {
    if claims.contains_key("request_uri") {
        return Err(AuthorizationRequestError::RequestObjectContainsRequestUri);
    }
    let mut parameters = HashMap::new();
    for (key, value) in claims {
        if matches!(key.as_str(), "request" | "client_id")
            || !AUTHORIZATION_REQUEST_PARAMETERS.contains(&key.as_str())
        {
            continue;
        }
        let value = if key == "resource" {
            let values = match value {
                Value::String(value) => vec![value],
                Value::Array(values) => values
                    .into_iter()
                    .map(|value| match value {
                        Value::String(value) => Some(value),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or(AuthorizationRequestError::RequestObjectParameterType)?,
                _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
            };
            crate::encode_resource_indicators(&values)
                .ok_or(AuthorizationRequestError::RequestObjectParameterType)?
        } else {
            match value {
                Value::String(value) => value,
                Value::Number(value) => value.to_string(),
                Value::Object(_) if key == "claims" => value.to_string(),
                Value::Array(_) if key == "authorization_details" => value.to_string(),
                _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
            }
        };
        parameters.insert(key, value);
    }
    Ok(parameters)
}

fn outer_authorization_parameters_conflict(
    outer: &HashMap<String, String>,
    request: &HashMap<String, String>,
) -> bool {
    AUTHORIZATION_REQUEST_PARAMETERS.iter().any(|key| {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            return false;
        }
        let (Some(outer), Some(request)) = (outer.get(*key), request.get(*key)) else {
            return false;
        };
        if *key == "resource" {
            parse_resource_indicator_parameter(Some(outer)).ok()
                != parse_resource_indicator_parameter(Some(request)).ok()
        } else {
            outer != request
        }
    })
}

#[derive(Clone, Copy, Debug)]
pub struct RawParAdmissionPolicy<'a> {
    pub client_is_confidential: bool,
    pub client_authentication_method: &'a str,
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub require_request_object: bool,
    pub fapi2_security: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ExpandedParAdmissionPolicy<'a> {
    pub client_type: &'a str,
    pub redirect_uris: &'a [String],
    pub allowed_scopes: &'a [String],
    pub capabilities: crate::AuthorizationCapabilityPolicy,
    pub signed_authorization_response_required: bool,
    pub allowed_audiences: &'a [String],
    pub pkce_required: bool,
    pub fapi2_requires_explicit_redirect_uri: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParAdmission {
    pub redirect_uri: String,
    pub resources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParAdmissionError {
    RequestUriNotAllowed,
    Authorization(crate::AuthorizationPolicyError),
    RequestObjectRequired,
    ConfidentialClientRequired,
    StrongClientAuthenticationRequired,
    SenderConstraintRequired,
    ExplicitRedirectUriRequired,
    RedirectUriRequired,
    RedirectUriNotRegistered,
}

impl ParAdmissionError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::RequestUriNotAllowed => "invalid_request_object",
            Self::Authorization(error) => error.oauth_error(),
            Self::ConfidentialClientRequired => "unauthorized_client",
            Self::StrongClientAuthenticationRequired => "invalid_client",
            Self::RequestObjectRequired
            | Self::SenderConstraintRequired
            | Self::ExplicitRedirectUriRequired
            | Self::RedirectUriRequired
            | Self::RedirectUriNotRegistered => "invalid_request",
        }
    }
}

/// Validates client and raw-form policy after client authentication, before a
/// signed Request Object is expanded. Authentication parameters remain a
/// transport concern and are not accepted by this policy function.
pub fn validate_raw_par_admission(
    parameters: &HashMap<String, String>,
    policy: RawParAdmissionPolicy<'_>,
) -> Result<(), ParAdmissionError> {
    if policy.fapi2_security {
        if !policy.client_is_confidential {
            return Err(ParAdmissionError::ConfidentialClientRequired);
        }
        if !matches!(
            policy.client_authentication_method,
            "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
        ) {
            return Err(ParAdmissionError::StrongClientAuthenticationRequired);
        }
        if !(policy.require_dpop_bound_tokens || policy.require_mtls_bound_tokens) {
            return Err(ParAdmissionError::SenderConstraintRequired);
        }
    }
    if policy.require_request_object && !parameters.contains_key("request") {
        return Err(ParAdmissionError::RequestObjectRequired);
    }
    Ok(())
}

/// Validates the authorization parameters after any signed Request Object has
/// been expanded, but before DPoP verification or PAR state persistence.
pub fn validate_expanded_par_admission(
    parameters: &HashMap<String, String>,
    policy: ExpandedParAdmissionPolicy<'_>,
) -> Result<ParAdmission, ParAdmissionError> {
    if parameters.contains_key("request_uri") {
        return Err(ParAdmissionError::RequestUriNotAllowed);
    }
    if policy.fapi2_requires_explicit_redirect_uri && !parameters.contains_key("redirect_uri") {
        return Err(ParAdmissionError::ExplicitRedirectUriRequired);
    }
    let redirect_uri = resolve_registered_redirect_uri(
        policy.client_type,
        policy.redirect_uris,
        parameters.get("redirect_uri").map(String::as_str),
    )
    .map_err(|error| match error {
        RedirectUriError::Missing => ParAdmissionError::RedirectUriRequired,
        RedirectUriError::Invalid => ParAdmissionError::RedirectUriNotRegistered,
    })?;
    let normalized = crate::normalize_authorization_request(
        parameters,
        crate::AuthorizationClientPolicy {
            client_type: policy.client_type,
            allowed_scopes: policy.allowed_scopes,
            allowed_audiences: policy.allowed_audiences,
        },
        policy.capabilities,
        crate::AuthorizationProfilePolicy {
            signed_authorization_response_required: policy.signed_authorization_response_required,
            pkce_required: policy.pkce_required,
        },
    )
    .map_err(ParAdmissionError::Authorization)?;
    Ok(ParAdmission {
        redirect_uri,
        resources: normalized.resources,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushedAuthorizationRequestConsumeError {
    Missing,
    Dependency(AuthorizationPortError),
}

pub(crate) fn classify_request_object_replay(
    result: Result<bool, AuthorizationPortError>,
) -> Result<(), AuthorizationRequestError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(AuthorizationRequestError::InvalidRequestObjectReplay),
        Err(error) => Err(AuthorizationRequestError::Dependency(error)),
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization_request.rs"]
mod tests;
