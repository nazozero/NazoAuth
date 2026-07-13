use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorizationPortError, RedirectUriError, is_subset, parse_resource_indicator_parameter,
    resolve_registered_redirect_uri,
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
pub enum RequestObjectMode {
    BasicOidc,
    SignedJar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

/// Claims obtained after the transport adapter has decoded and, for signed
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
    pub mode: RequestObjectMode,
    pub jti_policy: RequestObjectJtiPolicy,
    pub unsigned_request_object_allowed: bool,
    pub require_integrity_protected_parameters: bool,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestObjectReplay {
    pub client_id: String,
    pub jti: String,
    pub ttl_seconds: u64,
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
    RequestObjectSigningPolicy,
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
            | Self::RequestObjectSigningPolicy
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

/// Applies request-object claim and parameter policy after signature handling.
/// No replay state is mutated until all pure validation has succeeded.
pub fn normalize_request_object(
    outer: &HashMap<String, String>,
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
    if policy.mode == RequestObjectMode::BasicOidc && !policy.unsigned_request_object_allowed {
        return Err(AuthorizationRequestError::RequestObjectSigningPolicy);
    }
    if claims.client_id != policy.client_id
        || !request_object_party_claims_valid(claims, policy)
        || !request_object_audience_valid(claims, policy)
        || !request_object_times_valid(claims, policy)
        || !request_object_jti_valid(claims, policy)
    {
        return Err(AuthorizationRequestError::RequestObjectClaims);
    }

    let mut request_parameters = request_object_parameters(claims)?;
    request_parameters.insert("client_id".to_owned(), claims.client_id.clone());
    if outer
        .get("client_id")
        .is_some_and(|outer_client_id| outer_client_id != &claims.client_id)
    {
        return Err(AuthorizationRequestError::OuterClientIdConflict);
    }
    if policy.mode == RequestObjectMode::SignedJar
        && !request_parameters.contains_key("redirect_uri")
    {
        return Err(AuthorizationRequestError::SignedRequestObjectMissingRedirectUri);
    }
    if policy.require_integrity_protected_parameters
        && outer_authorization_parameters_conflict(outer, &request_parameters)
    {
        return Err(AuthorizationRequestError::OuterAuthorizationParametersConflict);
    }

    let replay = request_object_replay(claims, policy)?;
    let mut parameters = outer.clone();
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
    match policy.mode {
        RequestObjectMode::BasicOidc => {
            claims
                .iss
                .as_deref()
                .is_none_or(|issuer| issuer == policy.client_id)
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|subject| subject == policy.client_id)
        }
        RequestObjectMode::SignedJar => {
            claims.iss.as_deref() == Some(policy.client_id)
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|subject| subject == policy.client_id)
        }
    }
}

fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    match (&claims.aud, policy.mode) {
        (Some(Value::String(audience)), _) => {
            audience == policy.issuer || audience == &format!("{}/authorize", policy.issuer)
        }
        (Some(Value::Array(audiences)), _) => audiences.iter().any(|audience| {
            audience.as_str().is_some_and(|audience| {
                audience == policy.issuer || audience == format!("{}/authorize", policy.issuer)
            })
        }),
        (None, RequestObjectMode::BasicOidc) => true,
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
        None if policy.mode == RequestObjectMode::SignedJar => return false,
        None => now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS),
    };
    let not_before = match claims.nbf {
        Some(not_before) => not_before,
        None if policy.mode == RequestObjectMode::SignedJar => return false,
        None => now,
    };
    if not_before > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if policy.mode == RequestObjectMode::SignedJar {
        if now.saturating_sub(not_before) > REQUEST_OBJECT_MAX_TTL_SECONDS
            || expiry <= not_before
            || expiry.saturating_sub(not_before)
                > REQUEST_OBJECT_MAX_TTL_SECONDS.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        {
            return false;
        }
    } else if expiry > now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS) {
        return false;
    }
    !claims.iat.is_some_and(|issued_at| {
        issued_at > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(issued_at) > REQUEST_OBJECT_MAX_TTL_SECONDS
    })
}

fn request_object_jti_valid(claims: &RequestObjectClaims, policy: RequestObjectPolicy<'_>) -> bool {
    match (&claims.jti, policy.mode) {
        (Some(jti), _) => {
            let jti = jti.trim();
            !jti.is_empty() && jti.len() <= 128
        }
        (None, RequestObjectMode::SignedJar)
            if policy.jti_policy == RequestObjectJtiPolicy::RequiredForSignedJar =>
        {
            false
        }
        (None, _) => true,
    }
}

fn request_object_replay(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<Option<RequestObjectReplay>, AuthorizationRequestError> {
    let Some(jti) = claims.jti.as_ref() else {
        return Ok(None);
    };
    let ttl_seconds = match claims.exp {
        Some(expiry) => expiry
            .saturating_sub(policy.now)
            .clamp(1, REQUEST_OBJECT_MAX_TTL_SECONDS) as u64,
        None if policy.mode == RequestObjectMode::BasicOidc => {
            REQUEST_OBJECT_MAX_TTL_SECONDS as u64
        }
        None => return Err(AuthorizationRequestError::RequestObjectClaims),
    };
    Ok(Some(RequestObjectReplay {
        client_id: claims.client_id.clone(),
        jti: jti.clone(),
        ttl_seconds,
    }))
}

fn request_object_parameters(
    claims: &RequestObjectClaims,
) -> Result<HashMap<String, String>, AuthorizationRequestError> {
    if claims.parameters.contains_key("request_uri") {
        return Err(AuthorizationRequestError::RequestObjectContainsRequestUri);
    }
    let mut parameters = HashMap::new();
    for key in AUTHORIZATION_REQUEST_PARAMETERS {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            continue;
        }
        let Some(value) = claims.parameters.get(*key) else {
            continue;
        };
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Object(_) if *key == "claims" => value.to_string(),
            Value::Array(_) if matches!(*key, "authorization_details" | "resource") => {
                value.to_string()
            }
            _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
        };
        parameters.insert((*key).to_owned(), value);
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
    pub allowed_audiences: &'a [String],
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
    UnsupportedResponseType,
    RequestObjectRequired,
    ConfidentialClientRequired,
    StrongClientAuthenticationRequired,
    SenderConstraintRequired,
    ExplicitRedirectUriRequired,
    RedirectUriRequired,
    RedirectUriNotRegistered,
    InvalidResource,
    ResourceNotAllowed,
}

impl ParAdmissionError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::RequestUriNotAllowed => "invalid_request_object",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ConfidentialClientRequired => "unauthorized_client",
            Self::StrongClientAuthenticationRequired => "invalid_client",
            Self::RequestObjectRequired
            | Self::SenderConstraintRequired
            | Self::ExplicitRedirectUriRequired
            | Self::RedirectUriRequired
            | Self::RedirectUriNotRegistered => "invalid_request",
            Self::InvalidResource | Self::ResourceNotAllowed => "invalid_target",
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
    if parameters
        .get("response_type")
        .is_some_and(|response_type| response_type != "code")
    {
        return Err(ParAdmissionError::UnsupportedResponseType);
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
    let resources =
        parse_resource_indicator_parameter(parameters.get("resource").map(String::as_str))
            .map_err(|_| ParAdmissionError::InvalidResource)?;
    if !resources.is_empty() && !is_subset(&resources, policy.allowed_audiences) {
        return Err(ParAdmissionError::ResourceNotAllowed);
    }
    Ok(ParAdmission {
        redirect_uri,
        resources,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushedAuthorizationRequestConsumeError {
    Missing,
    Malformed,
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
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn signed_policy(now: i64) -> RequestObjectPolicy<'static> {
        RequestObjectPolicy {
            issuer: "https://issuer.example",
            client_id: "client",
            mode: RequestObjectMode::SignedJar,
            jti_policy: RequestObjectJtiPolicy::RequiredForSignedJar,
            unsigned_request_object_allowed: false,
            require_integrity_protected_parameters: true,
            now,
        }
    }

    fn signed_claims(now: i64) -> RequestObjectClaims {
        RequestObjectClaims {
            client_id: "client".to_owned(),
            iss: Some("client".to_owned()),
            sub: Some("client".to_owned()),
            aud: Some(json!(["unrelated", "https://issuer.example/authorize"])),
            exp: Some(now + 120),
            nbf: Some(now - 1),
            iat: Some(now - 1),
            jti: Some("unique".to_owned()),
            parameters: HashMap::from([
                (
                    "redirect_uri".to_owned(),
                    json!("https://client.example/cb"),
                ),
                ("scope".to_owned(), json!("openid")),
            ]),
        }
    }

    #[test]
    fn signed_request_object_is_normalized_only_after_all_claim_checks() {
        let now = 1_700_000_000;
        let outer = HashMap::from([
            ("client_id".to_owned(), "client".to_owned()),
            ("request".to_owned(), "jwt".to_owned()),
            ("scope".to_owned(), "openid".to_owned()),
            ("state".to_owned(), "unprotected".to_owned()),
        ]);
        let normalized = normalize_request_object(&outer, &signed_claims(now), signed_policy(now))
            .expect("valid signed request object");
        assert_eq!(
            normalized.parameters.get("scope").map(String::as_str),
            Some("openid")
        );
        assert!(!normalized.parameters.contains_key("state"));
        assert_eq!(
            normalized.replay.expect("replay instruction").ttl_seconds,
            120
        );
    }

    #[test]
    fn signed_request_object_rejects_conflicts_and_reserved_request_uri() {
        let now = 1_700_000_000;
        let claims = signed_claims(now);
        let conflicting = HashMap::from([
            ("client_id".to_owned(), "client".to_owned()),
            ("scope".to_owned(), "email".to_owned()),
        ]);
        assert_eq!(
            normalize_request_object(&conflicting, &claims, signed_policy(now)),
            Err(AuthorizationRequestError::OuterAuthorizationParametersConflict)
        );
        let mut claims = claims;
        claims
            .parameters
            .insert("request_uri".to_owned(), json!("urn:forbidden"));
        assert_eq!(
            normalize_request_object(&HashMap::new(), &claims, signed_policy(now)),
            Err(AuthorizationRequestError::RequestObjectContainsRequestUri)
        );
    }

    #[test]
    fn replay_and_dependency_failures_are_fail_closed_and_keep_error_categories() {
        assert_eq!(classify_request_object_replay(Ok(true)), Ok(()));
        assert_eq!(
            classify_request_object_replay(Ok(false)),
            Err(AuthorizationRequestError::InvalidRequestObjectReplay)
        );
        assert_eq!(
            classify_request_object_replay(Err(AuthorizationPortError::Unavailable)),
            Err(AuthorizationRequestError::Dependency(
                AuthorizationPortError::Unavailable
            ))
        );
    }

    #[test]
    fn par_fapi_policy_requires_confidential_strong_auth_and_sender_constraint() {
        let redirect_uris = vec!["https://client.example/cb".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let parameters = HashMap::from([
            ("response_type".to_owned(), "code".to_owned()),
            ("redirect_uri".to_owned(), redirect_uris[0].clone()),
            ("request".to_owned(), "signed.jwt".to_owned()),
            (
                "resource".to_owned(),
                "[\"https://api.example\"]".to_owned(),
            ),
        ]);
        let raw = RawParAdmissionPolicy {
            client_is_confidential: true,
            client_authentication_method: "private_key_jwt",
            require_dpop_bound_tokens: true,
            require_mtls_bound_tokens: false,
            require_request_object: true,
            fapi2_security: true,
        };
        let expanded = ExpandedParAdmissionPolicy {
            client_type: "confidential",
            redirect_uris: &redirect_uris,
            allowed_audiences: &audiences,
            fapi2_requires_explicit_redirect_uri: true,
        };
        assert!(validate_raw_par_admission(&parameters, raw).is_ok());
        assert!(validate_expanded_par_admission(&parameters, expanded).is_ok());
        assert_eq!(
            validate_raw_par_admission(
                &parameters,
                RawParAdmissionPolicy {
                    client_is_confidential: false,
                    ..raw
                }
            ),
            Err(ParAdmissionError::ConfidentialClientRequired)
        );
        assert_eq!(
            validate_raw_par_admission(
                &parameters,
                RawParAdmissionPolicy {
                    require_dpop_bound_tokens: false,
                    ..raw
                }
            ),
            Err(ParAdmissionError::SenderConstraintRequired)
        );
        let mut nested = parameters;
        nested.insert("request_uri".to_owned(), "urn:forbidden".to_owned());
        assert_eq!(
            validate_expanded_par_admission(&nested, expanded),
            Err(ParAdmissionError::RequestUriNotAllowed)
        );
    }

    proptest! {
        #[test]
        fn signed_request_object_time_window_is_bounded(
            age in 0_i64..1_000,
            lifetime in 1_i64..1_000,
        ) {
            let now = 1_700_000_000;
            let mut claims = signed_claims(now);
            claims.nbf = Some(now - age);
            claims.iat = Some(now - age);
            claims.exp = Some(now - age + lifetime);
            let accepted = normalize_request_object(&HashMap::new(), &claims, signed_policy(now)).is_ok();
            let expected = age <= REQUEST_OBJECT_MAX_TTL_SECONDS
                && lifetime <= REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS
                && lifetime > age;
            prop_assert_eq!(accepted, expected);
        }
    }
}
