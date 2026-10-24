use actix_web::{
    HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderMap, HeaderName, HeaderValue},
    },
};
use nazo_auth::DpopError;
use nazo_oauth_server::contracts::request_facts::DpopErrorContext;

use crate::oauth_error;

/// Preserve the request target authority; connection_info() also trusts
/// forwarding headers and therefore cannot supply this fact.
pub fn dpop_request_authority(request: &actix_web::HttpRequest) -> Option<&str> {
    let mut hosts = request.headers().get_all(header::HOST);
    let host = hosts.next().map(|value| value.to_str()).transpose().ok()?;
    if hosts.next().is_some() {
        return None;
    }
    match (request.uri().authority(), host) {
        (Some(authority), Some(host)) if !authority.as_str().eq_ignore_ascii_case(host) => None,
        (Some(authority), _) => Some(authority.as_str()),
        (None, host) => host,
    }
}

pub fn dpop_proof_present(headers: &HeaderMap) -> bool {
    headers.contains_key(HeaderName::from_static("dpop"))
}

pub fn dpop_proof_header(headers: &HeaderMap) -> Result<Option<&str>, DpopError> {
    let mut values = headers.get_all(HeaderName::from_static("dpop"));
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(DpopError::MalformedProof);
    }
    let value = value
        .to_str()
        .map_err(|_| DpopError::MalformedProof)?
        .trim();
    Ok((!value.is_empty()).then_some(value))
}

pub fn dpop_error_response(error: DpopError, context: DpopErrorContext) -> HttpResponse {
    let description = match &error {
        DpopError::MissingProof => "DPoP proof is required.",
        DpopError::MalformedProof => "DPoP proof is malformed.",
        DpopError::InvalidProof => "DPoP proof validation failed.",
        DpopError::ReplayDetected(_) => "DPoP proof jti has already been used.",
        DpopError::BindingMismatch => "DPoP binding mismatch.",
        DpopError::TokenNotBound => "Token is not DPoP-bound.",
        DpopError::UseNonce(_) => "Authorization server requires nonce in DPoP proof.",
        DpopError::StateStoreUnavailable => "DPoP nonce validation is unavailable.",
    };
    let status = match (&error, context) {
        (DpopError::MissingProof, DpopErrorContext::TokenEndpoint) => StatusCode::BAD_REQUEST,
        (DpopError::MissingProof | DpopError::UseNonce(_), DpopErrorContext::ProtectedResource) => {
            StatusCode::UNAUTHORIZED
        }
        (DpopError::StateStoreUnavailable, _) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let (error_code, challenge) = match &error {
        DpopError::UseNonce(_) => ("use_dpop_nonce", "DPoP error=\"use_dpop_nonce\""),
        DpopError::StateStoreUnavailable => ("server_error", "DPoP error=\"server_error\""),
        _ => ("invalid_dpop_proof", "DPoP error=\"invalid_dpop_proof\""),
    };
    let mut response = oauth_error(status, error_code, description);
    if context == DpopErrorContext::TokenEndpoint {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    if let DpopError::UseNonce(nonce) = error
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(challenge),
    );
    response
}

#[cfg(test)]
#[path = "../tests/unit/dpop.rs"]
mod tests;
