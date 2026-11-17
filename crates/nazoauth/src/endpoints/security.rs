use super::mtls::with_request_mtls_client_certificate;
use crate::http::Request as HttpRequest;
use http::{
    HeaderMap,
    header::{self, HeaderValue},
};
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, PresentedClientCredentials as ClientCredentials,
    unverified_client_assertion_client_id,
};
pub fn has_basic_authorization_scheme(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get(header::AUTHORIZATION)
        .map(HeaderValue::as_bytes)
    else {
        return false;
    };
    let start = raw
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    raw[start..end].eq_ignore_ascii_case(b"Basic")
}

pub fn extract_client_credentials(
    req: &HttpRequest,
    form_client_id: Option<&str>,
    form_secret: Option<&str>,
    form_assertion_type: Option<&str>,
    form_assertion: Option<&str>,
) -> ClientCredentials {
    let facts = crate::http::token_client_auth_transport_facts(
        req,
        crate::http::TokenClientAuthForm {
            client_id: form_client_id,
            client_secret: form_secret,
            client_assertion_type: form_assertion_type,
            client_assertion: form_assertion,
        },
    );
    let assertion_client_id = facts
        .client_assertion()
        .filter(|_| facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER))
        .and_then(unverified_client_assertion_client_id);
    let presentation = facts.presentation();
    let mtls_client_id = if !presentation.http_basic
        && !presentation.client_assertion_type
        && !presentation.client_assertion
        && form_secret.is_none()
    {
        form_client_id.filter(|_| {
            with_request_mtls_client_certificate(req, |certificate| certificate.is_some())
        })
    } else {
        None
    };
    facts.presented_credentials(assertion_client_id.as_deref(), mtls_client_id)
}
