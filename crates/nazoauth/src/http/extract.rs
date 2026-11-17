use crate::http::{Request, Response};
use http::{HeaderMap, Method, header};
use std::borrow::Cow;

use nazo_oauth_server::contracts::userinfo::AccessTokenAuthScheme;
use serde_json::json;

use crate::http::{authorization_error_response, json_response_no_store};

pub fn parse_mfa_json<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, Response> {
    super::parse_json(request).map_err(|_| invalid_mfa_json_response())
}

pub(super) fn invalid_mfa_json_response() -> Response {
    authorization_error_response(
        http::StatusCode::BAD_REQUEST,
        "invalid_request",
        "MFA request body is invalid.",
    )
}

pub async fn mfa_options() -> Response {
    json_response_no_store(json!({"status": "ok"}))
}

pub fn mfa_method_not_allowed() -> Response {
    authorization_error_response(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request",
        "HTTP method is not allowed.",
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceAccessToken<'a> {
    Present(AccessTokenAuthScheme, Cow<'a, str>),
    Missing,
    InvalidRequest,
}

pub fn authorization_access_token(headers: &HeaderMap) -> Option<(AccessTokenAuthScheme, &str)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    if scheme.eq_ignore_ascii_case("DPoP") {
        return Some((AccessTokenAuthScheme::DPoP, token));
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some((AccessTokenAuthScheme::Bearer, token));
    }
    None
}

pub fn resource_access_token<'a>(
    request: &'a Request,
    body: &'a [u8],
    forbid_form_body: bool,
) -> ResourceAccessToken<'a> {
    if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .nth(1)
        .is_some()
    {
        return ResourceAccessToken::InvalidRequest;
    }
    let body_token = resource_form_body_access_token(request, body);
    if matches!(&body_token, FormBodyAccessToken::InvalidRequest)
        || (forbid_form_body && !matches!(&body_token, FormBodyAccessToken::Missing))
    {
        return ResourceAccessToken::InvalidRequest;
    }
    let header_token = authorization_access_token(request.headers());
    let selected = match (header_token, body_token) {
        (Some(_), FormBodyAccessToken::Present(_)) => ResourceAccessToken::InvalidRequest,
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, Cow::Borrowed(token)),
        (None, FormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, FormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, FormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    };
    if matches!(selected, ResourceAccessToken::Present(..))
        && query_has_access_token(request.uri().query().unwrap_or(""))
    {
        ResourceAccessToken::InvalidRequest
    } else {
        selected
    }
}

fn query_has_access_token(query: &str) -> bool {
    query.split('&').any(|pair| {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        url::form_urlencoded::parse(key.as_bytes())
            .next()
            .is_some_and(|(key, _)| key == "access_token")
    })
}

enum FormBodyAccessToken<'a> {
    Present(Cow<'a, str>),
    Missing,
    InvalidRequest,
}

fn resource_form_body_access_token<'a>(
    request: &Request,
    body: &'a [u8],
) -> FormBodyAccessToken<'a> {
    if request.method() != Method::POST || body.is_empty() || !request_uses_form_urlencoded(request)
    {
        return FormBodyAccessToken::Missing;
    }
    let mut fields = url::form_urlencoded::parse(body).filter(|(key, _)| key == "access_token");
    let first = fields.next();
    if fields.next().is_some() {
        return FormBodyAccessToken::InvalidRequest;
    }
    match first {
        Some((_, value)) if !value.trim().is_empty() => FormBodyAccessToken::Present(value),
        _ => FormBodyAccessToken::Missing,
    }
}

pub fn request_uses_form_urlencoded(request: &Request) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

#[cfg(test)]
#[path = "../../tests/unit/http/extract.rs"]
mod tests;
