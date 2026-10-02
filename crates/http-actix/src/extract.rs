use actix_web::{
    HttpRequest, HttpResponse,
    error::InternalError,
    http::{
        Method,
        header::{self, HeaderMap},
    },
};
use nazo_oauth_server::contracts::userinfo::AccessTokenAuthScheme;
use serde_json::json;

use crate::{authorization_error_response, json_response_no_store};

pub fn mfa_json_config() -> actix_web::web::JsonConfig {
    actix_web::web::JsonConfig::default().error_handler(|_, _| {
        InternalError::from_response(
            "invalid MFA JSON payload",
            authorization_error_response(
                actix_web::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "MFA request body is invalid.",
            ),
        )
        .into()
    })
}

pub async fn mfa_options() -> HttpResponse {
    json_response_no_store(json!({"status": "ok"}))
}

pub async fn mfa_method_not_allowed() -> HttpResponse {
    authorization_error_response(
        actix_web::http::StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request",
        "HTTP method is not allowed.",
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceAccessToken {
    Present(AccessTokenAuthScheme, String),
    Missing,
    InvalidRequest,
}

pub fn authorization_access_token(headers: &HeaderMap) -> Option<(AccessTokenAuthScheme, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    if token.is_empty() || token.split_whitespace().count() != 1 {
        return None;
    }
    if scheme.eq_ignore_ascii_case("DPoP") {
        return Some((AccessTokenAuthScheme::DPoP, token.to_owned()));
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some((AccessTokenAuthScheme::Bearer, token.to_owned()));
    }
    None
}

pub fn resource_access_token(
    request: &HttpRequest,
    body: &[u8],
    forbid_form_body: bool,
) -> ResourceAccessToken {
    if request.headers().get_all(header::AUTHORIZATION).count() > 1 {
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
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, token),
        (None, FormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, FormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, FormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    };
    if matches!(selected, ResourceAccessToken::Present(..))
        && query_has_access_token(request.query_string())
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

enum FormBodyAccessToken {
    Present(String),
    Missing,
    InvalidRequest,
}

fn resource_form_body_access_token(request: &HttpRequest, body: &[u8]) -> FormBodyAccessToken {
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
        Some((_, value)) if !value.trim().is_empty() => {
            FormBodyAccessToken::Present(value.into_owned())
        }
        _ => FormBodyAccessToken::Missing,
    }
}

pub fn request_uses_form_urlencoded(request: &HttpRequest) -> bool {
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
#[path = "../tests/unit/extract.rs"]
mod tests;
