use actix_web::{
    HttpRequest, HttpResponse,
    error::InternalError,
    http::{
        Method,
        header::{self, HeaderMap},
    },
};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTokenAuthScheme {
    Bearer,
    DPoP,
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
    http_signatures_enabled: bool,
) -> ResourceAccessToken {
    let header_token = authorization_access_token(request.headers());
    let body_token = resource_form_body_access_token(request, body);
    if http_signatures_enabled && !matches!(&body_token, FormBodyAccessToken::Missing) {
        return ResourceAccessToken::InvalidRequest;
    }
    match (header_token, body_token) {
        (Some(_), FormBodyAccessToken::Present(_)) => ResourceAccessToken::InvalidRequest,
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, token),
        (None, FormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, FormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, FormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    }
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
    let mut access_token = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "access_token" {
            if access_token.is_some() {
                return FormBodyAccessToken::InvalidRequest;
            }
            let token = value.into_owned();
            if token.trim().is_empty() {
                return FormBodyAccessToken::Missing;
            }
            access_token = Some(token);
        }
    }
    access_token
        .map(FormBodyAccessToken::Present)
        .unwrap_or(FormBodyAccessToken::Missing)
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
mod tests {
    use actix_web::{http::header, test::TestRequest};

    use super::request_uses_form_urlencoded;

    #[test]
    fn form_content_type_is_case_insensitive_and_accepts_parameters() {
        let request = TestRequest::default()
            .insert_header((
                header::CONTENT_TYPE,
                "Application/X-WWW-Form-Urlencoded; charset=utf-8",
            ))
            .to_http_request();
        assert!(request_uses_form_urlencoded(&request));

        let request = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();
        assert!(!request_uses_form_urlencoded(&request));
    }

    #[test]
    fn access_token_transport_rejects_duplicates_and_signed_form_transport() {
        let request = TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            super::resource_access_token(&request, b"access_token=body-token", false),
            super::ResourceAccessToken::InvalidRequest
        );

        let request = TestRequest::post()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            super::resource_access_token(&request, b"access_token=body-token", true),
            super::ResourceAccessToken::InvalidRequest
        );
    }

    #[test]
    fn bearer_and_dpop_authorization_schemes_are_case_insensitive() {
        for (raw, expected) in [
            ("bearer token", super::AccessTokenAuthScheme::Bearer),
            ("dpop token", super::AccessTokenAuthScheme::DPoP),
        ] {
            let request = TestRequest::default()
                .insert_header((header::AUTHORIZATION, raw))
                .to_http_request();
            assert_eq!(
                super::authorization_access_token(request.headers()),
                Some((expected, "token".to_owned()))
            );
        }
    }
}
