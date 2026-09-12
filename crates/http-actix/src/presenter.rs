use std::borrow::Cow;

use actix_web::{
    HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderValue},
    },
};
use serde::Serialize;
use serde_json::json;

pub fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let description = oauth_error_description(description);
    json_response_status(
        status,
        json!({"error": error, "error_description": description}),
    )
}

pub fn authorization_error_response(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    no_store(oauth_error(status, error, description))
}

pub fn oauth_token_error(
    status: StatusCode,
    error: &str,
    description: &str,
    basic_challenge: bool,
) -> HttpResponse {
    let description = oauth_error_description(description);
    let mut response = no_store(oauth_error(status, error, &description));
    if basic_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nazo-oauth""#),
        );
    }
    response
}

pub fn oauth_bearer_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let mut response = oauth_error(status, error, description);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        bearer_challenge(error, description),
    );
    response
}

pub fn redirect_found(location: String) -> HttpResponse {
    redirect_with_status(StatusCode::FOUND, location)
}

/// Redirect a completed credential-bearing POST to a follow-up GET.
///
/// `303 See Other` makes the method transition explicit.  This is distinct
/// from the ordinary `302 Found` helper because browser-facing OAuth
/// authorization responses and external-login starts have different
/// redirect contracts.
pub fn redirect_see_other(location: String) -> HttpResponse {
    redirect_with_status(StatusCode::SEE_OTHER, location)
}

fn redirect_with_status(status: StatusCode, location: String) -> HttpResponse {
    let mut response = empty_response(status);
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub fn json_response<T: Serialize>(body: T) -> HttpResponse {
    HttpResponse::Ok().json(body)
}

pub fn json_response_status<T: Serialize>(status: StatusCode, body: T) -> HttpResponse {
    HttpResponse::build(status).json(body)
}

pub fn json_response_no_store<T: Serialize>(body: T) -> HttpResponse {
    no_store(json_response(body))
}

pub fn json_response_status_no_store<T: Serialize>(status: StatusCode, body: T) -> HttpResponse {
    no_store(json_response_status(status, body))
}

pub fn empty_response_no_store(status: StatusCode) -> HttpResponse {
    no_store(empty_response(status))
}

pub fn bytes_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

pub fn empty_response(status: StatusCode) -> HttpResponse {
    HttpResponse::build(status).finish()
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[doc(hidden)]
pub fn bearer_challenge(error: &str, description: &str) -> HeaderValue {
    let description = oauth_error_description(description);
    HeaderValue::from_str(&format!(
        r#"Bearer error="{}", error_description="{}""#,
        oauth_challenge_param(error),
        oauth_challenge_param(&description)
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

#[doc(hidden)]
pub fn oauth_error_description(description: &str) -> Cow<'_, str> {
    if description.bytes().all(is_oauth_error_description_byte) {
        Cow::Borrowed(description)
    } else {
        Cow::Borrowed("Request failed.")
    }
}

fn oauth_challenge_param(value: &str) -> Cow<'_, str> {
    if value.bytes().all(is_oauth_error_description_byte) {
        Cow::Borrowed(value)
    } else {
        Cow::Borrowed("Request failed.")
    }
}

#[doc(hidden)]
pub fn is_oauth_error_description_byte(byte: u8) -> bool {
    matches!(
        byte,
        0x09 | 0x0A | 0x0D | 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E
    )
}

/// Presents the existing OAuth endpoint error policies after semantic decisions.
pub fn oauth_endpoint_error_response(
    error: nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
) -> HttpResponse {
    use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;
    let status = |value: http::StatusCode| {
        StatusCode::from_u16(value.as_u16()).expect("HTTP status is valid")
    };
    match error {
        OAuthEndpointError::Json(fields) => {
            oauth_error(status(fields.status), &fields.error, &fields.description)
        }
        OAuthEndpointError::Authorization(fields) => {
            authorization_error_response(status(fields.status), &fields.error, &fields.description)
        }
        OAuthEndpointError::Token {
            fields,
            basic_challenge,
        } => oauth_token_error(
            status(fields.status),
            &fields.error,
            &fields.description,
            basic_challenge,
        ),
        OAuthEndpointError::Bearer(fields) => {
            oauth_bearer_error(status(fields.status), &fields.error, &fields.description)
        }
        OAuthEndpointError::Dpop { error, context } => crate::dpop_error_response(error, context),
        OAuthEndpointError::PreAuthorized(error) => pre_authorized_token_error_response(error),
        OAuthEndpointError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        OAuthEndpointError::Disabled => HttpResponse::NotFound().finish(),
    }
}

pub fn pre_authorized_token_error_response(
    error: nazo_openid4vci::application::CredentialHttpError,
) -> HttpResponse {
    let mut response = oauth_token_error(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::BAD_REQUEST),
        error.error,
        error.description,
        false,
    );
    if let Some(challenge) = match error.error {
        "use_dpop_nonce" => Some(header::HeaderValue::from_static(
            r#"DPoP error="use_dpop_nonce""#,
        )),
        "invalid_dpop_proof" => Some(header::HeaderValue::from_static(
            r#"DPoP error="invalid_dpop_proof""#,
        )),
        _ => None,
    } {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    if let Some(nonce) = error.dpop_nonce
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

/// Presents each token result with its original cache and nonce policy.
pub fn token_endpoint_success_response(
    success: nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess,
) -> HttpResponse {
    use nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess;
    match success {
        TokenEndpointSuccess::Issued { body, dpop_nonce } => {
            let mut response = json_response_no_store(body);
            if let Some(nonce) = dpop_nonce
                && let Ok(value) = HeaderValue::from_str(&nonce)
            {
                response
                    .headers_mut()
                    .insert(header::HeaderName::from_static("dpop-nonce"), value);
            }
            response
        }
        TokenEndpointSuccess::Replayed { body } => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .content_type("application/json")
            .body(body),
        TokenEndpointSuccess::PreAuthorized(body) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(body),
    }
}

#[cfg(test)]
#[path = "../tests/unit/presenter.rs"]
mod tests;
