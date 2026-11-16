use crate::http::Response;
use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;

#[derive(Serialize)]
struct OAuthErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

impl<'a> OAuthErrorBody<'a> {
    fn new(error: &'a str, description: &'a str) -> Self {
        Self {
            error,
            error_description: oauth_error_description(description),
        }
    }

    fn bearer_challenge(&self) -> HeaderValue {
        HeaderValue::from_str(&format!(
            r#"Bearer error="{}", error_description="{}""#,
            oauth_error_description(self.error),
            self.error_description,
        ))
        .expect("OAuth challenge fields contain only allowed ASCII")
    }
}

pub fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    json_response_status(status, OAuthErrorBody::new(error, description))
}

pub fn authorization_error_response(
    status: StatusCode,
    error: &str,
    description: &str,
) -> Response {
    no_store(oauth_error(status, error, description))
}

pub fn oauth_token_error(
    status: StatusCode,
    error: &str,
    description: &str,
    basic_challenge: bool,
) -> Response {
    let mut response = no_store(oauth_error(status, error, description));
    if basic_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nazo-oauth""#),
        );
    }
    response
}

pub fn oauth_bearer_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = OAuthErrorBody::new(error, description);
    let challenge = body.bearer_challenge();
    let mut response = json_response_status(status, body);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

pub fn redirect_found(location: String) -> Response {
    redirect_with_status(StatusCode::FOUND, location)
}

/// Redirect a completed credential-bearing POST to a follow-up GET.
///
/// `303 See Other` makes the method transition explicit.  This is distinct
/// from the ordinary `302 Found` helper because browser-facing OAuth
/// authorization responses and external-login starts have different
/// redirect contracts.
pub fn redirect_see_other(location: String) -> Response {
    redirect_with_status(StatusCode::SEE_OTHER, location)
}

fn redirect_with_status(status: StatusCode, location: String) -> Response {
    let mut response = empty_response(status);
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub fn json_response<T: Serialize>(body: T) -> Response {
    crate::http::json(http::Response::builder().status(http::StatusCode::OK), body)
}

pub fn json_response_status<T: Serialize>(status: StatusCode, body: T) -> Response {
    crate::http::json(http::Response::builder().status(status), body)
}

pub fn json_response_no_store<T: Serialize>(body: T) -> Response {
    no_store(json_response(body))
}

pub fn json_response_status_no_store<T: Serialize>(status: StatusCode, body: T) -> Response {
    no_store(json_response_status(status, body))
}

pub fn empty_response_no_store(status: StatusCode) -> Response {
    no_store(empty_response(status))
}

pub fn bytes_response(body: Vec<u8>) -> Response {
    crate::http::finish(http::Response::builder().status(http::StatusCode::OK), body)
}

pub fn empty_response(status: StatusCode) -> Response {
    crate::http::finish(http::Response::builder().status(status), Bytes::new())
}

pub fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(any(test, feature = "test-support"))]
pub fn bearer_challenge(error: &str, description: &str) -> HeaderValue {
    OAuthErrorBody::new(error, description).bearer_challenge()
}

#[doc(hidden)]
pub fn oauth_error_description(description: &str) -> &str {
    if description.bytes().all(is_oauth_error_description_byte) {
        description
    } else {
        "Request failed."
    }
}

#[doc(hidden)]
pub fn is_oauth_error_description_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E)
}

/// Presents the existing OAuth endpoint error policies after semantic decisions.
pub fn oauth_endpoint_error_response(
    error: nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
) -> Response {
    use nazo_oauth_server::contracts::oauth_error::OAuthEndpointError;
    match error {
        OAuthEndpointError::Json(fields) => {
            oauth_error(fields.status, &fields.error, &fields.description)
        }
        OAuthEndpointError::Authorization(fields) => {
            authorization_error_response(fields.status, &fields.error, &fields.description)
        }
        OAuthEndpointError::Token {
            fields,
            basic_challenge,
        } => oauth_token_error(
            fields.status,
            &fields.error,
            &fields.description,
            basic_challenge,
        ),
        OAuthEndpointError::Bearer(fields) => {
            oauth_bearer_error(fields.status, &fields.error, &fields.description)
        }
        OAuthEndpointError::Dpop { error, context } => {
            crate::http::dpop_error_response(error, context)
        }
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
        OAuthEndpointError::Disabled => crate::http::finish(
            http::Response::builder().status(http::StatusCode::NOT_FOUND),
            Bytes::new(),
        ),
    }
}

pub fn pre_authorized_token_error_response(
    error: nazo_openid4vci::application::CredentialHttpError,
) -> Response {
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
) -> Response {
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
        TokenEndpointSuccess::PreAuthorized(body) => json_response_no_store(body),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/http/presenter.rs"]
mod tests;

/// Complete a standard HTTP response without copying its body buffer.
pub fn finish(builder: http::response::Builder, body: impl Into<Bytes>) -> Response {
    builder.body(body.into()).unwrap_or_else(|_| {
        http::Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Bytes::new())
            .expect("constant response")
    })
}

/// Serialize once at the protocol boundary; adapters only move the result.
pub fn json(mut builder: http::response::Builder, value: impl Serialize) -> Response {
    if let Some(headers) = builder.headers_mut() {
        // Content-Type, the usual two CORS headers and six security defaults
        // should fit before the first insertion, without growing the map later.
        headers.reserve(9usize.saturating_sub(headers.keys_len()));
        headers
            .entry(header::CONTENT_TYPE)
            .or_insert_with(|| HeaderValue::from_static("application/json"));
    }
    match serde_json::to_vec(&value) {
        Ok(body) => finish(builder, body),
        Err(error) => super::request::text_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Json serialize error: {error}"),
        ),
    }
}
