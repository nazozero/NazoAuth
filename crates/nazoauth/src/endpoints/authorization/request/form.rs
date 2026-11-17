use crate::http::Request as HttpRequest;
use crate::http::Response as HttpResponse;
use crate::http::oauth_error;
use bytes::Bytes;
use http::StatusCode;
use http::header;
use std::collections::HashMap;

use nazo_auth::{encode_resource_indicators, has_duplicate_oauth_parameter};

pub fn parse_authorization_post_form(
    req: &HttpRequest,
    body: &Bytes,
    duplicate_parameters: &[&str],
) -> Result<HashMap<String, String>, HttpResponse> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization request must use application/x-www-form-urlencoded.",
        ));
    }
    let raw = std::str::from_utf8(body).map_err(|_| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization request form is invalid.",
        )
    })?;
    if has_duplicate_oauth_parameter(req.uri().query().unwrap_or(""), duplicate_parameters) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth 参数不能重复.",
        ));
    }
    parse_authorization_form_encoded(raw, duplicate_parameters)
}

pub fn parse_authorization_query(
    raw: &str,
    duplicate_parameters: &[&str],
) -> Result<HashMap<String, String>, HttpResponse> {
    parse_authorization_form_encoded(raw, duplicate_parameters)
}

pub fn parse_authorization_form_encoded(
    raw: &str,
    duplicate_parameters: &[&str],
) -> Result<HashMap<String, String>, HttpResponse> {
    let mut q = HashMap::new();
    let mut resource_values = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();
        if key == "resource" {
            resource_values.push(value);
            continue;
        }
        if duplicate_parameters.contains(&key.as_str()) && q.contains_key(&key) {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth 参数不能重复.",
            ));
        }
        q.insert(key, value);
    }
    if let Some(encoded) = encode_resource_indicators(&resource_values) {
        q.insert("resource".to_owned(), encoded);
    }
    Ok(q)
}

#[cfg(test)]
#[path = "../../../../tests/unit/endpoints/authorization_form.rs"]
mod tests;
