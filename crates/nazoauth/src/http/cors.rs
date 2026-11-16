//! The product's fixed browser transport policies, independent of a Web framework.
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use super::{Request, Response, empty_response, finish};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorsPolicy {
    None,
    WellKnown,
    BrowserTokenManagement,
    BrowserUserinfo,
    AuthApi,
    Admin,
    Scim,
}

impl CorsPolicy {
    fn methods(self) -> &'static str {
        match self {
            Self::None => "",
            Self::WellKnown => "GET, HEAD",
            Self::BrowserTokenManagement => "POST",
            Self::BrowserUserinfo => "GET, POST",
            Self::AuthApi | Self::Admin | Self::Scim => "GET, POST, PUT, PATCH, DELETE",
        }
    }

    fn allowed_headers(self) -> &'static str {
        match self {
            Self::None => "",
            Self::WellKnown => "accept",
            Self::BrowserTokenManagement | Self::BrowserUserinfo => {
                "authorization, content-type, dpop"
            }
            Self::AuthApi | Self::Admin => "authorization, content-type, x-csrf-token",
            Self::Scim => "authorization, content-type",
        }
    }

    fn exposed_headers(self) -> Option<&'static str> {
        match self {
            Self::WellKnown => Some("retry-after"),
            Self::BrowserTokenManagement | Self::BrowserUserinfo => {
                Some("www-authenticate, dpop-nonce, retry-after")
            }
            _ => None,
        }
    }

    fn credentials(self) -> bool {
        matches!(self, Self::AuthApi | Self::Admin)
    }
}

fn allowed_origin<'a>(request: &'a Request, origins: &[String]) -> Option<&'a HeaderValue> {
    request.headers().get(header::ORIGIN).filter(|value| {
        origins
            .iter()
            .any(|origin| value.as_bytes() == origin.as_bytes())
    })
}

fn vary(headers: &mut HeaderMap) {
    const VALUE: &str = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";
    if let Some(existing) = headers.get(header::VARY) {
        let mut combined = existing.as_bytes().to_vec();
        combined.extend_from_slice(b", ");
        combined.extend_from_slice(VALUE.as_bytes());
        if let Ok(value) = HeaderValue::from_bytes(&combined) {
            headers.insert(header::VARY, value);
        }
    } else {
        headers.insert(header::VARY, HeaderValue::from_static(VALUE));
    }
}

/// Returns a response only for a CORS preflight handled by this route's policy.
pub fn cors_preflight(
    policy: CorsPolicy,
    request: &Request,
    origins: &[String],
) -> Option<Response> {
    if policy == CorsPolicy::None || request.method() != Method::OPTIONS {
        return None;
    }
    let method = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| Method::from_bytes(v.as_bytes()).ok())?;
    let error = |description: &'static str| {
        Some(finish(
            http::Response::builder().status(StatusCode::BAD_REQUEST),
            description,
        ))
    };
    if !request.headers().contains_key(header::ORIGIN) {
        return error("Request header `Origin` is required but was not provided");
    }
    let Some(origin) = allowed_origin(request, origins) else {
        return error("Origin is not allowed to make this request");
    };
    if !policy
        .methods()
        .split(", ")
        .any(|allowed| allowed == method.as_str())
    {
        return error("Requested method is not allowed");
    }
    if let Some(requested) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        let Ok(requested) = requested.to_str() else {
            return error("Request header `Access-Control-Request-Headers` has an invalid value");
        };
        for name in requested.split(',').map(str::trim) {
            let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
                return error(
                    "Request header `Access-Control-Request-Headers` has an invalid value",
                );
            };
            if !policy
                .allowed_headers()
                .split(", ")
                .any(|allowed| name.as_str() == allowed)
            {
                return error("One or more request headers are not allowed");
            }
        }
    }
    let mut response = empty_response(StatusCode::OK);
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(policy.methods()),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(policy.allowed_headers()),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(
            if matches!(
                policy,
                CorsPolicy::BrowserTokenManagement | CorsPolicy::BrowserUserinfo
            ) {
                "0"
            } else {
                "3600"
            },
        ),
    );
    if policy.credentials() {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    vary(headers);
    Some(response)
}

pub fn apply_cors_headers(
    policy: CorsPolicy,
    request: &Request,
    origins: &[String],
    headers: &mut HeaderMap,
) {
    if policy == CorsPolicy::None {
        return;
    }
    if let Some(origin) = allowed_origin(request, origins) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    }
    if let Some(exposed) = policy.exposed_headers() {
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(exposed),
        );
    }
    if policy.credentials() {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    vary(headers);
}

#[cfg(test)]
#[path = "../../tests/unit/http/cors.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/http/host_cors.rs"]
mod host_tests;
