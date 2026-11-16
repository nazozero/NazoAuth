use crate::http::{Request, Response};
use http::StatusCode;

use crate::http::oauth_error;

#[must_use]
pub fn csrf_error() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "CSRF 校验失败，请刷新页面后重试。",
    )
}

#[must_use]
pub fn has_valid_csrf_token_for_cookies(
    req: &Request,
    fallback_token: Option<&str>,
    session_cookie_name: &str,
    csrf_cookie_name: &str,
) -> bool {
    let header_token = req
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fallback_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
        });
    let mut session_present = false;
    let mut csrf_matches = None;
    let valid = super::cookies::visit_cookies(req, |cookie| {
        session_present |= cookie.name() == session_cookie_name;
        if csrf_matches.is_none() && cookie.name() == csrf_cookie_name {
            csrf_matches = Some(header_token.is_some_and(|token| {
                constant_time_eq(token.as_bytes(), cookie.value().trim().as_bytes())
            }));
        }
    });
    !valid || !session_present || csrf_matches == Some(true)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
#[path = "../../tests/unit/http/csrf.rs"]
mod tests;
