use crate::http::{Request, Response};
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, SameSite};
use http::{HeaderValue, header};

/// Builds a host cookie with the server's established security attributes.
#[must_use]
pub fn make_cookie(
    name: &str,
    value: &str,
    http_only: bool,
    max_age: u64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .path("/")
        .max_age(CookieDuration::seconds(max_age.min(i64::MAX as u64) as i64))
        .same_site(SameSite::Lax)
        .http_only(http_only)
        .secure(secure)
        .build()
}

#[must_use]
pub fn clear_cookie(name: &str, secure: bool) -> Cookie<'static> {
    // Issuance and deletion share the same scope and security policy. An empty
    // value and zero lifetime remove the cookie without consulting a host clock.
    let mut cookie = make_cookie(name, "", true, 0, secure);
    cookie.set_expires(cookie::time::OffsetDateTime::UNIX_EPOCH);
    cookie
}

#[must_use]
pub fn with_cookie_headers(mut response: Response, cookies: &[Cookie<'static>]) -> Response {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

#[must_use]
pub fn cookie_value(req: &Request, name: &str) -> Option<String> {
    let mut selected = None;
    visit_cookies(req, |cookie| {
        if selected.is_none() && cookie.name() == name {
            selected = Some(cookie.value().to_owned());
        }
    })
    .then_some(selected)
    .flatten()
}

pub(super) fn visit_cookies(request: &Request, mut visit: impl FnMut(Cookie<'_>)) -> bool {
    for value in request.headers().get_all(header::COOKIE) {
        let Ok(value) = std::str::from_utf8(value.as_bytes()) else {
            return false;
        };
        for part in value
            .split(';')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if let Ok(cookie) = Cookie::parse_encoded(part) {
                visit(cookie);
            }
        }
    }
    true
}

#[cfg(test)]
#[path = "../../tests/unit/http/cookies.rs"]
mod tests;
