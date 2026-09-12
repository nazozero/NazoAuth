use actix_web::{HttpRequest, http::header};

pub(super) fn bearer_token(request: &HttpRequest) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer)
}

pub(super) fn parse_bearer(value: &str) -> Option<&str> {
    let mut parts = value.trim().splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    (scheme.eq_ignore_ascii_case("Bearer")
        && !token.is_empty()
        && token.split_whitespace().count() == 1)
        .then_some(token)
}
