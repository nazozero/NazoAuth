//! HTTP 响应构造工具。
// 统一 OAuth 错误响应、JSON 响应和重定向响应的形状。

use super::prelude::*;
use std::borrow::Cow;

#[derive(Clone)]
pub(crate) struct OAuthJsonErrorFields {
    pub(crate) error: String,
}

pub(crate) fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let mut response = json_response_status(
        status,
        json!({"error": error, "error_description": description}),
    );
    response.extensions_mut().insert(OAuthJsonErrorFields {
        error: error.to_owned(),
    });
    response
}

pub(crate) fn authorization_error_page(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head><body><main id=\"oidf_conformance_interaction\"><h1>{}</h1><p>{}</p></main></body></html>",
        html_escape_text(error),
        html_escape_text(error),
        html_escape_text(description)
    );
    no_store(
        HttpResponse::build(status)
            .content_type("text/html; charset=utf-8")
            .body(body),
    )
}

pub(crate) fn oauth_token_error(
    status: StatusCode,
    error: &str,
    description: &str,
    basic_challenge: bool,
) -> HttpResponse {
    let description = oauth_token_error_description(description);
    let mut response = no_store(oauth_error(status, error, &description));
    if basic_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nazo-oauth""#),
        );
    }
    response
}

fn oauth_token_error_description(description: &str) -> Cow<'_, str> {
    if description.bytes().all(is_oauth_error_description_byte) {
        Cow::Borrowed(description)
    } else {
        Cow::Borrowed("Request failed.")
    }
}

fn is_oauth_error_description_byte(byte: u8) -> bool {
    matches!(
        byte,
        0x09 | 0x0A | 0x0D | 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E
    )
}

fn html_escape_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(crate) fn oauth_bearer_error(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    let mut response = oauth_error(status, error, description);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

pub(crate) fn request_uses_form_urlencoded(req: &HttpRequest) -> bool {
    req.headers()
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

pub(crate) fn login_required_response(state: &AppState) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(
                &state.settings.session_cookie_name,
                state.settings.cookie_secure,
            ),
            clear_cookie(
                &state.settings.csrf_cookie_name,
                state.settings.cookie_secure,
            ),
        ],
    )
}

pub(crate) fn csrf_error() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "CSRF 校验失败，请刷新页面后重试。",
    )
}

pub(crate) fn has_valid_csrf_token(
    state: &AppState,
    req: &HttpRequest,
    fallback_token: Option<&str>,
) -> bool {
    if cookie_value(req, &state.settings.session_cookie_name).is_none() {
        return true;
    }
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
    let Some(header_token) = header_token else {
        return false;
    };
    let Some(cookie_token) = cookie_value(req, &state.settings.csrf_cookie_name) else {
        return false;
    };
    constant_time_eq(header_token.as_bytes(), cookie_token.trim().as_bytes())
}

pub(crate) fn redirect_found(location: String) -> HttpResponse {
    let mut response = empty_response(StatusCode::FOUND);
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub(crate) fn json_response<T>(body: T) -> HttpResponse
where
    T: Serialize,
{
    HttpResponse::Ok().json(body)
}

pub(crate) fn json_response_status<T>(status: StatusCode, body: T) -> HttpResponse
where
    T: Serialize,
{
    HttpResponse::build(status).json(body)
}

pub(crate) fn json_response_no_store<T>(body: T) -> HttpResponse
where
    T: Serialize,
{
    no_store(json_response(body))
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

pub(crate) fn bytes_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

pub(crate) fn empty_response(status: StatusCode) -> HttpResponse {
    HttpResponse::build(status).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_token_error_description_keeps_rfc_allowed_ascii() {
        assert_eq!(
            oauth_token_error_description("Authorization code has already been used.").as_ref(),
            "Authorization code has already been used."
        );
    }

    #[test]
    fn oauth_token_error_description_replaces_disallowed_text() {
        assert_eq!(
            oauth_token_error_description("授权码已被使用.").as_ref(),
            "Request failed."
        );
        assert_eq!(
            oauth_token_error_description("invalid\\request").as_ref(),
            "Request failed."
        );
    }

    #[test]
    fn authorization_error_page_is_html_and_no_store() {
        let response = authorization_error_page(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is invalid.",
        );

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }
}
