//! HTTP 响应构造工具。
// 统一 OAuth 错误响应、JSON 响应和重定向响应的形状。

use super::prelude::*;

pub(crate) fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    json_response_status(
        status,
        json!({"error": error, "error_description": description}),
    )
}

pub(crate) fn oauth_token_error(
    status: StatusCode,
    error: &str,
    description: &str,
    basic_challenge: bool,
) -> HttpResponse {
    let mut response = no_store(oauth_error(status, error, description));
    if basic_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nazo-oauth""#),
        );
    }
    response
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

pub(crate) fn login_required_response(state: &AppState) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(&state.settings.session_cookie_name),
            clear_cookie(&state.settings.csrf_cookie_name),
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
