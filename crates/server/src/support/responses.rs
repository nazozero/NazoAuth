//! HTTP 响应构造工具。
use super::{clear_cookie, constant_time_eq, cookie_value, with_cookie_headers};
use crate::domain::AppState;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
// 统一 OAuth 错误响应、JSON 响应和重定向响应的形状。

pub(crate) use nazo_http_actix::{
    OAuthJsonErrorFields, ResourceAccessToken, authorization_error_response, bytes_response,
    empty_response, empty_response_no_store, json_response, json_response_no_store,
    json_response_status, json_response_status_no_store, oauth_bearer_error, oauth_error,
    oauth_token_error, redirect_found, request_uses_form_urlencoded, resource_access_token,
};
#[cfg(test)]
use nazo_http_actix::{bearer_challenge, is_oauth_error_description_byte, oauth_error_description};

pub(crate) fn login_required_response(state: &AppState) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &[
            clear_cookie(
                state.settings.session().session_cookie_name,
                state.settings.session().cookie_secure,
            ),
            clear_cookie(
                state.settings.session().csrf_cookie_name,
                state.settings.session().cookie_secure,
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
    has_valid_csrf_token_for_cookies(
        req,
        fallback_token,
        state.settings.session().session_cookie_name,
        state.settings.session().csrf_cookie_name,
    )
}

pub(crate) fn has_valid_csrf_token_for_cookies(
    req: &HttpRequest,
    fallback_token: Option<&str>,
    session_cookie_name: &str,
    csrf_cookie_name: &str,
) -> bool {
    if cookie_value(req, session_cookie_name).is_none() {
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
    let Some(cookie_token) = cookie_value(req, csrf_cookie_name) else {
        return false;
    };
    constant_time_eq(header_token.as_bytes(), cookie_token.trim().as_bytes())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/responses.rs"]
mod tests;
