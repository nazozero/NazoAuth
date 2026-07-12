//! CSRF token 刷新端点。
// 只有已登录用户可以刷新 token，避免匿名请求制造无意义状态。
use crate::http::prelude::*;

/// 为当前会话生成新的 CSRF token。
pub(crate) async fn csrf(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Err(response) = current_user_or_login_required(&state, &req).await {
        return response;
    };

    let csrf_token = random_urlsafe_token();
    csrf_response(&state.settings, csrf_token)
}

fn csrf_response(settings: &Settings, csrf_token: String) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({"csrf_token": csrf_token})),
        &[make_cookie(
            &settings.csrf_cookie_name,
            &csrf_token,
            false,
            settings.session_ttl_seconds,
            settings.cookie_secure,
        )],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/csrf.rs"]
mod tests;
