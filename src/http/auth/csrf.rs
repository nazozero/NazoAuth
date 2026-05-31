//! CSRF token 刷新端点。
// 只有已登录用户可以刷新 token，避免匿名请求制造无意义状态。
use crate::http::prelude::*;

/// 为当前会话生成新的 CSRF token。
pub(crate) async fn csrf(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if current_user(&state, &req).await.is_none() {
        return login_required_response(&state);
    }

    let csrf_token = random_urlsafe_token();
    with_cookie_headers(
        json_response(json!({"csrf_token": csrf_token})),
        &[make_cookie(
            &state.settings.csrf_cookie_name,
            &csrf_token,
            false,
            state.settings.session_ttl_seconds,
            state.settings.cookie_secure,
        )],
    )
}
