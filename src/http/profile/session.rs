//! 当前用户会话接口。
// 只处理登出和会话/CSRF Cookie 清理。
use crate::http::prelude::*;

pub(crate) async fn logout(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Some(session_id) = cookie_value(&req, &state.settings.session_cookie_name) {
        let _ = valkey_del(&state.valkey, format!("oauth:session:{session_id}")).await;
    }
    with_cookie_headers(
        json_response(json!({"success": true})),
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
