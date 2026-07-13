//! 当前用户会话接口。
// 只处理登出和会话/CSRF Cookie 清理。
use crate::http::prelude::*;

pub(crate) async fn logout(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Some(session_id) = cookie_value(&req, &state.settings.session_cookie_name) {
        let _ = nazo_valkey::SessionStore::new(&state.valkey_connection())
            .delete(&session_id)
            .await;
    }
    logout_response(&state.settings)
}

fn logout_response(settings: &Settings) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({"success": true})),
        &[
            clear_cookie(&settings.session_cookie_name, settings.cookie_secure),
            clear_cookie(&settings.csrf_cookie_name, settings.cookie_secure),
        ],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/session.rs"]
mod tests;
