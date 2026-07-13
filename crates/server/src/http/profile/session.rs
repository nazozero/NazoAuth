//! 当前用户会话接口。
use crate::domain::AppState;
use crate::settings::Settings;
use crate::support::{clear_cookie, cookie_value, json_response, with_cookie_headers};
#[cfg(test)]
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
// 只处理登出和会话/CSRF Cookie 清理。

pub(crate) async fn logout(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    if let Some(session_id) = cookie_value(&req, state.settings.session().session_cookie_name) {
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
