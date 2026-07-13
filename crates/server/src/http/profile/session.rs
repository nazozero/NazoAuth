//! 当前用户会话接口。
use crate::support::sessions::{SessionHttpConfig, SessionProfileHandles};
use crate::support::{clear_cookie, json_response, with_cookie_headers};
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

pub(crate) async fn logout(handles: Data<SessionProfileHandles>, req: HttpRequest) -> HttpResponse {
    if let Err(error) = handles.delete_request_session(&req).await {
        tracing::warn!(%error, "failed to delete session during logout");
    }
    logout_response(handles.http_config())
}

fn logout_response(config: &SessionHttpConfig) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({"success": true})),
        &[
            clear_cookie(config.session_cookie_name(), config.cookie_secure()),
            clear_cookie(config.csrf_cookie_name(), config.cookie_secure()),
        ],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/session.rs"]
mod tests;
