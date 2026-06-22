//! CORS 策略。
// 只根据 Settings 构造 Actix CORS middleware，避免路由层混入跨域细节。

use actix_cors::Cors;
use actix_web::http::header;

use crate::settings::Settings;

pub(crate) fn build(settings: &Settings) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("dpop"),
            header::HeaderName::from_static("x-csrf-token"),
        ])
        .expose_headers(vec![
            header::WWW_AUTHENTICATE,
            header::HeaderName::from_static("dpop-nonce"),
            header::RETRY_AFTER,
        ])
        .supports_credentials()
        .max_age(3600);

    // 允许来源来自环境配置，默认值由 Settings 负责。
    for origin in &settings.cors_allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/cors.rs"]
mod tests;
