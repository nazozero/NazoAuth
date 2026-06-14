use super::*;
use crate::config::ConfigSource;

fn settings() -> Settings {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.csrf_cookie_name = "nazo_csrf".to_owned();
    settings.session_ttl_seconds = 900;
    settings.cookie_secure = true;
    settings
}

#[actix_web::test]
async fn csrf_response_returns_token_body_and_matching_cookie() {
    let settings = settings();
    let response = csrf_response(&settings, "csrf-token-1".to_owned());

    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get_all(actix_web::http::header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("nazo_csrf=csrf-token-1"))
        .expect("CSRF refresh must set a cookie bound to the returned token");

    assert!(cookie.contains("Secure"));
    assert!(!cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Max-Age=900"));

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("csrf response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, json!({"csrf_token": "csrf-token-1"}));
}
