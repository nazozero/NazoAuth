use super::*;
use crate::settings::Settings;

fn settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.session.session_cookie_name = "session".to_owned();
    settings.session.csrf_cookie_name = "csrf".to_owned();
    settings.session.cookie_secure = true;
    settings
}

#[actix_web::test]
async fn logout_response_clears_session_and_csrf_cookies_without_cacheable_state() {
    let settings = settings();
    let session = &settings.session;
    let config = SessionHttpConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let response = logout_response(&config);

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(set_cookie.len(), 2);
    assert!(
        set_cookie
            .iter()
            .any(|cookie| cookie.contains("session=") && cookie.contains("Max-Age=0"))
    );
    assert!(set_cookie.iter().all(|cookie| !cookie.contains("sid=")));
    assert!(
        set_cookie
            .iter()
            .any(|cookie| cookie.contains("csrf=") && cookie.contains("Max-Age=0"))
    );
    assert!(
        set_cookie
            .iter()
            .all(|cookie| cookie.contains("SameSite=Lax") && cookie.contains("Secure"))
    );

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("logout response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body, json!({"success": true}));
}
