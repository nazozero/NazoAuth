use super::*;
use crate::config::ConfigSource;

fn settings() -> Settings {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.session_cookie_name = "nazo_session".to_owned();
    settings.csrf_cookie_name = "nazo_csrf".to_owned();
    settings.session_ttl_seconds = 900;
    settings.cookie_secure = true;
    settings
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

#[actix_web::test]
async fn passkey_login_failure_is_uniform_and_does_not_enumerate_users() {
    let (status, body) = response_json(passkey_login_failed_response()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "passkey login failed.");
    assert!(body.get("user_id").is_none());
    assert!(body.get("email").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("ceremony_id").is_none());
}

#[actix_web::test]
async fn expired_passkey_ceremony_is_invalid_request_without_session_material() {
    let (status, body) = response_json(passkey_ceremony_expired_response()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey ceremony expired.");
    assert!(body.get("csrf_token").is_none());
    assert!(body.get("expires_in").is_none());
}

#[actix_web::test]
async fn passkey_session_response_sets_bound_cookies_and_minimal_body() {
    let settings = settings();
    let response = passkey_session_response(&settings, "session-secret", "csrf-secret", 900);

    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(actix_web::http::header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);

    let session_cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with("nazo_session=session-secret"))
        .expect("passkey login must set the session cookie");
    assert!(session_cookie.contains("HttpOnly"));
    assert!(session_cookie.contains("Secure"));
    assert!(session_cookie.contains("SameSite=Lax"));
    assert!(session_cookie.contains("Max-Age=900"));

    let csrf_cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with("nazo_csrf=csrf-secret"))
        .expect("passkey login must set a CSRF cookie");
    assert!(!csrf_cookie.contains("HttpOnly"));
    assert!(csrf_cookie.contains("Secure"));
    assert!(csrf_cookie.contains("SameSite=Lax"));
    assert!(csrf_cookie.contains("Max-Age=900"));

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    assert_eq!(
        body,
        json!({
            "expires_in": 900,
            "csrf_token": "csrf-secret",
            "mfa_required": false
        })
    );
    assert!(body.get("session_id").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("user_id").is_none());
}
