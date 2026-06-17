use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn endpoint_state(require_par: bool) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.require_pushed_authorization_requests = require_par;
    settings.issuer = "https://issuer.example".to_owned();
    settings.frontend_base_url = "https://app.example".to_owned();
    settings.auth_code_ttl_seconds = 60;

    AppState {
        diesel_db: create_pool(
            "postgres://nazo_authorize_test_invalid:nazo_authorize_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

fn unsigned_request_object(claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

#[actix_web::test]
async fn authorization_get_rejects_duplicate_oauth_parameters_before_client_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&client_id=client-b&response_type=code")
        .to_http_request();
    let mut q = query(&[("client_id", "client-b"), ("response_type", "code")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn authorization_get_requires_par_before_untrusted_runtime_parameters() {
    let state = Data::new(endpoint_state(true));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&response_type=code")
        .to_http_request();
    let mut q = query(&[("client_id", "client-a"), ("response_type", "code")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("redirect_uri").is_none());
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_get_requires_client_id_before_database_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?response_type=code")
        .to_http_request();
    let mut q = query(&[("response_type", "code")]);

    let response = authorize_request(state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn authorization_get_wrapper_uses_same_pre_database_validation() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?response_type=code")
        .to_http_request();
    let q = query(&[("response_type", "code")]);

    let response = authorize_get(state, req, Query(q)).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_post_wrapper_rejects_duplicate_parameters_before_client_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::post()
        .uri("/authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let body = Bytes::from_static(b"client_id=client-a&client_id=client-b&response_type=code");

    let (status, body) = json_body(authorize_post(state, req, body).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_extracts_client_id_from_request_object_before_client_lookup() {
    let state = Data::new(endpoint_state(false));
    let request_object = unsigned_request_object(json!({
        "client_id": "client-from-request-object",
        "iss": "client-from-request-object",
        "aud": "https://issuer.example",
        "response_type": "code",
        "redirect_uri": "https://client.example/cb"
    }));
    let uri = format!(
        "/authorize?request={}",
        urlencoding::encode(&request_object)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[("request", request_object.as_str())]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(
        q.get("client_id").map(String::as_str),
        Some("client-from-request-object")
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
}

#[actix_web::test]
async fn authorization_request_reports_client_lookup_failure_without_redirecting() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&response_type=code")
        .to_http_request();
    let mut q = query(&[("client_id", "client-a"), ("response_type", "code")]);

    let response = authorize_request(state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}
