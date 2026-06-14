use super::*;
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
