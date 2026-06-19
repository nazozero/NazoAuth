use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};
use crate::http::authorization::request::pushed_authorization_request_key;
use actix_web::test::TestRequest;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

fn prompt_none_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: format!("request-{}", Uuid::now_v7()),
        user_id: Uuid::now_v7(),
        client_id: "client-prompt-none".to_owned(),
        client_name: "Prompt None Client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["sid".to_owned()],
        id_token_claim_requests: Vec::new(),
        code_challenge: Some(pkce_s256(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn prompt_none_state_with_valkey(valkey: fred::prelude::Client) -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.auth_code_ttl_seconds = 60;

    AppState {
        diesel_db: create_pool(
            "postgres://nazo_prompt_none_test_invalid:nazo_prompt_none_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

async fn live_prompt_none_state() -> Option<AppState> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(1000);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(1000);
        connection.internal_command_timeout = std::time::Duration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    Some(prompt_none_state_with_valkey(valkey))
}

fn unavailable_prompt_none_state() -> AppState {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(50);
        connection.internal_command_timeout = std::time::Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    prompt_none_state_with_valkey(
        builder
            .build()
            .expect("valkey client construction should not connect"),
    )
}

fn prompt_none_request() -> HttpRequest {
    TestRequest::get()
        .uri("/oauth/authorize?prompt=none")
        .to_http_request()
}

fn redirect_query(response: &HttpResponse) -> std::collections::HashMap<String, String> {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization response should redirect")
        .to_str()
        .expect("Location should be valid UTF-8");
    url::Url::parse(location)
        .expect("Location should be absolute")
        .query_pairs()
        .into_owned()
        .collect()
}

#[test]
fn stored_grant_covers_prompt_none_request_when_scope_is_subset() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "profile", "email"]),
        &json!([]),
        &parse_scope("openid email"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_or_malformed_scope_sets() {
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "profile"]),
        &json!([]),
        &parse_scope("openid email"),
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!({"scope": "openid"}),
        &json!([]),
        &parse_scope("openid"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_treats_empty_requested_authorization_details_as_already_covered() {
    let stored_high_risk_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &stored_high_risk_details,
        &parse_scope("openid"),
        &json!([]),
    ));
}

#[test]
fn stored_grant_requires_exact_authorization_details_binding() {
    let scopes = json!(["openid", "payments"]);
    let read_details = json!([{"type":"account_information","actions":["read"]}]);
    let different_read_details =
        json!([{"type":"account_information","actions":["read"],"locations":["acct-2"]}]);

    assert!(stored_grant_covers_requested_authorization(
        &scopes,
        &read_details,
        &parse_scope("openid payments"),
        &read_details,
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &scopes,
        &read_details,
        &parse_scope("openid payments"),
        &different_read_details,
    ));
}

#[test]
fn stored_grant_never_silently_reuses_high_risk_authorization_details() {
    let payment_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &payment_details,
        &parse_scope("openid payments"),
        &payment_details,
    ));
}

#[actix_web::test]
async fn prompt_none_issues_single_use_authorization_code_without_user_interaction() {
    let Some(state) = live_prompt_none_state().await else {
        return;
    };
    let payload = prompt_none_payload();

    let response = issue_authorization_code_without_interaction(
        &state,
        &prompt_none_request(),
        payload.clone(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let query = redirect_query(&response);
    let code = query
        .get("code")
        .expect("prompt=none approval should issue authorization code");
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        query.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !query.contains_key("error"),
        "successful prompt=none response must not carry an OAuth error"
    );

    let raw = valkey_get(&state.valkey, authorization_code_key(code))
        .await
        .expect("authorization code should be readable")
        .expect("authorization code state should exist");
    match serde_json::from_str::<AuthorizationCodeState>(&raw)
        .expect("authorization code state should deserialize")
    {
        AuthorizationCodeState::Pending {
            payload: code_payload,
        } => {
            assert_eq!(code_payload.user_id, payload.user_id);
            assert_eq!(code_payload.client_id, payload.client_id);
            assert_eq!(code_payload.scopes, payload.scopes);
            assert_eq!(code_payload.nonce, payload.nonce);
            assert_eq!(code_payload.oidc_sid, payload.oidc_sid);
            assert_eq!(code_payload.id_token_claims, payload.id_token_claims);
        }
        _ => panic!("prompt=none must create a pending authorization code state"),
    }
}

#[actix_web::test]
async fn prompt_none_fails_closed_when_authorization_code_cannot_be_persisted() {
    let state = unavailable_prompt_none_state();

    let response = issue_authorization_code_without_interaction(
        &state,
        &prompt_none_request(),
        prompt_none_payload(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "prompt=none must not redirect with a code when the authorization code was not stored"
    );
}

#[actix_web::test]
async fn prompt_none_redirects_invalid_request_uri_when_request_uri_is_missing() {
    let Some(state) = live_prompt_none_state().await else {
        return;
    };
    let mut payload = prompt_none_payload();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    payload.pushed_request_uri = Some(request_uri);

    let response = issue_authorization_code_without_interaction(
        &state,
        &prompt_none_request(),
        payload,
    )
    .await;

    let query = redirect_query(&response);
    assert_eq!(query.get("error").map(String::as_str), Some("invalid_request_uri"));
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
}

#[actix_web::test]
async fn prompt_none_redirects_server_error_when_request_uri_is_malformed() {
    let Some(state) = live_prompt_none_state().await else {
        return;
    };
    let mut payload = prompt_none_payload();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    valkey_set_ex(
        &state.valkey,
        pushed_authorization_request_key(&request_uri),
        "{not-json".to_owned(),
        state.settings.auth_code_ttl_seconds,
    )
    .await
    .expect("malformed request_uri should persist");
    payload.pushed_request_uri = Some(request_uri);

    let response = issue_authorization_code_without_interaction(
        &state,
        &prompt_none_request(),
        payload,
    )
    .await;

    let query = redirect_query(&response);
    assert_eq!(query.get("error").map(String::as_str), Some("server_error"));
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
}

#[actix_web::test]
async fn prompt_none_redirects_server_error_when_request_uri_read_fails() {
    let state = unavailable_prompt_none_state();
    let mut payload = prompt_none_payload();
    payload.pushed_request_uri = Some(format!(
        "urn:ietf:params:oauth:request_uri:{}",
        Uuid::now_v7()
    ));

    let response =
        issue_authorization_code_without_interaction(&state, &prompt_none_request(), payload).await;

    let query = redirect_query(&response);
    assert_eq!(query.get("error").map(String::as_str), Some("server_error"));
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
}
