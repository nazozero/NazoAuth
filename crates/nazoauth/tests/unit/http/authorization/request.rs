use crate::test_support::valkey::{valkey_get, valkey_set_ex};
use crate::test_support::{DatabaseUserFixture, TestInfrastructure};
use crate::{config::ConfigSource, settings::Settings};
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use chrono::{Duration, Utc};
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};
use nazo_http_actix::{
    client_ip_with_config, cookie_value, form_post_authorization_response,
    oauth_endpoint_error_response, redirect_found,
};
use nazo_identity::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID, SessionId};
use nazo_oauth_server::{
    authorization::{AuthorizationOutcome, AuthorizationRequestFacts},
    crypto::pkce_s256,
    domain::oauth::{AuthorizationCodeState, PushedAuthorizationRequest},
    sessions::SessionPayload,
};
use nazo_postgres::create_pool;
use nazo_valkey::test_support::authorization_code_storage_key as authorization_code_key;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

async fn authorize_get(state: Data<TestInfrastructure>, req: HttpRequest) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    super::authorize_get(Data::new(dependencies.endpoint()), req).await
}
async fn authorize_post(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    super::authorize_post(Data::new(dependencies.endpoint()), req, body).await
}
async fn authorize_request(
    state: Data<TestInfrastructure>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    authorize_with_fixture(&dependencies.fixture, req, q).await
}
async fn authorize_with_fixture(
    fixture: &crate::http::authorization::test_support::AuthorizationTestFixture,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    let source_ip = client_ip_with_config(&req, &fixture.client_ip);
    let sid = cookie_value(&req, fixture.session_http.session_cookie_name()).map(SessionId::new);
    let facts = AuthorizationRequestFacts {
        source_ip: &source_ip,
        session_id: sid.as_ref(),
        user_agent: req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    };
    match fixture.application().authorize(&facts, q).await {
        Ok(AuthorizationOutcome::Redirect { location }) => redirect_found(location),
        Ok(AuthorizationOutcome::FormPost {
            action,
            parameters,
            session_state,
            csp_nonce,
        }) => form_post_authorization_response(
            &action,
            &parameters,
            session_state.as_deref(),
            &csp_nonce,
        ),
        Err(error) => oauth_endpoint_error_response(error),
    }
}
pub(super) async fn response_oauth_error_code(response: HttpResponse) -> Option<String> {
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("read OAuth response body");
    let body: Value = serde_json::from_slice(&body).expect("OAuth response must be JSON");
    body.get("error").and_then(Value::as_str).map(str::to_owned)
}

fn disconnected_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::default_centralized();
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(50);
        connection.internal_command_timeout = std::time::Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("valkey client construction should not connect")
}

#[path = "request/endpoint.rs"]
mod endpoint;
#[path = "request/prompt_none.rs"]
mod prompt_none;

fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn reauth_nonce_state_with_valkey(valkey: fred::prelude::Client) -> TestInfrastructure {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.frontend_base_url = "https://auth.example".to_owned();

    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_reauth_nonce_test_invalid:nazo_reauth_nonce_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn live_reauth_nonce_state() -> Option<TestInfrastructure> {
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
    Some(reauth_nonce_state_with_valkey(valkey))
}

#[actix_web::test]
async fn reauth_nonce_is_single_use_in_live_authorization_state() {
    let Some(state) = live_reauth_nonce_state().await else {
        return;
    };
    let dependencies =
        crate::http::authorization::test_support::TestAuthorizationDependencies::new(&state);
    let nonce = format!("live-reauth-{}", Uuid::now_v7());
    let started_at = Utc::now().timestamp();
    dependencies
        .fixture
        .service
        .store_reauth_nonce(&nonce, started_at, 600)
        .await
        .expect("real Valkey nonce write");
    let facts = AuthorizationRequestFacts {
        source_ip: "127.0.0.1",
        session_id: None,
        user_agent: None,
    };
    for _ in 0..2 {
        let mut resumed = query(&[("_nazo_reauth_nonce", &nonce)]);
        let result = dependencies
            .application()
            .authorize(&facts, &mut resumed)
            .await;
        assert!(
            result.is_err(),
            "missing client_id must fail after nonce consumption"
        );
        assert!(!resumed.contains_key("_nazo_reauth_nonce"));
        assert_eq!(
            dependencies
                .fixture
                .service
                .take_reauth_nonce(&nonce)
                .await
                .expect("real Valkey nonce lookup"),
            None
        );
    }
}
