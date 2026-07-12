use super::*;
use std::{sync::Arc, time::Duration as StdDuration};

use actix_web::test::TestRequest;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::settings::{EmailDelivery, SmtpEmailSettings, SmtpTlsMode};
use diesel::sql_query;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

fn send_code_request(email: &str) -> SendCodeRequest {
    SendCodeRequest {
        email: email.to_owned(),
    }
}

fn email_code_state(configure_email: bool) -> Data<AppState> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    if configure_email {
        settings.email.delivery = EmailDelivery::Smtp(SmtpEmailSettings {
            host: "127.0.0.1".to_owned(),
            port: 1025,
            tls: SmtpTlsMode::None,
            username: None,
            password: None,
            from: "Nazo OAuth <no-reply@example.com>"
                .parse()
                .expect("test sender should parse"),
        });
    }
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_email_code_test_invalid:nazo_email_code_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    })
}

struct LiveEmailCodeFixture {
    state: Data<AppState>,
}

impl LiveEmailCodeFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("default settings should load");
        settings.email.delivery = EmailDelivery::Smtp(SmtpEmailSettings {
            host: "127.0.0.1".to_owned(),
            port: 1025,
            tls: SmtpTlsMode::None,
            username: None,
            password: None,
            from: "Nazo OAuth <no-reply@example.com>"
                .parse()
                .expect("test sender should parse"),
        });
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_secs(2);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_secs(2);
            connection.internal_command_timeout = StdDuration::from_secs(2);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");

        Some(Self {
            state: Data::new(AppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            }),
        })
    }

    async fn create_user(&self, email: &str) -> UserRow {
        let tenant = default_tenant_context();
        let username = format!("email-code-{}", Uuid::now_v7().simple());
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-email-code-test-hash', true, false, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(tenant.tenant_id)
        .bind::<SqlUuid, _>(tenant.realm_id)
        .bind::<SqlUuid, _>(tenant.organization_id)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email.to_owned())
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn key_exists(&self, key: &str) -> bool {
        valkey_get(&self.state.valkey, key)
            .await
            .expect("valkey lookup should succeed")
            .is_some()
    }

    fn verification_code_key(&self, email: &str) -> String {
        let email = normalize_email_address(email).expect("test email should normalize");
        format!("oauth:email_verify:code:{email}")
    }

    fn email_cooldown_key(&self, email: &str) -> String {
        let email = normalize_email_address(email).expect("test email should normalize");
        format!("oauth:email_verify:send:{email}")
    }
}

#[actix_web::test]
async fn success_response_preserves_user_enumeration_resistance() {
    let response = send_code_success_response(false, Some("123456"));
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;

    assert_eq!(body.get("success"), Some(&json!(true)));
    assert_eq!(
        body.get("message").and_then(Value::as_str),
        Some("如果邮箱尚未注册，验证码将会发送。")
    );
    assert!(
        body.get("verification_code").is_none(),
        "normal success responses must not reveal whether an account exists or expose a code"
    );
}

#[actix_web::test]
async fn dev_success_response_exposes_code_only_when_explicitly_enabled_and_available() {
    let without_code = response_json(send_code_success_response(true, None)).await;
    assert!(
        without_code.get("verification_code").is_none(),
        "cooldown and existing-user paths must not invent a verification code"
    );

    let with_code = response_json(send_code_success_response(true, Some("654321"))).await;
    if cfg!(debug_assertions) {
        assert_eq!(with_code.get("verification_code"), Some(&json!("654321")));
    } else {
        assert!(
            with_code.get("verification_code").is_none(),
            "release builds must not leak verification codes even if dev response is configured"
        );
    }
}

#[test]
fn peer_cooldown_key_hashes_peer_identity_and_fails_closed_without_peer() {
    let request = TestRequest::default()
        .peer_addr("203.0.113.10:49152".parse().unwrap())
        .to_http_request();
    let key = email_code_peer_cooldown_key(&request);

    assert!(key.starts_with("oauth:email_verify:peer_send:"));
    assert!(
        !key.contains("203.0.113.10"),
        "rate-limit keys must not store raw peer identifiers"
    );
    assert_eq!(
        key,
        format!(
            "oauth:email_verify:peer_send:{}",
            blake3_hex("203.0.113.10")
        )
    );

    let missing_peer = TestRequest::default().to_http_request();
    assert_eq!(
        email_code_peer_cooldown_key(&missing_peer),
        format!("oauth:email_verify:peer_send:{}", blake3_hex("unknown")),
        "missing peer context must remain rate-limited under a stable fail-closed bucket"
    );
}

#[actix_web::test]
async fn send_code_rejects_invalid_email_before_delivery_or_user_lookup() {
    let req = TestRequest::default().to_http_request();

    let (status, body) = status_json(
        send_code_after_rate_limit(
            email_code_state(false),
            req,
            send_code_request("not an email address"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("verification_code").is_none());
}

#[actix_web::test]
async fn send_code_requires_configured_delivery_before_user_enumeration_paths() {
    let req = TestRequest::default().to_http_request();

    let (status, body) = status_json(
        send_code_after_rate_limit(
            email_code_state(false),
            req,
            send_code_request("user@example.com"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("verification_code").is_none());
}

#[actix_web::test]
async fn send_code_reports_user_lookup_failure_without_exposing_registration_state() {
    let req = TestRequest::default().to_http_request();

    let (status, body) = status_json(
        send_code_after_rate_limit(
            email_code_state(true),
            req,
            send_code_request("user@example.com"),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("success").is_none());
    assert!(body.get("verification_code").is_none());
}

#[actix_web::test]
async fn send_code_existing_user_returns_uniform_success_without_mutating_rate_limit_state() {
    let Some(fixture) = LiveEmailCodeFixture::new().await else {
        return;
    };
    let email = format!(
        "email-code-existing-{}@example.com",
        Uuid::now_v7().simple()
    );
    fixture.create_user(&email).await;
    let req = TestRequest::default().to_http_request();
    let peer_key = email_code_peer_cooldown_key(&req);

    let (status, body) = status_json(
        send_code_after_rate_limit(
            fixture.state.clone(),
            req,
            send_code_request(&email.to_uppercase()),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert!(body.get("verification_code").is_none());
    assert!(
        !fixture
            .key_exists(&fixture.verification_code_key(&email))
            .await,
        "existing-account requests must not mint a new verification code"
    );
    assert!(
        !fixture.key_exists(&peer_key).await,
        "existing-account short-circuit must happen before peer cooldown state is written"
    );
}

#[actix_web::test]
async fn send_code_peer_cooldown_short_circuits_without_writing_email_state() {
    let Some(fixture) = LiveEmailCodeFixture::new().await else {
        return;
    };
    let email = format!(
        "email-code-peer-cooldown-{}@example.com",
        Uuid::now_v7().simple()
    );
    let req = TestRequest::default()
        .peer_addr(
            "203.0.113.10:49152"
                .parse()
                .expect("peer address should parse"),
        )
        .to_http_request();
    let peer_key = email_code_peer_cooldown_key(&req);
    valkey_set_ex(
        &fixture.state.valkey,
        &peer_key,
        "1",
        fixture.state.settings.email.send_peer_cooldown_seconds,
    )
    .await
    .expect("peer cooldown should seed");

    let (status, body) = status_json(
        send_code_after_rate_limit(fixture.state.clone(), req, send_code_request(&email)).await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert!(body.get("verification_code").is_none());
    assert!(
        !fixture
            .key_exists(&fixture.verification_code_key(&email))
            .await,
        "peer-cooled requests must not create a reusable verification code"
    );
    assert!(
        !fixture
            .key_exists(&fixture.email_cooldown_key(&email))
            .await,
        "peer cooldown must short-circuit before email-specific cooldown state is written"
    );
}

#[actix_web::test]
async fn send_code_email_cooldown_short_circuits_without_rotating_verification_code() {
    let Some(fixture) = LiveEmailCodeFixture::new().await else {
        return;
    };
    let email = format!(
        "email-code-cooldown-{}@example.com",
        Uuid::now_v7().simple()
    );
    let req = TestRequest::default()
        .peer_addr(
            "203.0.113.11:49152"
                .parse()
                .expect("peer address should parse"),
        )
        .to_http_request();
    let peer_key = email_code_peer_cooldown_key(&req);
    let cooldown_key = fixture.email_cooldown_key(&email);
    valkey_set_ex(
        &fixture.state.valkey,
        &cooldown_key,
        "1",
        fixture.state.settings.email.send_cooldown_seconds,
    )
    .await
    .expect("email cooldown should seed");

    let (status, body) = status_json(
        send_code_after_rate_limit(fixture.state.clone(), req, send_code_request(&email)).await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert!(body.get("verification_code").is_none());
    assert!(
        !fixture
            .key_exists(&fixture.verification_code_key(&email))
            .await,
        "cooldown-short-circuited requests must not rotate the active verification code"
    );
    assert!(
        fixture.key_exists(&cooldown_key).await,
        "the existing email cooldown marker must remain authoritative"
    );
    assert!(
        fixture.key_exists(&peer_key).await,
        "peer cooldown should still be recorded once the request passes the peer-level gate"
    );
}

async fn response_json(response: HttpResponse) -> Value {
    status_json(response).await.1
}

async fn status_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    (
        status,
        serde_json::from_slice(&body).expect("response body should be json"),
    )
}
