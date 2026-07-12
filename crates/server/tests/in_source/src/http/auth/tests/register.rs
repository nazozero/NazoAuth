use super::*;
use std::{sync::Arc, time::Duration as StdDuration};

use crate::config::ConfigSource;
use crate::db::create_pool;

use diesel::sql_query;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

fn invalid_register_state() -> Data<AppState> {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let mut valkey_builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_register_test_invalid:nazo_register_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: valkey_builder
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

fn test_register_password() -> String {
    ["correct", "horse", "battery", "staple"].join(" ")
}

fn valid_verification_code() -> String {
    ['1', '2', '3', '4', '5', '6'].iter().collect()
}

fn padded_valid_verification_code() -> String {
    format!("  {}  ", valid_verification_code())
}

fn alternate_verification_code() -> String {
    ['6', '5', '4', '3', '2', '1'].iter().collect()
}

fn register_request() -> RegisterRequest {
    RegisterRequest {
        email: "User@Example.com".to_owned(),
        verification_code: padded_valid_verification_code(),
        password: test_register_password(),
    }
}

struct LiveRegisterFixture {
    state: Data<AppState>,
}

#[actix_web::test]
async fn find_user_by_email_treats_like_metacharacters_literally() {
    let Some(fixture) = LiveRegisterFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple();
    let victim_email = format!("wildxcard-{suffix}@example.com");
    let wildcard_email = format!("wild_card-{suffix}@example.com");
    let victim = fixture.create_user(&victim_email).await;

    assert!(
        fixture.user_by_email(&wildcard_email).await.is_none(),
        "email lookup must not treat '_' as a wildcard and match {}",
        victim.email
    );
    assert_eq!(
        fixture
            .user_by_email(&victim_email)
            .await
            .expect("literal victim email should still resolve")
            .id,
        victim.id
    );
}

impl LiveRegisterFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let settings =
            Settings::from_config(&ConfigSource::default()).expect("default settings should load");
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
                keyset: crate::test_support::test_key_manager(),
            }),
        })
    }

    async fn create_user(&self, email: &str) -> UserRow {
        let tenant = default_tenant_context();
        let username = format!("register-{}", Uuid::now_v7().simple());
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-register-test-hash', true, false, true, 'user', 0)
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

    async fn user_by_email(&self, email: &str) -> Option<UserRow> {
        let email = normalize_email_address(email).expect("test email should normalize");
        find_user_by_email(&self.state.diesel_db, &email)
            .await
            .expect("user lookup should succeed")
    }

    async fn store_verification_code(&self, email: &str, code: &str) {
        let email = normalize_email_address(email).expect("test email should normalize");
        let code_hash = hash_password(code).expect("verification code hash should derive");
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:email_verify:code:{email}"),
            code_hash,
            300,
        )
        .await
        .expect("verification code should store");
    }

    async fn verification_code_exists(&self, email: &str) -> bool {
        let email = normalize_email_address(email).expect("test email should normalize");
        valkey_get(
            &self.state.valkey,
            format!("oauth:email_verify:code:{email}"),
        )
        .await
        .expect("verification code lookup should succeed")
        .is_some()
    }
}

fn user_row() -> UserRow {
    let now = Utc::now();
    UserRow {
        id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        realm_id: Uuid::now_v7(),
        organization_id: Uuid::now_v7(),
        username: "user@example.com".to_owned(),
        email: "user@example.com".to_owned(),
        display_name: None,
        avatar_url: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile_url: None,
        website_url: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        role: "user".to_owned(),
        admin_level: 0,
        address_formatted: None,
        address_street_address: None,
        address_locality: None,
        address_region: None,
        address_postal_code: None,
        address_country: None,
        phone_number: None,
        phone_number_verified: false,
        email_verified: true,
        mfa_enabled: false,
        password_hash: "argon2-secret-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("register response body should collect");
    let body: Value = serde_json::from_slice(&body).expect("register response should be json");
    (status, body)
}

#[test]
fn verification_code_for_lookup_trims_transport_whitespace_only() {
    let payload = register_request();

    assert_eq!(verification_code_for_lookup(&payload), "123456");
}

#[actix_web::test]
async fn register_rejects_invalid_email_before_database_or_code_lookup() {
    let mut payload = register_request();
    payload.email = "not an email address".to_owned();

    let (status, body) =
        response_json(register_after_rate_limit(invalid_register_state(), payload).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("id").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("session").is_none());
}

#[actix_web::test]
async fn register_reports_code_lookup_failure_without_consuming_credentials() {
    let payload = register_request();

    let (status, body) =
        response_json(register_after_rate_limit(invalid_register_state(), payload).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("id").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn register_success_response_exposes_only_public_identity() {
    let user = user_row();
    let response = register_success_response(user.clone());

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("register success response should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["id"], json!(user.id));
    assert_eq!(body["email"], "user@example.com");
    assert!(body.get("password_hash").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("session").is_none());
    assert!(body.get("tenant_id").is_none());
}

#[actix_web::test]
async fn register_rejects_existing_email_without_consuming_verification_code() {
    let Some(fixture) = LiveRegisterFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("register-existing-{suffix}@example.com");
    let existing = fixture.create_user(&email).await;
    let verification_code = valid_verification_code();
    fixture
        .store_verification_code(&email, &verification_code)
        .await;

    let mut payload = register_request();
    payload.email = email.to_uppercase();

    let (status, body) =
        response_json(register_after_rate_limit(fixture.state.clone(), payload).await).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("id").is_none());
    assert_eq!(
        fixture
            .user_by_email(&email)
            .await
            .expect("existing user should remain present")
            .id,
        existing.id
    );
    assert!(
        fixture.verification_code_exists(&email).await,
        "email-already-registered rejections must not consume verification material"
    );
}

#[actix_web::test]
async fn register_does_not_reveal_existing_email_without_valid_verification_code() {
    let Some(fixture) = LiveRegisterFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("register-existing-invalid-code-{suffix}@example.com");
    fixture.create_user(&email).await;
    fixture
        .store_verification_code(&email, &alternate_verification_code())
        .await;

    let mut payload = register_request();
    payload.email = email;

    let (status, body) =
        response_json(register_after_rate_limit(fixture.state.clone(), payload).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("id").is_none());
}

#[actix_web::test]
async fn register_rejects_invalid_verification_code_without_creating_user() {
    let Some(fixture) = LiveRegisterFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("register-invalid-code-{suffix}@example.com");
    let verification_code = alternate_verification_code();
    fixture
        .store_verification_code(&email, &verification_code)
        .await;

    let mut payload = register_request();
    payload.email = email.clone();

    let (status, body) =
        response_json(register_after_rate_limit(fixture.state.clone(), payload).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("id").is_none());
    assert!(
        fixture.user_by_email(&email).await.is_none(),
        "invalid verification codes must not provision a local account"
    );
    assert!(
        fixture.verification_code_exists(&email).await,
        "failed registrations must leave the original verification code intact"
    );
}

#[actix_web::test]
async fn register_creates_verified_user_and_consumes_verification_code() {
    let Some(fixture) = LiveRegisterFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("register-success-{suffix}@example.com");
    let verification_code = valid_verification_code();
    fixture
        .store_verification_code(&email, &verification_code)
        .await;

    let mut payload = register_request();
    payload.email = email.to_uppercase();
    let password = payload.password.clone();

    let (status, body) =
        response_json(register_after_rate_limit(fixture.state.clone(), payload).await).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["email"], email);
    let created = fixture
        .user_by_email(&email)
        .await
        .expect("successful registration should create a user");
    assert_eq!(body["id"], json!(created.id));
    assert!(created.email_verified);
    assert_ne!(
        created.password_hash, password,
        "passwords must be hashed before they reach the database"
    );
    assert!(
        !fixture.verification_code_exists(&email).await,
        "successful registrations must consume the one-time verification code"
    );
}
