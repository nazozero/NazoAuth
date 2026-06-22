use super::*;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use actix_web::cookie::Cookie;
use diesel::sql_query;
use diesel::sql_types::{Bool, Nullable, Text, Uuid as SqlUuid};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::support::OAuthJsonErrorFields;

#[test]
fn profile_text_trims_blank_values_and_enforces_byte_limit() {
    assert_eq!(profile_text(None, 8, "display_name").unwrap(), None);
    assert_eq!(
        profile_text(Some("   \t ".to_owned()), 8, "display_name").unwrap(),
        None
    );
    assert_eq!(
        profile_text(Some("  Alice  ".to_owned()), 8, "display_name").unwrap(),
        Some("Alice".to_owned())
    );

    let response = profile_text(Some("abcdefghi".to_owned()), 8, "display_name").unwrap_err();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_oauth_error(&response, "invalid_request");
}

#[test]
fn normalize_profile_url_accepts_only_absolute_http_urls_without_fallback() {
    assert_eq!(
        normalize_profile_url(
            Some(" https://profile.example/u/alice ".to_owned()),
            "profile_url"
        )
        .unwrap(),
        Some("https://profile.example/u/alice".to_owned())
    );
    assert_eq!(
        normalize_profile_url(Some("http://localhost/profile".to_owned()), "profile_url").unwrap(),
        Some("http://localhost/profile".to_owned())
    );
    assert_eq!(normalize_profile_url(None, "profile_url").unwrap(), None);
    assert_eq!(
        normalize_profile_url(Some("   ".to_owned()), "profile_url").unwrap(),
        None
    );

    for invalid in [
        "client.example/profile",
        "/relative/profile",
        "javascript:alert(1)",
        "mailto:user@example.com",
        "urn:example:profile",
    ] {
        let response = normalize_profile_url(Some(invalid.to_owned()), "profile_url").unwrap_err();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_oauth_error(&response, "invalid_request");
    }
}

fn assert_oauth_error(response: &HttpResponse, expected: &str) {
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some(expected)
    );
}

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_profile_account_test_invalid:nazo_profile_account_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn request_with_session_but_no_csrf(state: &AppState, sid: &str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session_cookie_name.clone(),
            sid.to_owned(),
        ))
        .to_http_request()
}

struct LiveAccountFixture {
    state: Data<AppState>,
}

impl LiveAccountFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_account_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_account_test"),
        ]);
        let settings = Settings::from_config(&config).expect("test settings should load");
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
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

    async fn create_user(
        &self,
        suffix: &str,
        display_name: Option<&str>,
        phone_number: Option<&str>,
        phone_number_verified: bool,
    ) -> UserRow {
        let email = format!("account-{suffix}@example.com");
        let username = format!("account-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level,
                display_name, phone_number, phone_number_verified
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-account-test-hash', $6, false, true, 'user', 0, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Bool, _>(true)
        .bind::<Nullable<Text>, _>(display_name.map(str::to_owned))
        .bind::<Nullable<Text>, _>(phone_number.map(str::to_owned))
        .bind::<Bool, _>(phone_number_verified)
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &UserRow, sid: &str, pending_mfa: bool) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:session:{sid}"),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    fn request(&self, sid: &str, csrf: &str) -> HttpRequest {
        actix_web::test::TestRequest::default()
            .cookie(Cookie::new(
                self.state.settings.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }

    fn request_with_csrf_cookie(&self, sid: &str, csrf: &str) -> HttpRequest {
        actix_web::test::TestRequest::default()
            .cookie(Cookie::new(
                self.state.settings.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .to_http_request()
    }

    async fn fresh_user(&self, user_id: Uuid) -> UserRow {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        users::table
            .find(user_id)
            .select(UserRow::as_select())
            .first::<UserRow>(&mut conn)
            .await
            .expect("user should reload")
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value, bool) {
    let status = response.status();
    let has_set_cookie = response
        .headers()
        .contains_key(actix_web::http::header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

async fn assert_account_write_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("email").is_none());
    assert!(body.get("display_name").is_none());
    assert!(body.get("role").is_none());
    assert!(!has_set_cookie);
}

async fn assert_account_endpoint_requires_login(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert!(body.get("display_name").is_none());
    assert!(body.get("phone_number").is_none());
    assert!(
        has_set_cookie,
        "login-required profile responses must clear stale session cookies"
    );
}

#[actix_web::test]
async fn me_returns_pending_mfa_projection_only() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(
            &suffix,
            Some("Pending Account User"),
            Some("+15550000001"),
            true,
        )
        .await;
    let sid = format!("pending-account-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, true).await;

    let (status, body, has_set_cookie) = response_json(
        me(
            fixture.state.clone(),
            fixture.request_with_csrf_cookie(&sid, &csrf),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert_eq!(body["mfa_required"], true);
    assert_eq!(body["id"], json!(user.id));
    assert_eq!(body["email"], user.email);
    assert_eq!(body["csrf_token"], csrf);
    for forbidden in [
        "display_name",
        "avatar_url",
        "phone_number",
        "phone_number_verified",
        "role",
        "authorized_app_count",
    ] {
        assert!(
            body.get(forbidden).is_none(),
            "{forbidden} must not leak before the MFA challenge is completed"
        );
    }
}

#[actix_web::test]
async fn me_returns_authenticated_profile_with_mfa_required_false() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("Active User"), Some("+15550000002"), true)
        .await;
    let sid = format!("active-account-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let (status, body, has_set_cookie) =
        response_json(me(fixture.state.clone(), fixture.request(&sid, &csrf)).await).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert_eq!(body["mfa_required"], false);
    assert_eq!(body["email"], user.email);
    assert_eq!(body["display_name"], "Active User");
    assert_eq!(body["phone_number"], "+15550000002");
    assert_eq!(body["phone_number_verified"], true);
    assert_eq!(body["authorized_app_count"], 0);
    assert!(body.get("csrf_token").is_none());
}

#[actix_web::test]
async fn me_projects_pending_session_lookup_failure_as_server_error() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, None, None, false).await;
    let sid = format!("broken-account-{suffix}");
    fixture.store_session(&user, &sid, true).await;
    let state = Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_account_session_lookup_invalid:nazo_account_session_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(state.settings.session_cookie_name.clone(), sid))
        .to_http_request();

    let (status, body, has_set_cookie) = response_json(me(state, req).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn me_projects_authenticated_session_lookup_failure_as_server_error() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(
            &suffix,
            Some("Broken Active User"),
            Some("+15550000009"),
            true,
        )
        .await;
    let sid = format!("broken-active-account-{suffix}");
    fixture.store_session(&user, &sid, false).await;
    let state = Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_account_active_lookup_invalid:nazo_account_active_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(state.settings.session_cookie_name.clone(), sid))
        .to_http_request();

    let (status, body, has_set_cookie) = response_json(me(state, req).await).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn update_me_rejects_session_request_without_csrf_before_profile_write() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state, "account-update-no-csrf");

    assert_account_write_rejects_missing_csrf(
        update_me(
            state,
            req,
            Json(serde_json::from_value(json!({"display_name": "Alice"})).unwrap()),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn update_me_requires_login_before_profile_write() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_account_endpoint_requires_login(
        update_me(
            state,
            req,
            Json(serde_json::from_value(json!({"display_name": "Alice"})).unwrap()),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn update_me_rejects_invalid_profile_url_without_changing_user_state() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("Original Name"), Some("+15550000003"), true)
        .await;
    let sid = format!("invalid-profile-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let payload = serde_json::from_value::<UpdateProfileRequest>(json!({
        "display_name": "Updated Name",
        "profile_url": "javascript:alert(1)"
    }))
    .expect("payload should parse");
    let (status, body, has_set_cookie) = response_json(
        update_me(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(payload),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(!has_set_cookie);
    let fresh = fixture.fresh_user(user.id).await;
    assert_eq!(fresh.display_name.as_deref(), Some("Original Name"));
    assert_eq!(fresh.profile_url, None);
    assert_eq!(fresh.phone_number.as_deref(), Some("+15550000003"));
    assert!(fresh.phone_number_verified);
}

#[actix_web::test]
async fn update_me_rejects_overlong_display_name_without_changing_user_state() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("Original Name"), Some("+15550000008"), true)
        .await;
    let sid = format!("account-display-name-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let payload = serde_json::from_value::<UpdateProfileRequest>(json!({
        "display_name": "A".repeat(81)
    }))
    .expect("payload should parse");
    let (status, body, has_set_cookie) = response_json(
        update_me(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(payload),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(!has_set_cookie);
    let fresh = fixture.fresh_user(user.id).await;
    assert_eq!(fresh.display_name.as_deref(), Some("Original Name"));
    assert_eq!(fresh.phone_number.as_deref(), Some("+15550000008"));
    assert!(fresh.phone_number_verified);
}

#[actix_web::test]
async fn update_me_updates_only_whitelisted_profile_fields() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, Some("Original Name"), Some("+15550000004"), true)
        .await;
    let sid = format!("account-update-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let payload = serde_json::from_value::<UpdateProfileRequest>(json!({
        "display_name": "  Alice Example  ",
        "given_name": " Alice ",
        "family_name": " Example ",
        "middle_name": "   ",
        "nickname": "  Ally ",
        "profile_url": " https://profile.example/users/alice ",
        "website_url": "https://alice.example",
        "gender": "female",
        "birthdate": "2000-01-02",
        "zoneinfo": "Asia/Shanghai",
        "locale": "zh-CN",
        "address_formatted": "  1 Infinite Loop ",
        "address_street_address": "  1 Infinite Loop  ",
        "address_locality": "Cupertino",
        "address_region": "CA",
        "address_postal_code": "95014",
        "address_country": "US",
        "phone_number": " +15550000004 ",
        "email": "hijack@example.com",
        "role": "admin",
        "admin_level": 9,
        "mfa_enabled": true
    }))
    .expect("payload should parse");

    let (status, body, has_set_cookie) = response_json(
        update_me(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(payload),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert_eq!(body["display_name"], "Alice Example");
    assert_eq!(body["given_name"], "Alice");
    assert_eq!(body["family_name"], "Example");
    assert!(body["middle_name"].is_null());
    assert_eq!(body["nickname"], "Ally");
    assert_eq!(body["profile_url"], "https://profile.example/users/alice");
    assert_eq!(body["website_url"], "https://alice.example");
    assert_eq!(body["phone_number"], "+15550000004");
    assert_eq!(body["phone_number_verified"], true);
    assert_eq!(body["email"], user.email);
    assert_eq!(body["role"], "user");
    assert_eq!(body["admin_level"], 0);
    let fresh = fixture.fresh_user(user.id).await;
    assert_eq!(fresh.email, user.email);
    assert_eq!(fresh.role, "user");
    assert_eq!(fresh.admin_level, 0);
    assert_eq!(fresh.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(fresh.given_name.as_deref(), Some("Alice"));
    assert_eq!(fresh.family_name.as_deref(), Some("Example"));
    assert_eq!(fresh.middle_name, None);
    assert_eq!(fresh.nickname.as_deref(), Some("Ally"));
    assert_eq!(
        fresh.profile_url.as_deref(),
        Some("https://profile.example/users/alice")
    );
    assert_eq!(fresh.website_url.as_deref(), Some("https://alice.example"));
    assert_eq!(fresh.phone_number.as_deref(), Some("+15550000004"));
    assert!(fresh.phone_number_verified);
}

#[actix_web::test]
async fn update_me_resets_phone_verification_when_phone_number_changes() {
    let Some(fixture) = LiveAccountFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&suffix, None, Some("+15550000005"), true)
        .await;
    let sid = format!("account-phone-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let payload = serde_json::from_value::<UpdateProfileRequest>(json!({
        "phone_number": "+15559999999"
    }))
    .expect("payload should parse");
    let (status, body, has_set_cookie) = response_json(
        update_me(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(payload),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert_eq!(body["phone_number"], "+15559999999");
    assert_eq!(body["phone_number_verified"], false);
    let fresh = fixture.fresh_user(user.id).await;
    assert_eq!(fresh.phone_number.as_deref(), Some("+15559999999"));
    assert!(!fresh.phone_number_verified);
}
