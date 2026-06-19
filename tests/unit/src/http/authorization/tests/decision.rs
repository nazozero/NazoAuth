use super::*;
use actix_web::cookie::Cookie;
use actix_web::test::TestRequest;
use diesel::sql_query;
use diesel::sql_types::{Bool, Int4, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset};

fn decision_state() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
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

fn consent_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: "request-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        redirect_uri: "https://client.example/callback?existing=1".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn consent_payload_for_user(client_id: &str, user_id: Uuid) -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: format!("request-{}", Uuid::now_v7()),
        user_id,
        client_id: client_id.to_owned(),
        client_name: "Client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        state: Some("test-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("session-oidc".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

#[derive(Clone)]
struct DecisionLiveFixture {
    state: Data<AppState>,
}

impl DecisionLiveFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("test settings should load");
        settings.issuer = "https://issuer.example".to_owned();
        settings.frontend_base_url = "https://app.example".to_owned();
        settings.auth_code_ttl_seconds = 60;

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
                keyset: Arc::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            }),
        })
    }

    async fn create_user(&self, suffix: &str, auth_role: &str, admin_level: i32) -> UserRow {
        let email = format!("authorize-decision-{suffix}@example.com");
        let username = format!("authorize-decision-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection should open");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-authorize-test-hash', true, false, true, $6, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(auth_role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn insert_client(&self, client_id: &str, is_active: bool) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection should open");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client_id)
            .execute(&mut conn)
            .await
            .expect("test client cleanup should succeed");

        sql_query(
            r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_argon2_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip,
                tls_client_auth_san_email, allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                allow_authorization_code_without_pkce, is_active,
                post_logout_redirect_uris, backchannel_logout_session_required
            )
            VALUES (
                $1, $2, $3, $4, 'Authorization Test Client', 'confidential',
                NULL, '["https://client.example/callback"]'::jsonb, '["openid","profile"]'::jsonb, '["resource://default"]'::jsonb,
                '["authorization_code"]'::jsonb, 'client_secret_basic', false,
                false, NULL, NULL,
                '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb,
                false,
                false, false,
                true, $5,
                '[]'::jsonb, true
            )
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client_id)
        .bind::<Bool, _>(is_active)
        .execute(&mut conn)
        .await
        .expect("test client insert should succeed");
    }

    async fn store_session(&self, user: &UserRow, sid: &str, auth_time: i64) {
        let payload = crate::support::SessionPayload {
            user_id: user.id,
            auth_time,
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
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

    async fn store_consent_payload(&self, payload: &ConsentPayload) {
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:consent:{}", payload.request_id),
            serde_json::to_string(payload).expect("consent payload should serialize"),
            self.state.settings.auth_code_ttl_seconds,
        )
        .await
        .expect("consent payload should persist");
    }

    fn auth_request(&self, sid: &str, csrf_token: Option<&str>) -> HttpRequest {
        let mut request = TestRequest::post().uri("/authorize/decision");
        request = request.cookie(Cookie::new(
            self.state.settings.session_cookie_name.clone(),
            sid.to_owned(),
        ));
        request = request.cookie(Cookie::new(
            self.state.settings.csrf_cookie_name.clone(),
            "csrf-session-token".to_owned(),
        ));
        if let Some(csrf_token) = csrf_token {
            request = request.insert_header(("x-csrf-token", csrf_token.to_owned()));
        }
        request.to_http_request()
    }
}

fn redirect_location(response: &HttpResponse) -> url::Url {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization response should redirect")
        .to_str()
        .expect("Location header should be valid UTF-8");
    url::Url::parse(location).expect("redirect location should remain absolute")
}

async fn json_error(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should return JSON");
    (status, value)
}

#[test]
fn authorization_decision_is_explicit_allowlist() {
    assert!(matches!(
        parse_authorization_decision("approve"),
        Some(AuthorizationDecision::Approve)
    ));
    assert!(matches!(
        parse_authorization_decision("deny"),
        Some(AuthorizationDecision::Deny)
    ));
    assert!(parse_authorization_decision("anything-else").is_none());
    assert!(parse_authorization_decision(" approve ").is_none());
}

#[test]
fn missing_or_malformed_consent_payload_is_rejected() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":1}"#.to_owned())).is_none());
}

#[actix_web::test]
async fn denied_authorization_redirect_preserves_state_without_issuing_code() {
    let state = decision_state();
    let payload = consent_payload();
    let response = authorization_error_redirect(&state, &payload, "access_denied").await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed.query_pairs().into_owned().collect::<HashMap<_, _>>();

    assert_eq!(parsed.scheme(), "https");
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("code"),
        "authorization denial must never include an authorization code"
    );
}

#[actix_web::test]
async fn approved_authorization_redirect_omits_error_and_carries_only_the_new_code() {
    let state = decision_state();
    let response = authorization_response_redirect(
        &state,
        "https://client.example/callback",
        "client-1",
        None,
        Some("code-1"),
        None,
        Some("opaque-state"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed.query_pairs().into_owned().collect::<HashMap<_, _>>();

    assert_eq!(pairs.get("code").map(String::as_str), Some("code-1"));
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("error"),
        "successful authorization redirect must not include stale error state"
    );
}

#[actix_web::test]
async fn authorization_decision_requires_authentication_without_session() {
    let state = Data::new(decision_state());
    let form = DecisionForm {
        request_id: "request-no-session".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let req = TestRequest::post()
        .uri("/authorize/decision")
        .to_http_request();
    let (status, body) = json_error(authorize_decision(state, req, Form(form)).await).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
}

#[actix_web::test]
async fn authorization_decision_rejects_invalid_csrf_token_with_session_cookie() {
    let state = decision_state();
    let session_cookie = state.settings.session_cookie_name.clone();
    let csrf_cookie = state.settings.csrf_cookie_name.clone();
    let req = TestRequest::post()
        .uri("/authorize/decision")
        .cookie(Cookie::new(session_cookie, "sid-csrf-1"))
        .cookie(Cookie::new(csrf_cookie, "csrf-cookie"))
        .to_http_request();
    let form = DecisionForm {
        request_id: "request-1".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: Some("csrf-body-mismatch".to_owned()),
    };
    let response = authorize_decision(Data::new(state), req, Form(form)).await;
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_invalid_decision_after_auth() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("invalid-decision", "user", 0).await;
    fixture
        .store_session(&user, "sid-invalid-decision", Utc::now().timestamp())
        .await;
    let req = fixture.auth_request("sid-invalid-decision", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: "request-1".to_owned(),
        decision: "unexpected".to_owned(),
        csrf_token: None,
    };

    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_missing_consent_payload_with_valid_session() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("missing-payload", "user", 0).await;
    fixture
        .store_session(&user, "sid-missing-payload", Utc::now().timestamp())
        .await;
    let req = fixture.auth_request("sid-missing-payload", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: "request-does-not-exist".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_request_if_user_not_match() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let owner = fixture.create_user("mismatch-owner", "user", 0).await;
    let other = fixture.create_user("mismatch-other", "user", 0).await;
    fixture
        .store_session(&owner, "sid-user-mismatch", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user("client-1", other.id);
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-user-mismatch", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn authorization_decision_rejects_request_with_invalid_pushed_request_uri() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("pushed-missing", "user", 0).await;
    fixture
        .store_session(&user, "sid-pushed-missing", Utc::now().timestamp())
        .await;

    let payload = ConsentPayload {
        pushed_request_uri: Some("urn:ietf:params:oauth:request_uri:missing".to_owned()),
        ..consent_payload_for_user("client-1", user.id)
    };
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-pushed-missing", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;

    let location = redirect_location(&response);
    let pairs = location
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("error").map(String::as_str), Some("invalid_request_uri"));
}

#[actix_web::test]
async fn authorization_decision_accepts_deny_with_user_match() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("decision-deny", "user", 0).await;
    fixture
        .store_session(&user, "sid-decision-deny", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user("client-1", user.id);
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-decision-deny", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "deny".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let pairs = redirect_location(&response)
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("error").map(String::as_str), Some("access_denied"));
    assert!(!pairs.contains_key("code"));
}

#[actix_web::test]
async fn authorization_decision_issues_code_for_matching_user_and_client() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("decision-approve", "user", 0).await;
    let client_id = "client-decision-approve";
    fixture.insert_client(client_id, true).await;
    fixture
        .store_session(&user, "sid-decision-approve", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user(client_id, user.id);
    fixture.store_consent_payload(&payload).await;

    let req = fixture.auth_request("sid-decision-approve", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let pairs = redirect_location(&response)
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert!(pairs.contains_key("code"));
    assert!(pairs.contains_key("iss"));
    assert!(!pairs.contains_key("error"));
}
