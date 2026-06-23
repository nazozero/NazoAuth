use super::*;
use actix_web::FromRequest;
use actix_web::cookie::Cookie;
use actix_web::http::{Method, header};
use actix_web::web::Data;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Uuid as SqlUuid};
use fred::interfaces::ClientLike;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore, VerificationKey};
use crate::support::{generate_key_material, public_jwk_from_private_der};

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

fn test_state_with_keyset(keyset: Keyset) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_oidc_logout_test_invalid:nazo_oidc_logout_test_invalid@127.0.0.1:1/nazo"
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
        keyset: KeysetStore::new(keyset),
    }
}

struct LiveLogoutFixture {
    state: Data<AppState>,
}

impl LiveLogoutFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_logout_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_logout_test"),
        ]);
        let settings = Settings::from_config(&config).expect("test settings should load");
        let key_material =
            generate_key_material(Algorithm::EdDSA).expect("EdDSA key should generate");
        let verification_key = public_jwk_from_private_der(
            "logout-kid",
            Algorithm::EdDSA,
            &key_material.private_pkcs8_der,
        )
        .expect("public JWK should derive");
        let mut valkey_builder = fred::prelude::Builder::from_config(
            fred::prelude::Config::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(
            |performance: &mut fred::prelude::PerformanceConfig| {
                performance.default_command_timeout = StdDuration::from_millis(1000);
            },
        );
        valkey_builder.with_connection_config(
            |connection: &mut fred::prelude::ConnectionConfig| {
                connection.connection_timeout = StdDuration::from_millis(1000);
                connection.internal_command_timeout = StdDuration::from_millis(1000);
                connection.max_command_attempts = 1;
            },
        );
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");

        Some(Self {
            state: Data::new(AppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "logout-kid".to_owned(),
                    active_alg: Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(
                        key_material.private_pkcs8_der,
                    ),
                    verification_keys: vec![VerificationKey {
                        kid: "logout-kid".to_owned(),
                        public_jwk: verification_key,
                    }],
                }),
            }),
        })
    }

    async fn create_user(&self, suffix: &str) -> UserRow {
        let email = format!("logout-{suffix}@example.com");
        let username = format!("logout-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-logout-test-hash', $6, false, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Bool, _>(true)
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &UserRow, sid: &str, oidc_sid: &str) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(oidc_sid.to_owned()),
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

    async fn insert_client(
        &self,
        client_id: &str,
        redirect_uri: &str,
        post_logout_redirect_uri: &str,
        backchannel_logout_uri: Option<&str>,
    ) -> Uuid {
        self.insert_client_with_subject(
            client_id,
            redirect_uri,
            post_logout_redirect_uri,
            backchannel_logout_uri,
            "public",
            None,
        )
        .await
    }

    async fn insert_client_with_subject(
        &self,
        client_id: &str,
        redirect_uri: &str,
        post_logout_redirect_uri: &str,
        backchannel_logout_uri: Option<&str>,
        subject_type: &str,
        sector_identifier_host: Option<&str>,
    ) -> Uuid {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_argon2_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
                tls_client_auth_san_ip, tls_client_auth_san_email,
                allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                allow_authorization_code_without_pkce, is_active, post_logout_redirect_uris,
                backchannel_logout_uri, backchannel_logout_session_required,
                subject_type, sector_identifier_host
            )
            VALUES (
                $1, $2, $3, $4, 'OIDC Logout Test Client', 'confidential',
                NULL, $5, '["openid"]'::jsonb, '["resource://default"]'::jsonb,
                '["authorization_code"]'::jsonb, 'client_secret_post', false,
                false, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
                false, false, false, false, true, $6, $7, true, $8, $9
            )
            RETURNING id
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client_id.to_owned())
        .bind::<Jsonb, _>(json!([redirect_uri]))
        .bind::<Jsonb, _>(json!([post_logout_redirect_uri]))
        .bind::<Nullable<Text>, _>(backchannel_logout_uri.map(str::to_owned))
        .bind::<Text, _>(subject_type.to_owned())
        .bind::<Nullable<Text>, _>(sector_identifier_host.map(str::to_owned))
        .get_result::<IdRow>(&mut conn)
        .await
        .expect("test client should insert")
        .id
    }

    async fn grant_client(&self, user: &UserRow, client_id: Uuid) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO user_client_grants (
                tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,
                last_scopes, last_authorization_details, authorization_count
            )
            VALUES ($1, $2, $3, now(), now(), '["openid"]'::jsonb, '[]'::jsonb, 1)
            "#,
        )
        .bind::<SqlUuid, _>(user.tenant_id)
        .bind::<SqlUuid, _>(user.id)
        .bind::<SqlUuid, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("user grant should insert");
    }

    async fn issue_id_token_hint(&self, user_id: Uuid, client_id: &str, oidc_sid: &str) -> String {
        let keyset = self.state.keyset.snapshot();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_owned());
        header.kid = Some(keyset.active_kid.clone());
        keyset
            .sign_jwt(
                &header,
                &json!({
                    "iss": self.state.settings.issuer,
                    "sub": user_id.to_string(),
                    "aud": client_id,
                    "sid": oidc_sid,
                    "exp": Utc::now().timestamp() + 300
                }),
            )
            .await
            .expect("id_token_hint should sign")
    }

    async fn logout_request(
        &self,
        uri: &str,
        sid: Option<&str>,
    ) -> (HttpRequest, actix_web::web::Payload) {
        let mut request = actix_web::test::TestRequest::default().uri(uri);
        if let Some(sid) = sid {
            request = request.cookie(Cookie::new(
                self.state.settings.session_cookie_name.clone(),
                sid.to_owned(),
            ));
        }
        logout_request_with_payload(request).await
    }

    async fn session_exists(&self, sid: &str) -> bool {
        valkey_get(&self.state.valkey, &format!("oauth:session:{sid}"))
            .await
            .expect("session lookup should succeed")
            .is_some()
    }
}

async fn logout_request_with_payload(
    request: actix_web::test::TestRequest,
) -> (HttpRequest, actix_web::web::Payload) {
    let (req, mut payload) = request.to_http_parts();
    let payload = actix_web::web::Payload::from_request(&req, &mut payload)
        .await
        .expect("test payload should extract");
    (req, payload)
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

async fn oauth_error_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    (status, body)
}

fn set_cookie_values(response: &HttpResponse, cookie_name: &str) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .filter_map(|raw| {
            let (name, value) = raw.split(';').next()?.split_once('=')?;
            (name == cookie_name).then(|| value.to_owned())
        })
        .collect()
}

fn form_body_value(request: &str, key: &str) -> Option<String> {
    let body = request.split("\r\n\r\n").nth(1)?;
    url::form_urlencoded::parse(body.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

#[test]
fn logout_query_parser_trims_known_parameters_and_ignores_unknown_values() {
    let form = parse_logout_pairs(
        "id_token_hint=%20token%20&client_id=%20client-1%20&post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout&state=%20state-1%20&unknown=value",
    )
    .expect("valid logout query should parse");

    assert_eq!(form.id_token_hint.as_deref(), Some("token"));
    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(
        form.post_logout_redirect_uri.as_deref(),
        Some("https://client.example/logout")
    );
    assert_eq!(form.state.as_deref(), Some("state-1"));
}

#[test]
fn logout_query_parser_rejects_duplicate_registered_parameters() {
    let response = match parse_logout_pairs("client_id=client-1&client_id=client-2") {
        Ok(_) => panic!("duplicate client_id must fail before client lookup"),
        Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn logout_query_parser_keeps_empty_registered_values_as_present_parameters() {
    let form = parse_logout_pairs("client_id=&state=")
        .expect("empty registered values should still be parsed as explicit parameters");

    assert_eq!(form.client_id.as_deref(), Some(""));
    assert_eq!(form.state.as_deref(), Some(""));
}

#[actix_web::test]
async fn logout_post_requires_form_urlencoded_content_type() {
    let (req, mut payload) = logout_request_with_payload(
        actix_web::test::TestRequest::default()
            .method(Method::POST)
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(r#"{"client_id":"client-1"}"#),
    )
    .await;

    let response = match parse_logout_request(&req, &mut payload).await {
        Ok(_) => panic!("logout POST must not accept ambiguous JSON input"),
        Err(response) => response,
    };

    let (status, body) = oauth_error_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("logout_token").is_none());
}

#[actix_web::test]
async fn logout_post_merges_query_and_body_but_rejects_duplicate_registered_parameter() {
    let (req, mut payload) = logout_request_with_payload(
        actix_web::test::TestRequest::default()
            .method(Method::POST)
            .uri("/oidc/logout?client_id=client-1")
            .insert_header((
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            ))
            .set_payload("client_id=client-2&state=state-1"),
    )
    .await;

    let response = match parse_logout_request(&req, &mut payload).await {
        Ok(_) => panic!("query and body must share the same duplicate protection"),
        Err(response) => response,
    };

    let (status, body) = oauth_error_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn logout_post_rejects_oversized_form_body_before_client_lookup() {
    let oversized = "state=".to_owned() + &"x".repeat(16 * 1024);
    let (req, mut payload) = logout_request_with_payload(
        actix_web::test::TestRequest::default()
            .method(Method::POST)
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(oversized),
    )
    .await;

    let response = match parse_logout_request(&req, &mut payload).await {
        Ok(_) => panic!("oversized logout requests must be rejected before state mutation"),
        Err(response) => response,
    };

    let (status, body) = oauth_error_json(response).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn logout_post_accepts_form_body_with_content_type_parameters() {
    let (req, mut payload) = logout_request_with_payload(
        actix_web::test::TestRequest::default()
            .method(Method::POST)
            .insert_header((
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            ))
            .set_payload("client_id=client-1&state=state-1"),
    )
    .await;

    let form = parse_logout_request(&req, &mut payload)
        .await
        .expect("form POST with content-type parameters should parse");

    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(form.state.as_deref(), Some("state-1"));
}

#[test]
fn post_logout_redirect_requires_exact_registered_uri_and_preserves_state() {
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!(["https://client.example/logout/callback"]),
        backchannel_logout_uri: None,
        subject_type: "public".to_owned(),
        sector_identifier_host: None,
    };
    let form = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/callback".to_owned()),
        state: Some("state-1".to_owned()),
        ..LogoutRequest::default()
    };

    assert_eq!(
        validate_post_logout_redirect(&form, Some(&client)).unwrap(),
        Some("https://client.example/logout/callback?state=state-1".to_owned())
    );

    let unregistered = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/other".to_owned()),
        ..LogoutRequest::default()
    };
    assert!(validate_post_logout_redirect(&unregistered, Some(&client)).is_err());
}

#[test]
fn post_logout_redirect_appends_state_without_discarding_registered_query() {
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!(["https://client.example/logout/callback?flow=rp"]),
        backchannel_logout_uri: None,
        subject_type: "public".to_owned(),
        sector_identifier_host: None,
    };
    let form = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/callback?flow=rp".to_owned()),
        state: Some("state 1".to_owned()),
        ..LogoutRequest::default()
    };

    assert_eq!(
        validate_post_logout_redirect(&form, Some(&client)).unwrap(),
        Some("https://client.example/logout/callback?flow=rp&state=state+1".to_owned())
    );
}

#[test]
fn post_logout_redirect_rejects_missing_client_and_invalid_registered_uri() {
    let form = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout/callback".to_owned()),
        ..LogoutRequest::default()
    };
    let missing_client = validate_post_logout_redirect(&form, None)
        .expect_err("redirect URI requires a resolved registered client");
    assert_eq!(missing_client.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&missing_client).as_deref(),
        Some("invalid_request")
    );

    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!(["not a uri"]),
        backchannel_logout_uri: None,
        subject_type: "public".to_owned(),
        sector_identifier_host: None,
    };
    let invalid = LogoutRequest {
        post_logout_redirect_uri: Some("not a uri".to_owned()),
        ..LogoutRequest::default()
    };
    let invalid_uri = validate_post_logout_redirect(&invalid, Some(&client))
        .expect_err("registered logout redirects must still be absolute URI values");
    assert_eq!(invalid_uri.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&invalid_uri).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn logout_client_id_must_match_id_token_hint_audience() {
    let hint = IdTokenHintClaims {
        sub: "user-1".to_owned(),
        aud: json!("client-1"),
        sid: Some("sid-1".to_owned()),
    };
    let matching = LogoutRequest {
        client_id: Some("client-1".to_owned()),
        ..LogoutRequest::default()
    };
    let conflicting = LogoutRequest {
        client_id: Some("client-2".to_owned()),
        ..LogoutRequest::default()
    };

    assert_eq!(
        identify_logout_client(&matching, Some(&hint)).unwrap(),
        Some("client-1".to_owned())
    );
    assert!(identify_logout_client(&conflicting, Some(&hint)).is_err());
}

#[test]
fn logout_client_identification_rejects_non_string_hint_audiences() {
    let hint = IdTokenHintClaims {
        sub: "user-1".to_owned(),
        aud: json!({"client_id": "client-1"}),
        sid: None,
    };
    let form = LogoutRequest {
        client_id: Some("client-1".to_owned()),
        ..LogoutRequest::default()
    };

    let response = identify_logout_client(&form, Some(&hint))
        .expect_err("id_token_hint aud must be a string or string array");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn logout_client_identification_requires_client_context_for_redirects() {
    let redirect_without_client = LogoutRequest {
        post_logout_redirect_uri: Some("https://client.example/logout".to_owned()),
        ..LogoutRequest::default()
    };
    let response = identify_logout_client(&redirect_without_client, None)
        .expect_err("post logout redirect must be tied to a registered client");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );

    assert_eq!(
        identify_logout_client(&LogoutRequest::default(), None).unwrap(),
        None
    );
}

#[test]
fn audience_contains_accepts_only_string_audience_members() {
    assert!(audience_contains(&json!("client-1"), "client-1"));
    assert!(audience_contains(
        &json!(["other-client", "client-1"]),
        "client-1"
    ));
    assert!(!audience_contains(&json!("other-client"), "client-1"));
    assert!(!audience_contains(
        &json!(["other-client", 42, {"client_id": "client-1"}]),
        "client-1"
    ));
    assert!(!audience_contains(&json!({"aud": "client-1"}), "client-1"));
}

#[actix_web::test]
async fn logout_client_lookup_without_client_id_does_not_touch_database() {
    let state = test_state_with_keyset(Keyset {
        active_kid: "test-kid".to_owned(),
        active_alg: Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: Vec::new(),
    });

    assert!(lookup_logout_client(&state, None).await.unwrap().is_none());
}

#[actix_web::test]
async fn logout_client_lookup_reports_database_failure_for_registered_context() {
    let state = test_state_with_keyset(Keyset {
        active_kid: "test-kid".to_owned(),
        active_alg: Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: Vec::new(),
    });

    let response = lookup_logout_client(&state, Some("client-1"))
        .await
        .expect_err("client lookups must fail closed when the registry is unavailable");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn logout_client_lookup_rejects_unregistered_client() {
    let Some(fixture) = LiveLogoutFixture::new().await else {
        return;
    };

    let response = lookup_logout_client(&fixture.state, Some("missing-client"))
        .await
        .expect_err("post_logout_redirect validation must bind to a registered active client");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn multi_audience_id_token_hint_requires_explicit_matching_client_id() {
    let hint = IdTokenHintClaims {
        sub: "user-1".to_owned(),
        aud: json!(["client-1", "client-2"]),
        sid: Some("sid-1".to_owned()),
    };
    let missing = LogoutRequest::default();
    let matching = LogoutRequest {
        client_id: Some("client-2".to_owned()),
        ..LogoutRequest::default()
    };

    assert!(identify_logout_client(&missing, Some(&hint)).is_err());
    assert_eq!(
        identify_logout_client(&matching, Some(&hint)).unwrap(),
        Some("client-2".to_owned())
    );
}

#[test]
fn id_token_hint_decoder_rejects_malformed_unsupported_and_unidentified_tokens() {
    let key = generate_key_material(Algorithm::RS256).expect("RSA key should generate");
    let public_jwk =
        public_jwk_from_private_der("logout-kid", Algorithm::RS256, &key.private_pkcs8_der)
            .expect("public JWK should derive");
    let state = test_state_with_keyset(Keyset {
        active_kid: "logout-kid".to_owned(),
        active_alg: Algorithm::RS256,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(key.private_pkcs8_der.clone()),
        verification_keys: vec![crate::domain::VerificationKey {
            kid: "logout-kid".to_owned(),
            public_jwk,
        }],
    });
    let claims = json!({
        "iss": state.settings.issuer,
        "sub": "user-1",
        "aud": "client-1",
        "exp": Utc::now().timestamp() + 300
    });

    assert!(decode_id_token_hint(&state, "not-a-jwt").is_none());

    let mut non_jwt_header = Header::new(Algorithm::RS256);
    non_jwt_header.kid = Some("logout-kid".to_owned());
    non_jwt_header.typ = Some("JOSE".to_owned());
    let non_jwt = jsonwebtoken::encode(
        &non_jwt_header,
        &claims,
        &EncodingKey::from_rsa_der(&key.private_pkcs8_der),
    )
    .expect("test token should sign");
    assert!(decode_id_token_hint(&state, &non_jwt).is_none());

    let unsupported_alg = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"secret"),
    )
    .expect("test token should sign");
    assert!(decode_id_token_hint(&state, &unsupported_alg).is_none());

    let missing_kid = jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_der(&key.private_pkcs8_der),
    )
    .expect("test token should sign");
    assert!(decode_id_token_hint(&state, &missing_kid).is_none());
}

#[test]
fn single_audience_accepts_string_or_single_string_array_only() {
    assert_eq!(
        single_audience(&json!("client-1")).as_deref(),
        Some("client-1")
    );
    assert_eq!(
        single_audience(&json!(["client-1"])).as_deref(),
        Some("client-1")
    );
    assert!(single_audience(&json!(["client-1", "client-2"])).is_none());
    assert!(single_audience(&json!([42])).is_none());
    assert!(single_audience(&json!({"aud": "client-1"})).is_none());
}

#[test]
fn id_token_hint_subject_matches_pairwise_subject_for_registered_client_sector() {
    use crate::config::ConfigSource;

    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.pairwise_subject_secret = Some("0123456789012345678901234567890123456789".to_owned());
    let user_id = Uuid::now_v7();
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
        subject_type: "pairwise".to_owned(),
        sector_identifier_host: None,
    };
    let subject = unique_logout_subject_for_client(&settings, user_id, &client)
        .expect("pairwise subject computation should succeed")
        .expect("pairwise subject should be unique");
    let hint = IdTokenHintClaims {
        sub: subject,
        aud: json!("client-1"),
        sid: Some("sid-1".to_owned()),
    };

    assert!(id_token_hint_matches_current_session(
        &settings,
        Some(&client),
        user_id,
        "sid-1",
        &hint
    ));
    assert!(!id_token_hint_matches_current_session(
        &settings,
        Some(&client),
        user_id,
        "sid-2",
        &hint
    ));
}

#[test]
fn id_token_hint_without_registered_client_never_matches_session() {
    use crate::config::ConfigSource;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let hint = IdTokenHintClaims {
        sub: Uuid::now_v7().to_string(),
        aud: json!("client-1"),
        sid: None,
    };

    assert!(!id_token_hint_matches_current_session(
        &settings,
        None,
        Uuid::now_v7(),
        "sid-1",
        &hint
    ));
}

#[test]
fn id_token_hint_subject_policy_error_never_matches_session() {
    use crate::config::ConfigSource;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let user_id = Uuid::now_v7();
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!(["https://client.example/callback"]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
        subject_type: "pairwise".to_owned(),
        sector_identifier_host: Some("client.example".to_owned()),
    };
    let hint = IdTokenHintClaims {
        sub: user_id.to_string(),
        aud: json!("client-1"),
        sid: Some("sid-1".to_owned()),
    };

    assert!(
        unique_logout_subject_for_client(&settings, user_id, &client).is_err(),
        "pairwise logout subject must fail closed when the server secret is missing"
    );
    assert!(!id_token_hint_matches_current_session(
        &settings,
        Some(&client),
        user_id,
        "sid-1",
        &hint
    ));
}

#[test]
fn backchannel_logout_subject_is_omitted_when_pairwise_sector_is_ambiguous() {
    use crate::config::ConfigSource;

    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.pairwise_subject_secret = Some("0123456789012345678901234567890123456789".to_owned());
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!([
            "https://one.example/callback",
            "https://two.example/callback"
        ]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
        subject_type: "pairwise".to_owned(),
        sector_identifier_host: None,
    };

    assert!(
        unique_logout_subject_for_client(&settings, Uuid::now_v7(), &client)
            .expect("pairwise subjects should compute")
            .is_none()
    );
}

#[test]
fn backchannel_logout_subject_uses_public_subject_when_configured() {
    use crate::config::ConfigSource;

    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let user_id = Uuid::now_v7();
    let client = BackchannelLogoutClient {
        client_id: "client-1".to_owned(),
        redirect_uris: json!([]),
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: Some("https://client.example/backchannel-logout".to_owned()),
        subject_type: "public".to_owned(),
        sector_identifier_host: None,
    };

    assert_eq!(
        unique_logout_subject_for_client(&settings, user_id, &client)
            .expect("public subject should compute")
            .as_deref(),
        Some(user_id.to_string().as_str())
    );
}

async fn one_shot_logout_server(status: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr: SocketAddr = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test request should arrive");
        let mut buffer = vec![0_u8; 4096];
        let read = stream.read(&mut buffer).await.expect("request should read");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let response =
            format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response should write");
        request
    });
    (format!("http://{addr}"), handle)
}

#[actix_web::test]
async fn post_backchannel_logout_sends_form_encoded_logout_token() {
    let (uri, request) = one_shot_logout_server("204 No Content").await;

    post_backchannel_logout(&uri, "logout.token.value")
        .await
        .expect("2xx backchannel endpoint should be accepted");
    let request = request.await.expect("test server should finish");

    assert!(request.starts_with("POST / HTTP/1.1"));
    assert!(request.contains("content-type: application/x-www-form-urlencoded"));
    assert!(request.ends_with("logout_token=logout.token.value"));
}

#[actix_web::test]
async fn post_backchannel_logout_rejects_non_success_response() {
    let (uri, request) = one_shot_logout_server("500 Internal Server Error").await;

    let error = post_backchannel_logout(&uri, "logout-token")
        .await
        .expect_err("non-2xx backchannel endpoint must be treated as delivery failure");
    request.await.expect("test server should finish");

    assert!(error.to_string().contains("500 Internal Server Error"));
}

#[actix_web::test]
async fn oidc_logout_rejects_invalid_id_token_hint_before_client_lookup() {
    let state = Data::new(test_state_with_keyset(Keyset {
        active_kid: "test-kid".to_owned(),
        active_alg: Algorithm::EdDSA,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: Vec::new(),
    }));
    let (req, payload) = logout_request_with_payload(
        actix_web::test::TestRequest::default().uri("/oidc/logout?id_token_hint=not-a-jwt"),
    )
    .await;

    let response = oidc_logout(state, req, payload).await;
    let cookie_headers = response.headers().contains_key(header::SET_COOKIE);
    let (status, body) = oauth_error_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "id_token_hint is invalid.");
    assert!(!cookie_headers);
}

#[actix_web::test]
async fn oidc_logout_reports_session_lookup_failure_before_clearing_cookies() {
    let Some(fixture) = LiveLogoutFixture::new().await else {
        return;
    };
    let sid = format!("logout-broken-{}", Uuid::now_v7().simple());
    let state = Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_logout_lookup_invalid:nazo_logout_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let payload = SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        pending_mfa: false,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        format!("oauth:session:{sid}"),
        serde_json::to_string(&payload).expect("session should serialize"),
        state.settings.session_ttl_seconds,
    )
    .await
    .expect("session should store");
    let (req, payload) = fixture.logout_request("/oidc/logout", Some(&sid)).await;

    let response = oidc_logout(state, req, payload).await;
    let cookie_headers = response.headers().contains_key(header::SET_COOKIE);
    let (status, body) = oauth_error_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "logout session lookup failed.");
    assert!(!cookie_headers);
}

#[actix_web::test]
async fn oidc_logout_clears_session_and_sends_backchannel_logout_token_with_registered_client() {
    let Some(fixture) = LiveLogoutFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let sid = format!("logout-{suffix}");
    let oidc_sid = format!("op-session-{suffix}");
    let redirect_uri = "https://client.example/callback";
    let post_logout_redirect_uri = "https://client.example/logout/callback";
    let (backchannel_uri, request_handle) = one_shot_logout_server("204 No Content").await;
    let user = fixture.create_user(&suffix).await;
    fixture.store_session(&user, &sid, &oidc_sid).await;
    let client_public_id = format!("logout-client-{suffix}");
    let client_id = fixture
        .insert_client(
            &client_public_id,
            redirect_uri,
            post_logout_redirect_uri,
            Some(&backchannel_uri),
        )
        .await;
    fixture.grant_client(&user, client_id).await;
    let id_token_hint = fixture
        .issue_id_token_hint(user.id, &client_public_id, &oidc_sid)
        .await;
    let uri = format!(
        "/oidc/logout?id_token_hint={}&post_logout_redirect_uri={}&state=logout-state",
        urlencoding::encode(&id_token_hint),
        urlencoding::encode(post_logout_redirect_uri),
    );
    let (req, payload) = fixture.logout_request(&uri, Some(&sid)).await;

    let response = oidc_logout(fixture.state.clone(), req, payload).await;
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let session_cookies = set_cookie_values(&response, &fixture.state.settings.session_cookie_name);
    let csrf_cookies = set_cookie_values(&response, &fixture.state.settings.csrf_cookie_name);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should read");

    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("https://client.example/logout/callback?state=logout-state")
    );
    assert!(body.is_empty());
    assert_eq!(session_cookies.as_slice(), [""]);
    assert_eq!(csrf_cookies.as_slice(), [""]);
    assert!(
        !fixture.session_exists(&sid).await,
        "logout must delete the local OP session before returning"
    );

    let request = request_handle
        .await
        .expect("backchannel request should arrive");
    let logout_token = form_body_value(&request, "logout_token")
        .expect("backchannel request should include logout_token");
    let header =
        jsonwebtoken::decode_header(&logout_token).expect("logout token header should decode");
    assert_eq!(header.typ.as_deref(), Some("logout+jwt"));
    assert_eq!(header.kid.as_deref(), Some("logout-kid"));

    let keyset = fixture.state.keyset.snapshot();
    let verification_key = keyset
        .verification_key("logout-kid")
        .expect("verification key should load");
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, Algorithm::EdDSA)
        .expect("logout token decoding key should derive");
    let mut validation = jsonwebtoken::Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    validation.set_issuer(&[fixture.state.settings.issuer.as_str()]);
    let claims = jsonwebtoken::decode::<Value>(&logout_token, &decoding_key, &validation)
        .expect("logout token should verify")
        .claims;

    assert_eq!(claims["aud"], client_public_id);
    assert_eq!(claims["sid"], oidc_sid);
    assert_eq!(claims["sub"], user.id.to_string());
    assert_eq!(
        claims["events"],
        json!({"http://schemas.openid.net/event/backchannel-logout": {}})
    );
    assert!(claims["jti"].as_str().is_some());
}

#[actix_web::test]
async fn oidc_logout_skips_backchannel_client_when_subject_policy_is_invalid() {
    let Some(fixture) = LiveLogoutFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let sid = format!("logout-{suffix}");
    let oidc_sid = format!("op-session-{suffix}");
    let redirect_uri = "https://client.example/callback";
    let post_logout_redirect_uri = "https://client.example/logout/callback";
    let user = fixture.create_user(&suffix).await;
    fixture.store_session(&user, &sid, &oidc_sid).await;
    let client_public_id = format!("logout-client-{suffix}");
    let client_id = fixture
        .insert_client_with_subject(
            &client_public_id,
            redirect_uri,
            post_logout_redirect_uri,
            Some("https://client.example/backchannel-logout"),
            "pairwise",
            Some("client.example"),
        )
        .await;
    fixture.grant_client(&user, client_id).await;
    let uri = format!(
        "/oidc/logout?client_id={}&post_logout_redirect_uri={}&state=logout-state",
        urlencoding::encode(&client_public_id),
        urlencoding::encode(post_logout_redirect_uri),
    );
    let (req, payload) = fixture.logout_request(&uri, Some(&sid)).await;

    let response = oidc_logout(fixture.state.clone(), req, payload).await;
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let session_cookies = set_cookie_values(&response, &fixture.state.settings.session_cookie_name);
    let csrf_cookies = set_cookie_values(&response, &fixture.state.settings.csrf_cookie_name);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should read");

    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("https://client.example/logout/callback?state=logout-state")
    );
    assert!(body.is_empty());
    assert_eq!(session_cookies.as_slice(), [""]);
    assert_eq!(csrf_cookies.as_slice(), [""]);
    assert!(
        !fixture.session_exists(&sid).await,
        "invalid backchannel subject policy must not prevent local logout"
    );
}
