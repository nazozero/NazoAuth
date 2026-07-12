use super::*;
use std::{
    collections::HashSet,
    future::Future,
    io::Write,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};

use crate::settings::DpopNoncePolicy;
use crate::support::{generate_key_material, public_jwk_from_private_der};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::sql_query;
use diesel::sql_types::{Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder as ValkeyBuilder, Config as ValkeyConfig};
use nazo_auth::ConfirmationClaims;
use nazo_http_signatures::{
    OriginalRequest, RequestInput, RequestPolicy, ResponseInput, SignatureFields,
    VerificationPolicy, parse_response_for_verification, prepare_request,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct FapiLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for FapiLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fapi_test_state() -> AppState {
    fapi_test_state_with_settings(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn fapi_test_state_with_settings(settings: Settings) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_fapi_test_invalid:nazo_fapi_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn fapi_signing_state_with_invalid_db() -> Data<AppState> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_fapi_test_invalid:nazo_fapi_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

fn fapi_external_signer_failure_state(stderr_secret: &str) -> Data<AppState> {
    let mut state = fapi_test_state();
    state.keyset = crate::test_support::external_failure_key_manager(stderr_secret);
    Data::new(state)
}

fn fapi_enabled_signing_state_with_invalid_db() -> Data<AppState> {
    let state = fapi_signing_state_with_invalid_db();
    let mut settings = (*state.settings).clone();
    settings.enable_fapi_http_signatures = true;
    Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    })
}

async fn fapi_enabled_signing_state_with_live_valkey_nonce() -> Option<Data<AppState>> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let valkey = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).ok()?)
        .build()
        .ok()?;
    valkey.init().await.ok()?;
    let state = fapi_enabled_signing_state_with_invalid_db();
    let mut settings = (*state.settings).clone();
    settings.dpop_nonce_policy = DpopNoncePolicy::Required;
    Some(Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey,
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    }))
}

fn live_fapi_signing_state() -> Option<Data<AppState>> {
    live_fapi_signing_state_from_database_url(std::env::var("DATABASE_URL").ok()?)
}

fn live_fapi_signing_state_from_database_url(database_url: String) -> Option<Data<AppState>> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }))
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn exec_sql(state: &Data<AppState>, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_schema(state: &Data<AppState>, schema: &str, tables: &[&str]) {
    exec_sql(
        state,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_sql(
            state,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn rename_column(state: &Data<AppState>, schema: &str, table: &str, from: &str, to: &str) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &Data<AppState>, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

fn fapi_trusted_proxy_state() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.client_ip_header_mode = ClientIpHeaderMode::None;
    settings.trusted_proxy_cidrs =
        parse_trusted_proxy_cidrs(Some("192.0.2.0/24".to_owned())).unwrap();
    fapi_test_state_with_settings(settings)
}

async fn signed_fapi_access_token(
    state: &Data<AppState>,
    tenant_id: Uuid,
    audiences: &[String],
    ttl: i64,
) -> IssuedAccessToken {
    make_jwt(
        state,
        AccessTokenJwtInput {
            tenant_id,
            subject: "fapi-subject",
            user_id: None,
            subject_type: "client",
            client_id: "fapi-client",
            audiences,
            scopes: &["openid".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
    )
    .await
    .expect("FAPI resource access token should sign")
}

async fn signed_fapi_claims(state: &Data<AppState>, claims: Claims) -> String {
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some(keyset.active_kid.clone());
    state
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::AccessToken, &header, &claims)
        .await
        .expect("FAPI resource claims should sign")
}

async fn insert_fapi_client_and_revocation(
    state: &Data<AppState>,
    client_id: &str,
    access_token_jti: &str,
) {
    #[derive(diesel::QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = SqlUuid)]
        id: Uuid,
    }

    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        DELETE FROM access_token_revocations
        USING oauth_clients
        WHERE access_token_revocations.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("FAPI resource revocation cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("FAPI resource client cleanup should succeed");
    let row = sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
            tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, is_active,
            post_logout_redirect_uris, backchannel_logout_session_required
        )
        VALUES (
            $1, $2, $3, $4, 'FAPI Resource Test Client', 'confidential',
            NULL, '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
            '["resource://default"]'::jsonb, '["client_credentials"]'::jsonb,
            'client_secret_post', false, false, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb, false, false, false, false, true,
            '[]'::jsonb, true
        )
        RETURNING id
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(client_id)
    .get_result::<IdRow>(&mut conn)
    .await
    .expect("FAPI resource client insert should succeed");
    sql_query(
        r#"
        INSERT INTO access_token_revocations (
            tenant_id, client_id, access_token_jti_blake3, revoked_at, expires_at
        )
        VALUES ($1, $2, $3, now(), $4)
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(row.id)
    .bind::<Text, _>(blake3_hex(access_token_jti))
    .bind::<Timestamptz, _>(Utc::now() + Duration::minutes(5))
    .execute(&mut conn)
    .await
    .expect("FAPI resource revocation insert should succeed");
}

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "public".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 300,
        cnf,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

fn fapi_http_signature_client(public_jwk: Value) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "HTTP Signature Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!([]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["client_credentials"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        is_active: true,
        jwks: Some(json!({"keys": [public_jwk]})),
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: false,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

async fn signed_resource_request_fixture(
    body: &[u8],
) -> (
    nazo_key_management::KeyManager,
    ClientRow,
    HttpRequest,
    SignatureFields,
) {
    signed_resource_request_for_authorization(body, "Bearer opaque-access-token").await
}

fn client_http_signature(private_key: &[u8], signing_input: &[u8]) -> Vec<u8> {
    let encoded = jsonwebtoken::crypto::sign(
        signing_input,
        &jsonwebtoken::EncodingKey::from_ed_der(private_key),
        jsonwebtoken::Algorithm::EdDSA,
    )
    .expect("client request should sign");
    URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("signature should decode")
}

async fn signed_resource_request_for_authorization(
    body: &[u8],
    authorization: &str,
) -> (
    nazo_key_management::KeyManager,
    ClientRow,
    HttpRequest,
    SignatureFields,
) {
    let material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("client key generation");
    let kid = "resource-client-ed25519";
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .expect("client public JWK");
    let client = fapi_http_signature_client(public_jwk.clone());
    let digest = (!body.is_empty()).then(|| nazo_http_signatures::content_digest(body));
    let mut headers = vec![("authorization", authorization)];
    if let Some(digest) = digest.as_deref() {
        headers.push(("content-digest", digest));
    }
    let prepared = prepare_request(
        RequestInput {
            method: if body.is_empty() { "GET" } else { "POST" },
            target_uri: "https://issuer.example/fapi/resource",
            headers: &headers,
            body,
        },
        RequestPolicy {
            created: Utc::now().timestamp(),
            keyid: kid,
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .expect("request should prepare");
    let detached = client_http_signature(&material.private_pkcs8_der, prepared.signature_base());
    let fields = prepared.finish(&detached);
    let mut request = if body.is_empty() {
        actix_web::test::TestRequest::get()
    } else {
        actix_web::test::TestRequest::post()
    };
    request = request
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, authorization))
        .insert_header(("signature-input", fields.signature_input.clone()))
        .insert_header(("signature", fields.signature.clone()));
    if let Some(digest) = digest {
        request = request.insert_header(("content-digest", digest));
    }
    let keyset = crate::test_support::test_key_manager();
    (keyset, client, request.to_http_request(), fields)
}

async fn signed_resource_request_with_received_digest(
    body: &[u8],
    authorization: &str,
    received_digest: &str,
) -> (ClientRow, HttpRequest, SignatureFields) {
    let material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("client key generation");
    let kid = "resource-client-varied-digest";
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .unwrap();
    let client = fapi_http_signature_client(public_jwk.clone());
    let canonical = nazo_http_signatures::content_digest(body);
    let headers = [("authorization", authorization)];
    let prepared = prepare_request(
        RequestInput {
            method: "POST",
            target_uri: "https://issuer.example/fapi/resource",
            headers: &headers,
            body,
        },
        RequestPolicy {
            created: Utc::now().timestamp(),
            keyid: kid,
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap();
    let canonical_line = format!("\"content-digest\": {canonical}");
    let received_line = format!(
        "\"content-digest\": {}",
        received_digest.trim_matches([' ', '\t'])
    );
    let modified_base = String::from_utf8(prepared.signature_base().to_vec())
        .unwrap()
        .replace(&canonical_line, &received_line);
    let detached = client_http_signature(&material.private_pkcs8_der, modified_base.as_bytes());
    let fields = prepared.finish(&detached);
    let req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, authorization))
        .insert_header(("content-digest", received_digest))
        .insert_header(("signature-input", fields.signature_input.clone()))
        .insert_header(("signature", fields.signature.clone()))
        .to_http_request();
    (client, req, fields)
}

#[derive(Clone, Copy)]
enum ExtraHeaderMode {
    Exact,
    Tampered,
    Duplicate,
    NonUtf8,
}

async fn enabled_request_with_signed_extras(
    state: &Data<AppState>,
    mode: ExtraHeaderMode,
) -> (HttpRequest, ClientRow, SignatureFields, String) {
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.client_id = "client-1".to_owned();
    let token = signed_fapi_claims(state, claims).await;
    let authorization = format!("Bearer {token}");
    let material = generate_key_material(jsonwebtoken::Algorithm::EdDSA).unwrap();
    let kid = "resource-client-extra-headers";
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::EdDSA,
        &material.private_pkcs8_der,
    )
    .unwrap();
    let client = fapi_http_signature_client(public_jwk.clone());
    let signed_headers = [
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-123"),
    ];
    let prepared = prepare_request(
        RequestInput {
            method: "GET",
            target_uri: "https://issuer.example/fapi/resource",
            headers: &signed_headers,
            body: b"",
        },
        RequestPolicy {
            created: Utc::now().timestamp(),
            keyid: kid,
            algorithm: "ed25519",
            covered_headers: &["content-type", "idempotency-key"],
        },
    )
    .unwrap();
    let detached = client_http_signature(&material.private_pkcs8_der, prepared.signature_base());
    let fields = prepared.finish(&detached);
    let mut request = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, authorization.as_str()))
        .insert_header(("content-type", "application/json"))
        .insert_header(("signature-input", fields.signature_input.clone()))
        .insert_header(("signature", fields.signature.clone()));
    request = match mode {
        ExtraHeaderMode::Exact => request.insert_header(("idempotency-key", "operation-123")),
        ExtraHeaderMode::Tampered => request.insert_header(("idempotency-key", "operation-999")),
        ExtraHeaderMode::Duplicate => request
            .append_header(("idempotency-key", "operation-123"))
            .append_header(("idempotency-key", "operation-123")),
        ExtraHeaderMode::NonUtf8 => request.insert_header((
            "idempotency-key",
            HeaderValue::from_bytes(b"operation-\xff").unwrap(),
        )),
    };
    (request.to_http_request(), client, fields, authorization)
}

fn copied_signature_fields(fields: &SignatureFields) -> SignatureFields {
    SignatureFields {
        signature_input: fields.signature_input.clone(),
        signature: fields.signature.clone(),
    }
}

fn replace_created(signature_input: &str, created: i64) -> String {
    let marker = ";created=";
    let start = signature_input.find(marker).unwrap() + marker.len();
    let end = signature_input[start..]
        .find(';')
        .map(|offset| start + offset)
        .unwrap_or(signature_input.len());
    format!(
        "{}{}{}",
        &signature_input[..start],
        created,
        &signature_input[end..]
    )
}

async fn assert_signed_error_covers_received_signature_fields(
    state: &Data<AppState>,
    response: HttpResponse,
    method: &str,
    fields: &SignatureFields,
) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let digest = response
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let interaction_id = response
        .headers()
        .get("x-fapi-interaction-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let response_fields = SignatureFields {
        signature_input: response
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        signature: response
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    assert!(
        response_fields
            .signature_input
            .contains("\"signature-input\";req")
    );
    assert!(
        response_fields
            .signature_input
            .contains("\"signature\";req")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let mut response_headers = vec![
        ("content-digest", digest.as_str()),
        ("content-type", content_type.as_str()),
    ];
    if let Some(interaction_id) = interaction_id.as_deref() {
        response_headers.push(("x-fapi-interaction-id", interaction_id));
    }
    let parsed = parse_response_for_verification(
        ResponseInput {
            status: 401,
            headers: &response_headers,
            body: &body,
        },
        OriginalRequest {
            input: RequestInput {
                method,
                target_uri: "https://issuer.example/fapi/resource",
                headers: &[],
                body: b"",
            },
            signature_fields: Some(fields),
        },
        response_fields,
        VerificationPolicy {
            now: Utc::now().timestamp(),
            max_age_seconds: 60,
            future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
        },
    )
    .expect("client should reconstruct the signed error from the received request fields");
    let server = state.keyset.snapshot();
    let verifier = fapi_http_signature_client(server.verification_keys[0].public_jwk.clone());
    verify_client_http_message(
        &verifier,
        DEFAULT_TENANT_ID,
        "client-1",
        parsed.keyid(),
        parsed.algorithm(),
        parsed.signature_base(),
        parsed.signature(),
    )
    .unwrap();
}

#[derive(Clone, Copy)]
enum FakeReplayMode {
    Track,
    DependencyFailure,
}

struct FakeFapiResourceStore {
    revoked: bool,
    revocation_error: bool,
    client: Option<ClientRow>,
    client_error: bool,
    replay_mode: FakeReplayMode,
    seen_replays: Mutex<HashSet<[u8; 32]>>,
    revocation_calls: AtomicUsize,
    client_calls: AtomicUsize,
    replay_calls: AtomicUsize,
    protected_work_calls: AtomicUsize,
}

impl FakeFapiResourceStore {
    fn accepting(client: ClientRow) -> Arc<Self> {
        Arc::new(Self {
            revoked: false,
            revocation_error: false,
            client: Some(client),
            client_error: false,
            replay_mode: FakeReplayMode::Track,
            seen_replays: Mutex::new(HashSet::new()),
            revocation_calls: AtomicUsize::new(0),
            client_calls: AtomicUsize::new(0),
            replay_calls: AtomicUsize::new(0),
            protected_work_calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> (usize, usize, usize, usize) {
        (
            AtomicUsize::load(&self.revocation_calls, Ordering::SeqCst),
            AtomicUsize::load(&self.client_calls, Ordering::SeqCst),
            AtomicUsize::load(&self.replay_calls, Ordering::SeqCst),
            AtomicUsize::load(&self.protected_work_calls, Ordering::SeqCst),
        )
    }
}

impl FapiResourceStore for FakeFapiResourceStore {
    fn revoked<'a>(
        &'a self,
        _tenant_id: Uuid,
        _jti: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            self.revocation_calls.fetch_add(1, Ordering::SeqCst);
            if self.revocation_error {
                anyhow::bail!("injected revocation failure");
            }
            Ok(self.revoked)
        })
    }

    fn client<'a>(
        &'a self,
        _tenant_id: Uuid,
        _client_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<ClientRow>>> + Send + 'a>> {
        Box::pin(async move {
            self.client_calls.fetch_add(1, Ordering::SeqCst);
            if self.client_error {
                anyhow::bail!("injected client failure");
            }
            Ok(self.client.clone())
        })
    }

    fn consume_replay<'a>(
        &'a self,
        fingerprint: &'a [u8; 32],
        _max_age_seconds: i64,
    ) -> Pin<Box<dyn Future<Output = ReplayConsumption> + Send + 'a>> {
        Box::pin(async move {
            self.replay_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.replay_mode, FakeReplayMode::DependencyFailure) {
                return ReplayConsumption::DependencyFailure;
            }
            if self.seen_replays.lock().unwrap().insert(*fingerprint) {
                ReplayConsumption::Accepted
            } else {
                ReplayConsumption::Replay
            }
        })
    }

    fn protected_work_reached(&self) {
        self.protected_work_calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn with_fapi_store(req: HttpRequest, store: Arc<dyn FapiResourceStore>) -> HttpRequest {
    use actix_web::HttpMessage;
    req.extensions_mut()
        .insert(FapiResourceStoreOverride(store));
    req
}

async fn enabled_endpoint_request(
    state: &Data<AppState>,
    store_client_id: &str,
    ttl: i64,
    body: &[u8],
) -> (HttpRequest, Bytes, ClientRow) {
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.client_id = store_client_id.to_owned();
    claims.exp = Utc::now().timestamp() + ttl;
    let token = signed_fapi_claims(state, claims).await;
    let authorization = format!("Bearer {token}");
    let (_keyset, mut client, req, _fields) =
        signed_resource_request_for_authorization(body, &authorization).await;
    client.client_id = store_client_id.to_owned();
    (req, Bytes::copy_from_slice(body), client)
}

fn captured_fapi_request(req: &HttpRequest, body: &Bytes) -> FapiOriginalRequest {
    FapiOriginalRequest::capture("https://issuer.example", req, body)
}

fn signed_endpoint_dpop_proof(
    signing_key: &SigningKey,
    access_token: &str,
) -> (String, String, Value) {
    let public_x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": public_x});
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{public_x}"}}"#);
    let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    let header = json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk});
    let claims = json!({
        "htm": "GET",
        "htu": "https://issuer.example/fapi/resource",
        "iat": Utc::now().timestamp(),
        "jti": format!("fapi-nonce-{}", Uuid::now_v7()),
        "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
    });
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    (
        format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        jkt,
        jwk,
    )
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[actix_web::test]
async fn fapi_resource_rejects_missing_or_conflicting_access_token_transport() {
    let state = Data::new(fapi_test_state());
    let missing_req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .to_http_request();

    let missing = fapi_resource(state.clone(), missing_req, Bytes::new()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&missing).as_deref(), Some("invalid_token"));
    assert!(!missing.headers().contains_key("signature-input"));
    assert!(!missing.headers().contains_key("signature"));

    let duplicate_req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let duplicate = fapi_resource(
        state,
        duplicate_req,
        Bytes::from_static(b"access_token=body-token"),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&duplicate).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn fapi_resource_http_signature_enabled_rejects_form_body_token_transport() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=body-token"), true);

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));

    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let duplicate = resource_access_token(
        &req,
        &Bytes::from_static(b"access_token=one&access_token=two"),
        true,
    );
    assert!(matches!(duplicate, ResourceAccessToken::InvalidRequest));
}

#[actix_web::test]
async fn fapi_resource_http_signature_valid_request_uses_exact_client_jwk() {
    let (_keyset, client, req, _fields) = signed_resource_request_fixture(b"").await;
    let original = captured_fapi_request(&req, &Bytes::new());

    let verified = verify_fapi_resource_http_signature(
        &client,
        &original,
        FapiResourceSignaturePolicy {
            tenant_id: DEFAULT_TENANT_ID,
            client_id: "client-1",
            max_age_seconds: 60,
        },
    )
    .expect("valid resource signature should verify");

    assert_eq!(verified.keyid(), "resource-client-ed25519");
    assert_eq!(verified.algorithm(), "ed25519");

    let body = Bytes::from_static(br#"{"amount":10}"#);
    let (_keyset, client, req, _fields) = signed_resource_request_fixture(&body).await;
    let original = captured_fapi_request(&req, &body);
    assert!(
        verify_fapi_resource_http_signature(
            &client,
            &original,
            FapiResourceSignaturePolicy {
                tenant_id: DEFAULT_TENANT_ID,
                client_id: "client-1",
                max_age_seconds: 60,
            },
        )
        .is_ok()
    );
}

#[actix_web::test]
async fn fapi_resource_http_signature_rejects_duplicate_signature_headers() {
    let (_keyset, client, _req, fields) = signed_resource_request_fixture(b"").await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer opaque-access-token"))
        .insert_header(("signature-input", fields.signature_input))
        .append_header(("signature", fields.signature))
        .append_header(("signature", "sig1=:ZHVwbGljYXRlOg==:"))
        .to_http_request();
    let original = captured_fapi_request(&req, &Bytes::new());

    assert!(
        verify_fapi_resource_http_signature(
            &client,
            &original,
            FapiResourceSignaturePolicy {
                tenant_id: DEFAULT_TENANT_ID,
                client_id: "client-1",
                max_age_seconds: 60,
            },
        )
        .is_err()
    );
}

#[actix_web::test]
async fn fapi_resource_http_signature_response_is_request_linked_and_verifiable() {
    let (_client_keyset, _client, req, request_fields) = signed_resource_request_fixture(b"").await;
    let state = fapi_signing_state_with_invalid_db();
    let mut response = json_response_no_store(json!({"sub": "protected-subject"}));
    response.headers_mut().insert(
        "x-fapi-interaction-id".parse().unwrap(),
        "interaction-123".parse().unwrap(),
    );
    let original = captured_fapi_request(&req, &Bytes::new());

    let signed = sign_fapi_resource_response(&state, &original, response).await;

    assert_eq!(signed.status(), StatusCode::OK);
    let response_digest = signed
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let response_fields = SignatureFields {
        signature_input: signed
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        signature: signed
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    let response_signature_input = response_fields.signature_input.clone();
    let response_signature = response_fields.signature.clone();
    assert!(response_fields.signature_input.contains("\"content-type\""));
    assert!(
        response_fields
            .signature_input
            .contains("\"x-fapi-interaction-id\"")
    );
    let content_type = signed
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let interaction_id = signed
        .headers()
        .get("x-fapi-interaction-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body = actix_web::body::to_bytes(signed.into_body()).await.unwrap();
    let response_headers = [
        ("content-digest", response_digest.as_str()),
        ("content-type", content_type.as_str()),
        ("x-fapi-interaction-id", interaction_id.as_str()),
    ];
    let request_headers = [("authorization", "Bearer opaque-access-token")];
    let parsed = parse_response_for_verification(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: &body,
        },
        OriginalRequest {
            input: RequestInput {
                method: "GET",
                target_uri: "https://issuer.example/fapi/resource",
                headers: &request_headers,
                body: b"",
            },
            signature_fields: Some(&request_fields),
        },
        response_fields,
        VerificationPolicy {
            now: Utc::now().timestamp(),
            max_age_seconds: 60,
            future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
        },
    )
    .expect("response signature should be linked to the original request");
    let server = state.keyset.snapshot();
    let verifier = fapi_http_signature_client(server.verification_keys[0].public_jwk.clone());
    verify_client_http_message(
        &verifier,
        DEFAULT_TENANT_ID,
        "client-1",
        parsed.keyid(),
        parsed.algorithm(),
        parsed.signature_base(),
        parsed.signature(),
    )
    .expect("server response signature should verify");

    for (tampered_content_type, tampered_interaction_id) in [
        ("text/plain", interaction_id.as_str()),
        (content_type.as_str(), "interaction-tampered"),
    ] {
        let tampered_headers = [
            ("content-digest", response_digest.as_str()),
            ("content-type", tampered_content_type),
            ("x-fapi-interaction-id", tampered_interaction_id),
        ];
        let tampered = parse_response_for_verification(
            ResponseInput {
                status: 200,
                headers: &tampered_headers,
                body: &body,
            },
            OriginalRequest {
                input: RequestInput {
                    method: "GET",
                    target_uri: "https://issuer.example/fapi/resource",
                    headers: &request_headers,
                    body: b"",
                },
                signature_fields: Some(&request_fields),
            },
            SignatureFields {
                signature_input: response_signature_input.clone(),
                signature: response_signature.clone(),
            },
            VerificationPolicy {
                now: Utc::now().timestamp(),
                max_age_seconds: 60,
                future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
            },
        )
        .expect("tampering must reconstruct a base for cryptographic rejection");
        assert!(
            verify_client_http_message(
                &verifier,
                DEFAULT_TENANT_ID,
                "client-1",
                tampered.keyid(),
                tampered.algorithm(),
                tampered.signature_base(),
                tampered.signature(),
            )
            .is_err()
        );
    }
}

#[actix_web::test]
async fn fapi_resource_http_signature_signer_failure_returns_empty_503() {
    let mut state = fapi_test_state();
    state.keyset = crate::test_support::failing_key_manager();
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer opaque-access-token"))
        .to_http_request();
    let protected = json_response_no_store(json!({"secret": "must-not-leak"}));
    let original = captured_fapi_request(&req, &Bytes::new());

    let response = sign_fapi_resource_response(&state, &original, protected).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap()
            .is_empty()
    );
}

#[actix_web::test]
async fn fapi_resource_http_signature_logs_do_not_expose_request_or_response_secrets() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = FapiLogWriter(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut state = fapi_test_state();
    state.keyset = crate::test_support::failing_key_manager();
    let state = Data::new(state);
    let request_body = Bytes::from_static(b"request-body-secret");
    let digest = nazo_http_signatures::content_digest(&request_body);
    let request_signature_input = "sig1=(\"@method\");created=1";
    let request_signature = "sig1=:cmF3LXNpZ25hdHVyZS1zZWNyZXQ=:";
    let req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer authorization-secret"))
        .insert_header(("content-digest", digest))
        .insert_header(("signature-input", request_signature_input))
        .insert_header(("signature", request_signature))
        .to_http_request();
    let protected = json_response_no_store(json!({"value": "protected-body-secret"}));
    let original = captured_fapi_request(&req, &request_body);

    let response = sign_fapi_resource_response(&state, &original, protected).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(_guard);
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    for secret in [
        "authorization-secret",
        "request-body-secret",
        "raw-signature-secret",
        "protected-body-secret",
    ] {
        assert!(!logs.contains(secret), "logs exposed {secret}");
    }
}

#[actix_web::test]
async fn fapi_response_signing_log_redacts_external_signer_stderr() {
    const STDERR_SECRET: &str = "external-signer-stderr-secret";
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = FapiLogWriter(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let state = fapi_external_signer_failure_state(STDERR_SECRET);
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer opaque-access-token"))
        .to_http_request();
    let original = captured_fapi_request(&req, &Bytes::new());

    let response = sign_fapi_resource_response(
        &state,
        &original,
        json_response_no_store(json!({"value": "protected"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(_guard);
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("category=\"signer_failure\""));
    assert!(!logs.contains(STDERR_SECRET));
}

#[actix_web::test]
async fn fapi_resource_http_signature_signs_success_errors_and_nonce_challenges() {
    let (_client_keyset, _client, req, _request_fields) =
        signed_resource_request_fixture(b"").await;
    let state = fapi_signing_state_with_invalid_db();
    let original = captured_fapi_request(&req, &Bytes::new());
    let responses = [
        HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(json!({"sub": "subject"})),
        HttpResponse::Unauthorized()
            .insert_header((header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""))
            .json(json!({"error": "invalid_token"})),
        HttpResponse::Unauthorized()
            .insert_header((header::WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\""))
            .insert_header(("dpop-nonce", "bounded-nonce"))
            .json(json!({"error": "use_dpop_nonce"})),
        HttpResponse::ServiceUnavailable()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(json!({"error": "server_error"})),
    ];

    for response in responses {
        let status = response.status();
        let signed = sign_fapi_resource_response(&state, &original, response).await;
        assert_eq!(signed.status(), status);
        assert!(signed.headers().contains_key("content-digest"));
        assert!(signed.headers().contains_key("signature-input"));
        assert!(signed.headers().contains_key("signature"));
        if signed.headers().contains_key("dpop-nonce") {
            assert_eq!(
                signed
                    .headers()
                    .get("dpop-nonce")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "bounded-nonce"
            );
            assert!(signed.headers().contains_key(header::WWW_AUTHENTICATE));
        }
    }
}

#[actix_web::test]
async fn fapi_resource_http_signature_preserves_multi_value_response_headers() {
    let (_client_keyset, _client, req, _request_fields) =
        signed_resource_request_fixture(b"").await;
    let state = fapi_signing_state_with_invalid_db();
    let original = captured_fapi_request(&req, &Bytes::new());
    let response = HttpResponse::Unauthorized()
        .append_header((header::WWW_AUTHENTICATE, "Bearer realm=\"one\""))
        .append_header((header::WWW_AUTHENTICATE, "DPoP error=\"use_dpop_nonce\""))
        .append_header((header::SET_COOKIE, "a=1; Path=/; Secure"))
        .append_header((header::SET_COOKIE, "b=2; Path=/; Secure"))
        .append_header((header::VARY, "Origin"))
        .append_header((header::VARY, "Accept-Encoding"))
        .json(json!({"error": "use_dpop_nonce"}));

    let signed = sign_fapi_resource_response(&state, &original, response).await;

    assert_eq!(
        signed.headers().get_all(header::WWW_AUTHENTICATE).count(),
        2
    );
    assert_eq!(signed.headers().get_all(header::SET_COOKIE).count(), 2);
    assert_eq!(signed.headers().get_all(header::VARY).count(), 2);
}

#[actix_web::test]
async fn fapi_resource_http_signature_malformed_headers_return_signed_error_without_mapping_drift()
{
    let state = fapi_enabled_signing_state_with_invalid_db();
    let duplicate_digest = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .append_header((
            "content-digest",
            "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        ))
        .append_header((
            "content-digest",
            "sha-256=:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=:",
        ))
        .append_header(("signature-input", "sig1=(\"@method\");created=1"))
        .append_header(("signature", "sig1=:b25l:"))
        .append_header(("signature", "sig1=:dHdv:"))
        .to_http_request();

    let response = fapi_resource(state.clone(), duplicate_digest, Bytes::new()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
    let response_input = response
        .headers()
        .get("signature-input")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(response_input.contains("\"@method\";req"));
    assert!(response_input.contains("\"@target-uri\";req"));
    assert!(!response_input.contains("\"content-digest\";req"));
    assert!(!response_input.contains("\"signature\";req"));

    let invalid_authorization = HeaderValue::from_bytes(b"Bearer \xff").unwrap();
    let invalid_utf8 = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, invalid_authorization))
        .to_http_request();
    let response = fapi_resource(state, invalid_utf8, Bytes::new()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));

    let invalid_signature_input = HeaderValue::from_bytes(b"sig1=(\xff)").unwrap();
    let invalid_digest = HeaderValue::from_bytes(b"sha-256=:AA\xff=:").unwrap();
    let invalid_signature_request = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .insert_header(("signature-input", invalid_signature_input))
        .insert_header(("signature", "sig1=:b25l:"))
        .insert_header(("content-digest", invalid_digest))
        .to_http_request();
    let response = fapi_resource(
        fapi_enabled_signing_state_with_invalid_db(),
        invalid_signature_request,
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
}

#[actix_web::test]
async fn fapi_resource_http_signature_enabled_endpoint_covers_get_post_and_replay() {
    let state = fapi_enabled_signing_state_with_invalid_db();
    let (get_req, get_body, client) = enabled_endpoint_request(&state, "client-1", 300, b"").await;
    let store = FakeFapiResourceStore::accepting(client);
    let get_req = with_fapi_store(get_req, store.clone());
    let replay_req = get_req.clone();

    let response = fapi_resource(state.clone(), get_req, get_body.clone()).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "store calls: {:?}",
        store.calls()
    );
    assert!(response.headers().contains_key("signature-input"));
    assert_eq!(store.calls(), (1, 1, 1, 1));

    let replay = fapi_resource(state.clone(), replay_req, get_body).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert!(replay.headers().contains_key("signature"));
    assert_eq!(store.calls(), (2, 2, 2, 1));

    let (post_req, post_body, post_client) =
        enabled_endpoint_request(&state, "client-1", 300, br#"{"amount":10}"#).await;
    let post_store = FakeFapiResourceStore::accepting(post_client);
    let post = fapi_resource(state, with_fapi_store(post_req, post_store), post_body).await;
    assert_eq!(post.status(), StatusCode::OK);
    assert!(post.headers().contains_key("content-digest"));
}

#[actix_web::test]
async fn fapi_resource_enabled_endpoint_interoperates_with_safe_signed_extra_headers() {
    let state = fapi_enabled_signing_state_with_invalid_db();
    let (req, client, request_fields, authorization) =
        enabled_request_with_signed_extras(&state, ExtraHeaderMode::Exact).await;
    let store = FakeFapiResourceStore::accepting(client);
    let response = fapi_resource(state.clone(), with_fapi_store(req, store), Bytes::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let digest = response
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let interaction_id = response
        .headers()
        .get("x-fapi-interaction-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let response_fields = SignatureFields {
        signature_input: response
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        signature: response
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    assert!(
        response_fields
            .signature_input
            .contains("\"signature-input\";req")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let response_headers = [
        ("content-digest", digest.as_str()),
        ("content-type", content_type.as_str()),
        ("x-fapi-interaction-id", interaction_id.as_str()),
    ];
    let request_headers = [
        ("authorization", authorization.as_str()),
        ("content-type", "application/json"),
        ("idempotency-key", "operation-123"),
    ];
    let parsed = parse_response_for_verification(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: &body,
        },
        OriginalRequest {
            input: RequestInput {
                method: "GET",
                target_uri: "https://issuer.example/fapi/resource",
                headers: &request_headers,
                body: b"",
            },
            signature_fields: Some(&request_fields),
        },
        response_fields,
        VerificationPolicy {
            now: Utc::now().timestamp(),
            max_age_seconds: 60,
            future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
        },
    )
    .unwrap();
    let server = state.keyset.snapshot();
    let verifier = fapi_http_signature_client(server.verification_keys[0].public_jwk.clone());
    verify_client_http_message(
        &verifier,
        DEFAULT_TENANT_ID,
        "client-1",
        parsed.keyid(),
        parsed.algorithm(),
        parsed.signature_base(),
        parsed.signature(),
    )
    .unwrap();

    for mode in [
        ExtraHeaderMode::Tampered,
        ExtraHeaderMode::Duplicate,
        ExtraHeaderMode::NonUtf8,
    ] {
        let (req, client, _, _) = enabled_request_with_signed_extras(&state, mode).await;
        let response = fapi_resource(
            state.clone(),
            with_fapi_store(req, FakeFapiResourceStore::accepting(client)),
            Bytes::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[actix_web::test]
async fn fapi_resource_http_signature_revoked_and_expired_stop_before_client_and_replay() {
    let state = fapi_enabled_signing_state_with_invalid_db();
    let (revoked_req, revoked_body, client) =
        enabled_endpoint_request(&state, "client-1", 300, b"").await;
    let mut revoked_store = FakeFapiResourceStore::accepting(client);
    Arc::get_mut(&mut revoked_store).unwrap().revoked = true;
    let revoked = fapi_resource(
        state.clone(),
        with_fapi_store(revoked_req, revoked_store.clone()),
        revoked_body,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(revoked_store.calls(), (1, 0, 0, 0));

    let (expired_req, expired_body, client) =
        enabled_endpoint_request(&state, "client-1", -1, b"").await;
    let expired_store = FakeFapiResourceStore::accepting(client);
    let expired = fapi_resource(
        state,
        with_fapi_store(expired_req, expired_store.clone()),
        expired_body,
    )
    .await;
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(expired_store.calls(), (1, 0, 0, 0));
}

#[actix_web::test]
async fn fapi_resource_http_signature_endpoint_signs_store_failures_and_hides_signer_body() {
    let state = fapi_enabled_signing_state_with_invalid_db();

    let (req, body, client) = enabled_endpoint_request(&state, "client-1", 300, b"").await;
    let retry_req = req.clone();
    let retry_body = body.clone();
    let retry_client = client.clone();
    let mut revocation_store = FakeFapiResourceStore::accepting(client);
    Arc::get_mut(&mut revocation_store)
        .unwrap()
        .revocation_error = true;
    let response = fapi_resource(
        state.clone(),
        with_fapi_store(req, revocation_store.clone()),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().contains_key("signature"));
    assert_eq!(revocation_store.calls(), (1, 0, 0, 0));
    let retry_store = FakeFapiResourceStore::accepting(retry_client);
    let retry = fapi_resource(
        state.clone(),
        with_fapi_store(retry_req, retry_store.clone()),
        retry_body,
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(retry_store.calls(), (1, 1, 1, 1));

    let (req, body, client) = enabled_endpoint_request(&state, "client-1", 300, b"").await;
    let mut client_store = FakeFapiResourceStore::accepting(client);
    Arc::get_mut(&mut client_store).unwrap().client_error = true;
    let response = fapi_resource(
        state.clone(),
        with_fapi_store(req, client_store.clone()),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().contains_key("signature-input"));
    assert_eq!(client_store.calls(), (1, 1, 0, 0));

    let (req, body, client) = enabled_endpoint_request(&state, "client-1", 300, b"").await;
    let mut replay_store = FakeFapiResourceStore::accepting(client);
    Arc::get_mut(&mut replay_store).unwrap().replay_mode = FakeReplayMode::DependencyFailure;
    let response = fapi_resource(
        state.clone(),
        with_fapi_store(req, replay_store.clone()),
        body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().contains_key("signature"));
    assert_eq!(replay_store.calls(), (1, 1, 1, 0));
}

#[actix_web::test]
async fn fapi_resource_http_signature_endpoint_signs_dpop_nonce_challenge() {
    let Some(state) = fapi_enabled_signing_state_with_live_valkey_nonce().await else {
        return;
    };
    let signing_key = SigningKey::from_bytes(&[29u8; 32]);
    let placeholder_token = "placeholder";
    let (_placeholder_proof, jkt, jwk) =
        signed_endpoint_dpop_proof(&signing_key, placeholder_token);
    let mut claims = access_claims(Some(ConfirmationClaims {
        jkt: Some(jkt),
        x5t_s256: None,
    }));
    claims.iss = state.settings.issuer.clone();
    claims.client_id = "client-1".to_owned();
    let token = signed_fapi_claims(&state, claims).await;
    let (proof, _jkt, _jwk) = signed_endpoint_dpop_proof(&signing_key, &token);
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("DPoP {token}")))
        .insert_header(("dpop", proof))
        .to_http_request();
    let store = FakeFapiResourceStore::accepting(fapi_http_signature_client(jwk));

    let response = fapi_resource(state, with_fapi_store(req, store.clone()), Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("dpop-nonce"));
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
    assert_eq!(store.calls(), (0, 0, 0, 0));
}

#[actix_web::test]
async fn fapi_resource_http_signature_post_preserves_semantic_received_digest_binding() {
    let state = fapi_enabled_signing_state_with_invalid_db();
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.client_id = "client-1".to_owned();
    let token = signed_fapi_claims(&state, claims).await;
    let authorization = format!("Bearer {token}");
    let body = Bytes::from_static(br#"{"semantic":true}"#);
    let received_digest = format!(
        "\t sha-512=:AA==:, {} \t",
        nazo_http_signatures::content_digest(&body)
    );
    let (client, req, request_fields) =
        signed_resource_request_with_received_digest(&body, &authorization, &received_digest).await;
    let store = FakeFapiResourceStore::accepting(client);

    let response = fapi_resource(state.clone(), with_fapi_store(req, store), body.clone()).await;

    assert_eq!(response.status(), StatusCode::OK);
    let response_digest = response
        .headers()
        .get("content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let interaction_id = response
        .headers()
        .get("x-fapi-interaction-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let response_fields = SignatureFields {
        signature_input: response
            .headers()
            .get("signature-input")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        signature: response
            .headers()
            .get("signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    };
    assert!(
        response_fields
            .signature_input
            .contains("\"content-digest\";req")
    );
    let response_body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let response_headers = [
        ("content-digest", response_digest.as_str()),
        ("content-type", content_type.as_str()),
        ("x-fapi-interaction-id", interaction_id.as_str()),
    ];
    let request_headers = [
        ("authorization", authorization.as_str()),
        ("content-digest", received_digest.as_str()),
    ];
    let parsed = parse_response_for_verification(
        ResponseInput {
            status: 200,
            headers: &response_headers,
            body: &response_body,
        },
        OriginalRequest {
            input: RequestInput {
                method: "POST",
                target_uri: "https://issuer.example/fapi/resource",
                headers: &request_headers,
                body: &body,
            },
            signature_fields: Some(&request_fields),
        },
        response_fields,
        VerificationPolicy {
            now: Utc::now().timestamp(),
            max_age_seconds: 60,
            future_skew_seconds: FAPI_HTTP_SIGNATURE_FUTURE_SKEW_SECONDS,
        },
    )
    .expect("client should verify the response using the received digest serialization");
    let server = state.keyset.snapshot();
    let verifier = fapi_http_signature_client(server.verification_keys[0].public_jwk.clone());
    verify_client_http_message(
        &verifier,
        DEFAULT_TENANT_ID,
        "client-1",
        parsed.keyid(),
        parsed.algorithm(),
        parsed.signature_base(),
        parsed.signature(),
    )
    .unwrap();
}

#[actix_web::test]
async fn fapi_resource_http_signature_errors_preserve_unique_received_signature_bindings() {
    let state = fapi_enabled_signing_state_with_invalid_db();
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.client_id = "client-1".to_owned();
    let token = signed_fapi_claims(&state, claims).await;
    let authorization = format!("Bearer {token}");
    let (_keyset, client, _req, valid_fields) =
        signed_resource_request_for_authorization(b"", &authorization).await;
    let now = Utc::now().timestamp();
    let mut stale = copied_signature_fields(&valid_fields);
    stale.signature_input = replace_created(&stale.signature_input, now - 600);
    let mut future = copied_signature_fields(&valid_fields);
    future.signature_input = replace_created(&future.signature_input, now + 600);
    let mut wrong_tag = copied_signature_fields(&valid_fields);
    wrong_tag.signature_input = wrong_tag
        .signature_input
        .replace("fapi-2-request", "wrong-request-tag");
    let mut missing_coverage = copied_signature_fields(&valid_fields);
    missing_coverage.signature_input =
        missing_coverage
            .signature_input
            .replacen(" \"authorization\"", "", 1);
    assert_ne!(
        missing_coverage.signature_input,
        valid_fields.signature_input
    );

    for fields in [stale, future, wrong_tag, missing_coverage] {
        let req = actix_web::test::TestRequest::get()
            .uri("/fapi/resource")
            .insert_header((header::AUTHORIZATION, authorization.as_str()))
            .insert_header(("signature-input", fields.signature_input.clone()))
            .insert_header(("signature", fields.signature.clone()))
            .to_http_request();
        let store = FakeFapiResourceStore::accepting(client.clone());
        let response = fapi_resource(
            state.clone(),
            with_fapi_store(req, store.clone()),
            Bytes::new(),
        )
        .await;
        assert_eq!(store.calls(), (1, 1, 0, 0));
        assert_signed_error_covers_received_signature_fields(&state, response, "GET", &fields)
            .await;
    }

    let request_body = Bytes::from_static(br#"{"digest":"mismatch"}"#);
    let (_keyset, client, _req, fields) =
        signed_resource_request_for_authorization(&request_body, &authorization).await;
    let wrong_digest = nazo_http_signatures::content_digest(b"different body");
    let req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, authorization))
        .insert_header(("content-digest", wrong_digest))
        .insert_header(("signature-input", fields.signature_input.clone()))
        .insert_header(("signature", fields.signature.clone()))
        .to_http_request();
    let store = FakeFapiResourceStore::accepting(client);
    let response = fapi_resource(
        state.clone(),
        with_fapi_store(req, store.clone()),
        request_body,
    )
    .await;
    assert_eq!(store.calls(), (1, 1, 0, 0));
    assert_signed_error_covers_received_signature_fields(&state, response, "POST", &fields).await;
}

#[actix_web::test]
async fn fapi_resource_http_signature_replay_is_atomic_with_exact_ttl() {
    let Ok(valkey_url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let valkey = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).unwrap())
        .build()
        .unwrap();
    valkey.init().await.unwrap();
    let first = *blake3::hash(b"first-safe-fingerprint").as_bytes();
    let fresh = *blake3::hash(b"fresh-safe-fingerprint").as_bytes();

    assert_eq!(
        consume_fapi_http_signature_replay(&valkey, &first, 60).await,
        ReplayConsumption::Accepted
    );
    assert_eq!(
        consume_fapi_http_signature_replay(&valkey, &first, 60).await,
        ReplayConsumption::Replay
    );
    assert_eq!(
        consume_fapi_http_signature_replay(&valkey, &fresh, 60).await,
        ReplayConsumption::Accepted
    );
    let ttl: i64 = valkey
        .ttl(fapi_http_signature_replay_key(&first))
        .await
        .unwrap();
    assert!((64..=65).contains(&ttl), "unexpected replay TTL: {ttl}");
    let _: () = valkey
        .del(vec![
            fapi_http_signature_replay_key(&first),
            fapi_http_signature_replay_key(&fresh),
        ])
        .await
        .unwrap();
}

#[actix_web::test]
async fn fapi_resource_http_signature_replay_dependency_failure_is_fail_closed() {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable URL should parse"),
    );
    builder.with_performance_config(|performance| {
        performance.default_command_timeout = std::time::Duration::from_millis(50);
    });
    builder.with_connection_config(|connection| {
        connection.connection_timeout = std::time::Duration::from_millis(50);
        connection.internal_command_timeout = std::time::Duration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    let disconnected = builder
        .build()
        .expect("unavailable Valkey client should construct");
    let fingerprint = *blake3::hash(b"dependency-failure-fingerprint").as_bytes();

    assert_eq!(
        consume_fapi_http_signature_replay(&disconnected, &fingerprint, 60).await,
        ReplayConsumption::DependencyFailure
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_unverifiable_access_token_before_revocation_lookup() {
    let state = Data::new(fapi_test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_signed_token_with_wrong_resource_audience_before_db_lookup() {
    let state = fapi_signing_state_with_invalid_db();
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["https://issuer.example/userinfo".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_signed_token_with_invalid_tenant_boundary_before_db_lookup() {
    let state = fapi_signing_state_with_invalid_db();
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.tenant_id = "not-a-uuid".to_owned();
    claims.aud = json!("resource://default");
    let token = signed_fapi_claims(&state, claims).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_revoked_access_token() {
    let Some(state) = live_fapi_signing_state() else {
        return;
    };
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    insert_fapi_client_and_revocation(&state, "fapi-client", &token.jti).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_expired_access_token_after_revocation_lookup() {
    let Some(state) = live_fapi_signing_state() else {
        return;
    };
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        -1,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_returns_server_error_when_revocation_lookup_cannot_connect() {
    let state = fapi_signing_state_with_invalid_db();
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn fapi_resource_returns_server_error_when_revocation_query_fails_after_token_validation() {
    let schema = format!("fapi_revocation_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_fapi_signing_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["access_token_revocations"]).await;
    rename_column(
        &state,
        &schema,
        "access_token_revocations",
        "access_token_jti_blake3",
        "access_token_jti_blake3_broken",
    )
    .await;
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state.clone(), req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    drop_schema(&state, &schema).await;
}

#[test]
fn post_body_access_token_accepts_single_form_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"), false);

    let ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from form body");
    };
    assert_eq!(token, "token-1");
}

#[test]
fn post_body_access_token_rejects_missing_content_type() {
    let req = actix_web::test::TestRequest::post().to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"), false);

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn post_body_access_token_rejects_duplicate_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(
        &req,
        &Bytes::from_static(b"access_token=token-1&access_token=token-2"),
        false,
    );

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn post_body_access_token_treats_blank_or_absent_value_as_missing() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let blank = resource_access_token(&req, &Bytes::from_static(b"access_token=%20%09"), false);
    assert!(matches!(blank, ResourceAccessToken::Missing));

    let absent = resource_access_token(&req, &Bytes::from_static(b"scope=openid"), false);
    assert!(matches!(absent, ResourceAccessToken::Missing));
}

#[test]
fn query_access_token_is_not_accepted() {
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource?access_token=query-token")
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new(), false);

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn authorization_header_access_token_accepts_single_value() {
    let req = actix_web::test::TestRequest::get()
        .insert_header((header::AUTHORIZATION, "DPoP header-token"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new(), false);

    let ResourceAccessToken::Present(AccessTokenAuthScheme::DPoP, token) = token else {
        panic!("expected dpop token from authorization header");
    };
    assert_eq!(token, "header-token");
}

#[test]
fn access_token_rejects_multiple_transport_methods() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=body-token"), false);

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn fapi_resource_accepts_only_bound_resource_audiences() {
    let mut settings = Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("resource://default")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/fapi/resource"])
    ));
    settings.protected_resource_identifier = "https://api.example/fapi/resource".to_owned();
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("https://api.example/fapi/resource")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/userinfo")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/userinfo"])
    ));
}

#[test]
fn fapi_interaction_id_echoes_request_or_generates_response_value() {
    let echoed = actix_web::test::TestRequest::get()
        .insert_header((
            "x-fapi-interaction-id",
            "fAf943Fd-23A7-441b-B8cE-d012413FcA0c",
        ))
        .to_http_request();
    assert_eq!(
        fapi_interaction_id(&echoed).to_str().ok(),
        Some("fAf943Fd-23A7-441b-B8cE-d012413FcA0c")
    );

    let generated = actix_web::test::TestRequest::get().to_http_request();
    assert!(
        fapi_interaction_id(&generated)
            .to_str()
            .is_ok_and(|value| { Uuid::parse_str(value).is_ok() })
    );
}

#[actix_web::test]
async fn sender_constrained_resource_rejects_wrong_transport_without_backend_lookup() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let bearer_with_dpop_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: Some("dpop-jkt".to_owned()),
            x5t_s256: None,
        })),
    )
    .await
    .expect_err("Bearer transport must not accept a DPoP-bound access token");
    assert_eq!(bearer_with_dpop_cnf.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&bearer_with_dpop_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );

    let dpop_without_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::DPoP,
        &access_claims(None),
    )
    .await
    .expect_err("DPoP transport must require a DPoP-bound access token");
    assert_eq!(dpop_without_cnf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&dpop_without_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_requires_verified_certificate() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("thumbprint".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must require a verified certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_rejects_certificate_thumbprint_mismatch() {
    let state = fapi_trusted_proxy_state();
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must reject the wrong client certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_accepts_matching_verified_certificate() {
    let state = fapi_trusted_proxy_state();
    let thumbprint = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8";
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint))
        .to_http_request();

    validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some(thumbprint.to_owned()),
        })),
    )
    .await
    .expect("matching verified mTLS certificate should satisfy token binding");
}
