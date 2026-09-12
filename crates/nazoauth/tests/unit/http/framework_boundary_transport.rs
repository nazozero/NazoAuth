use nazo_oauth_server::contracts::userinfo::{
    PreparedUserinfo, UserinfoError, UserinfoFuture, UserinfoOperations, UserinfoPreparationFuture,
    UserinfoRequestFacts,
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use actix_web::{
    HttpRequest, HttpResponse,
    body::to_bytes,
    http::{StatusCode, header},
    test::TestRequest,
    web::{Bytes, Data},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::future::{BoxFuture, FutureExt};
use nazo_auth::{
    DpopError, DpopNoncePolicy, DpopStateFuture, DpopStateStorePort, RequestRateLimitBucket,
    RequestRateLimitError, RequestRateLimitFuture, RequestRateLimitPort,
};
use nazo_http_actix::IpCidr;
use nazo_http_actix::{ClientIpConfig, ClientIpHeaderMode, UserinfoEndpoint};
use nazo_oauth_server::contracts::userinfo::AccessTokenAuthScheme;
use serde_json::Value;
use serde_json::json;

use crate::http;
use crate::http::well_known::ReadinessDependencies;
use nazo_key_management::KeyManager;
use nazo_persistence::{DatabaseHealthError, DatabaseHealthPort};

async fn live_transport_state() -> crate::test_support::TestInfrastructure {
    let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("transport golden tests require the configured test PostgreSQL database");
    let valkey_url = std::env::var("VALKEY_URL")
        .expect("transport golden tests require the configured test Valkey instance");
    let database = nazo_postgres::create_pool(database_url, 2).expect("test database pool");
    let valkey = nazo_valkey::test_support::connect(&valkey_url, std::time::Duration::from_secs(1))
        .await
        .expect("test Valkey connection");
    let mut settings =
        crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
            .expect("test settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://mtls.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();
    crate::test_support::initialize_audit_dependencies(&database);
    crate::test_support::TestInfrastructure {
        diesel_db: database,
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn ready_body_bytes(response: HttpResponse) -> Vec<u8> {
    to_bytes(response.into_body())
        .await
        .expect("response body must serialize to bytes")
        .to_vec()
}

#[derive(Clone)]
struct FakeDatabaseHealth {
    ok: bool,
}

impl DatabaseHealthPort for FakeDatabaseHealth {
    fn check(&self) -> BoxFuture<'_, Result<(), DatabaseHealthError>> {
        let ok = self.ok;
        async move { if ok { Ok(()) } else { Err(DatabaseHealthError) } }.boxed()
    }
}

#[derive(Clone)]
struct FakeTransientStateHealth {
    ok: bool,
}

impl nazo_oauth_server::ports::transient_state::TransientStateHealthPort
    for FakeTransientStateHealth
{
    fn check(&self) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<'_, ()> {
        let ok = self.ok;
        Box::pin(async move {
            if ok {
                Ok(())
            } else {
                Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
            }
        })
    }
}

fn healthy_keyset() -> KeyManager {
    KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA)
}

#[actix_web::test]
async fn framework_boundary_transport_readiness_contracts_match_expected_boundary() {
    let ready = http::well_known::ready(Data::new(ReadinessDependencies::new(
        Arc::new(FakeDatabaseHealth { ok: true }),
        Arc::new(FakeTransientStateHealth { ok: true }),
        healthy_keyset(),
    )))
    .await;
    assert_eq!(ready.status(), StatusCode::OK);

    let ready = serde_json::from_slice::<Value>(&ready_body_bytes(ready).await)
        .expect("readiness body should deserialize");
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["checks"]["database"]["status"], "up");
    assert_eq!(ready["checks"]["transient_state"]["status"], "up");
    assert_eq!(ready["checks"]["signing_keys"]["status"], "up");
}

#[actix_web::test]
async fn framework_boundary_transport_readiness_fails_closed_when_dependencies_are_unavailable() {
    let response = http::well_known::ready(Data::new(ReadinessDependencies::new(
        Arc::new(FakeDatabaseHealth { ok: false }),
        Arc::new(FakeTransientStateHealth { ok: true }),
        healthy_keyset(),
    )))
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload = serde_json::from_slice::<Value>(&ready_body_bytes(response).await)
        .expect("readiness body should parse");
    assert_eq!(payload["status"], "not_ready");
    assert_eq!(payload["checks"]["database"]["status"], "down");
    assert_eq!(payload["checks"]["transient_state"]["status"], "up");
    assert_eq!(payload["checks"]["signing_keys"]["status"], "up");
}

#[actix_web::test]
async fn framework_boundary_transport_well_known_endpoints_keep_contracts() {
    assert_eq!(
        http::well_known::live().await.into_inner(),
        serde_json::json!({"status": "live"})
    );
    assert_eq!(
        http::well_known::startup().await.into_inner(),
        serde_json::json!({"status": "started"})
    );
    assert_eq!(
        http::well_known::captcha_config().await.into_inner(),
        serde_json::json!({
            "turnstile_enabled": false,
            "turnstile_site_key": Value::Null,
            "registration_enabled": true
        })
    );
}

#[test]
fn framework_boundary_transport_views_helpers_maintain_http_projection_semantics() {
    let mut query = std::collections::HashMap::new();
    query.insert("page".to_owned(), "3".to_owned());
    query.insert("page_size".to_owned(), "50".to_owned());
    assert_eq!(http::views::pagination(&query), (3, 50, 100));

    let mut headers = actix_web::http::header::HeaderMap::new();
    let fetch = actix_web::http::header::HeaderName::from_static("sec-fetch-site");
    assert!(!http::views::is_cross_site_fetch(&headers));
    headers.insert(
        fetch.clone(),
        actix_web::http::header::HeaderValue::from_static("same-origin"),
    );
    assert!(!http::views::is_cross_site_fetch(&headers));
    headers.insert(
        fetch,
        actix_web::http::header::HeaderValue::from_static("cross-site"),
    );
    assert!(http::views::is_cross_site_fetch(&headers));
}

#[derive(Clone)]
struct RecordingRateLimiter {
    outcome: Result<u64, RequestRateLimitError>,
    calls: Arc<Mutex<Vec<(RequestRateLimitBucket, String, u64)>>>,
}

impl RequestRateLimitPort for RecordingRateLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((bucket, subject.to_owned(), window_seconds));
            self.outcome
        })
    }
}

#[actix_web::test]
async fn framework_boundary_transport_rate_limit_exact_wire_and_store_order() {
    let store = Arc::new(RecordingRateLimiter {
        outcome: Ok(3),
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let req = TestRequest::default()
        .peer_addr("203.0.113.77:443".parse().unwrap())
        .to_http_request();
    let response = http::rate_limit::enforce_auth_request_limit(
        &nazo_oauth_server::rate_limit::AuthRequestLimiter::new(store.clone(), 41, 2),
        &req,
        &ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
    .await
    .expect_err("third request must be rate limited");
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::Authentication,
            "203.0.113.77".to_owned(),
            41
        )]
    );
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "41");
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"temporarily_unavailable","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_rate_limit_store_failure_exact_wire_and_order() {
    let store = Arc::new(RecordingRateLimiter {
        outcome: Err(RequestRateLimitError),
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let req = TestRequest::default()
        .peer_addr("198.51.100.9:443".parse().unwrap())
        .to_http_request();
    let response = http::rate_limit::enforce_auth_request_limit(
        &nazo_oauth_server::rate_limit::AuthRequestLimiter::new(store.clone(), 60, 10),
        &req,
        &ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
    .await
    .expect_err("store failure must fail closed");
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::Authentication,
            "198.51.100.9".to_owned(),
            60
        )]
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::RETRY_AFTER).is_none());
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"server_error","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_duplicate_dpop_header_has_exact_error_wire() {
    let req = TestRequest::default()
        .insert_header(("dpop", "first-proof"))
        .append_header(("dpop", "second-proof"))
        .to_http_request();
    let error = nazo_http_actix::dpop_proof_header(req.headers())
        .expect_err("duplicate DPoP proof headers must be rejected");
    let response = nazo_http_actix::dpop_error_response(
        error,
        nazo_oauth_server::contracts::request_facts::DpopErrorContext::TokenEndpoint,
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "DPoP error=\"invalid_dpop_proof\""
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_dpop_proof","error_description":"DPoP proof is malformed."}"#
    );
}

#[test]
fn framework_boundary_transport_empty_dpop_header_is_present_but_has_no_proof() {
    let req = TestRequest::default()
        .insert_header(("dpop", "   "))
        .to_http_request();
    assert!(nazo_http_actix::dpop_proof_present(req.headers()));
    assert_eq!(
        nazo_http_actix::dpop_proof_header(req.headers()).unwrap(),
        None
    );
}

struct RecordingUserinfo {
    calls: Arc<Mutex<Vec<(AccessTokenAuthScheme, String)>>>,
    result: UserinfoError,
}

impl UserinfoOperations for RecordingUserinfo {
    fn prepare<'a>(
        &'a self,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoPreparationFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push((scheme, token));
            Err(self.result.clone())
        })
    }
    fn userinfo<'a>(
        &'a self,
        _prepared: PreparedUserinfo,
        _facts: UserinfoRequestFacts<'a>,
    ) -> UserinfoFuture<'a> {
        panic!("rejected preparation must not reach binding")
    }
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_rejects_conflicting_auth_sources_before_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer token-in-header"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .app_data(Data::new(crate::http::mtls::MtlsCertificateSource::new(
            crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
        )))
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("client-cert", ":not-base64!:"))
        .to_http_request();
    let response = nazo_http_actix::userinfo(
        endpoint,
        req,
        Bytes::from_static(b"access_token=token-in-body"),
    )
    .await;
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
    );
    assert_eq!(ready_body_bytes(response).await, br#"{"error":"invalid_request","error_description":"Only one access token transport method may be used."}"#);
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_missing_token_challenge_skips_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::default().to_http_request();
    let response = nazo_http_actix::userinfo(endpoint, req, Bytes::new()).await;
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_token","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_userinfo_invalid_token_challenge_follows_port() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(UserinfoEndpoint::new(
        Arc::new(RecordingUserinfo {
            calls: calls.clone(),
            result: UserinfoError::InvalidAccessToken,
        }),
        Arc::new(NoFapiMtls),
    ));
    let req = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer invalid-access-token"))
        .to_http_request();
    let response = nazo_http_actix::userinfo(endpoint, req, Bytes::new()).await;
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(calls.lock().unwrap()[0].1, "invalid-access-token");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_token","error_description":"Request failed."}"#
    );
}

#[test]
fn framework_boundary_transport_untrusted_rfc9440_peer_cannot_supply_mtls_facts() {
    let trusted = [IpCidr::parse("192.0.2.0/24").unwrap()];
    let req = TestRequest::default()
        .app_data(Data::new(http::mtls::MtlsCertificateSource::new(
            http::mtls::MtlsCertificateSourceMode::Rfc9440,
        )))
        .peer_addr("198.51.100.10:443".parse().unwrap())
        .insert_header(("client-cert", ":AA==:"))
        .to_http_request();
    assert!(http::mtls::request_mtls_client_certificate(&req, &trusted).is_none());
    assert!(http::mtls::request_mtls_thumbprint(&req, &trusted).is_none());
}

#[test]
fn framework_boundary_transport_direct_tls_does_not_fallback_to_certificate_headers() {
    let req = TestRequest::default()
        .app_data(Data::new(http::mtls::MtlsCertificateSource::new(
            http::mtls::MtlsCertificateSourceMode::DirectTls,
        )))
        .insert_header(("client-cert", ":AA==:"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .to_http_request();
    assert!(http::mtls::request_mtls_client_certificate(&req, &[]).is_none());
}

struct NoFapiAuthorizer;

impl nazo_oauth_server::contracts::fapi_resource::FapiResourceAuthorizer for NoFapiAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: nazo_resource_server::ProtectedResourceAuthorizationRequest<'a>,
        _context: nazo_resource_server::ProtectedResourceAuthorizationContext<'a>,
    ) -> nazo_oauth_server::contracts::fapi_resource::FapiFuture<
        'a,
        Result<
            nazo_resource_server::ProtectedResourceAuthorizationResult,
            nazo_oauth_server::contracts::fapi_resource::FapiAuthorizationError,
        >,
    > {
        panic!("authorization must not run without access token")
    }
}

struct NoFapiMtls;

impl nazo_http_actix::mtls::MtlsThumbprintExtractor for NoFapiMtls {
    fn resolve(&self, _request: &HttpRequest) -> Option<String> {
        panic!("certificate extraction must not run without access token")
    }
}

struct NoFapiSignatures;

impl nazo_oauth_server::contracts::fapi_resource::FapiHttpMessageSignatures for NoFapiSignatures {
    fn enabled(&self) -> bool {
        false
    }
    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a nazo_http_signatures::VerifiedInput,
    ) -> nazo_oauth_server::contracts::fapi_resource::FapiFuture<
        'a,
        Result<(), nazo_oauth_server::contracts::fapi_resource::FapiSignatureVerificationError>,
    > {
        panic!("signature verification must be disabled")
    }
    fn response_signature(
        &self,
    ) -> Result<
        Arc<dyn nazo_oauth_server::contracts::fapi_resource::FapiResponseSignature>,
        nazo_oauth_server::contracts::fapi_resource::FapiSignatureOperationError,
    > {
        panic!("signature presentation must be disabled")
    }
}

#[actix_web::test]
async fn framework_boundary_transport_fapi_missing_token_has_exact_unsigned_wire() {
    let endpoint = Data::new(nazo_http_actix::FapiResourceEndpoint::new(
        "https://issuer.example",
        "https://mtls.issuer.example",
        300,
        Arc::new(NoFapiAuthorizer),
        Arc::new(NoFapiMtls),
        Arc::new(NoFapiSignatures),
    ));
    let response = nazo_http_actix::fapi_resource(
        endpoint,
        TestRequest::get().uri("/fapi/resource").to_http_request(),
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert!(!response.headers().contains_key("signature"));
    assert!(!response.headers().contains_key("signature-input"));
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_token","error_description":"Request failed."}"#
    );
}

struct FailingFapiResponseSigner {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl nazo_oauth_server::contracts::fapi_resource::FapiHttpMessageSignatures
    for FailingFapiResponseSigner
{
    fn enabled(&self) -> bool {
        self.calls.lock().unwrap().push("enabled");
        true
    }

    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a nazo_http_signatures::VerifiedInput,
    ) -> nazo_oauth_server::contracts::fapi_resource::FapiFuture<
        'a,
        Result<(), nazo_oauth_server::contracts::fapi_resource::FapiSignatureVerificationError>,
    > {
        panic!("missing token must stop before signature verification")
    }

    fn response_signature(
        &self,
    ) -> Result<
        Arc<dyn nazo_oauth_server::contracts::fapi_resource::FapiResponseSignature>,
        nazo_oauth_server::contracts::fapi_resource::FapiSignatureOperationError,
    > {
        self.calls.lock().unwrap().push("response_signature");
        Err(nazo_oauth_server::contracts::fapi_resource::FapiSignatureOperationError::Unavailable)
    }
}

#[actix_web::test]
async fn framework_boundary_transport_fapi_signer_failure_erases_error_wire_after_capture() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(nazo_http_actix::FapiResourceEndpoint::new(
        "https://issuer.example",
        "https://mtls.issuer.example",
        300,
        Arc::new(NoFapiAuthorizer),
        Arc::new(NoFapiMtls),
        Arc::new(FailingFapiResponseSigner {
            calls: calls.clone(),
        }),
    ));
    let response = nazo_http_actix::fapi_resource(
        endpoint,
        TestRequest::get().uri("/fapi/resource").to_http_request(),
        Bytes::new(),
    )
    .await;
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["enabled", "response_signature"]
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("signature"));
    assert!(!response.headers().contains_key("signature-input"));
    assert_eq!(ready_body_bytes(response).await, b"");
}

struct RecordingFapiSigner {
    bases: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl nazo_oauth_server::contracts::fapi_resource::FapiResponseSignature for RecordingFapiSigner {
    fn kid(&self) -> &str {
        "response-key"
    }
    fn algorithm(&self) -> &str {
        "ed25519"
    }
    fn sign<'a>(
        &'a self,
        signature_base: &'a [u8],
    ) -> nazo_oauth_server::contracts::fapi_resource::FapiFuture<
        'a,
        Result<Vec<u8>, nazo_oauth_server::contracts::fapi_resource::FapiSignatureOperationError>,
    > {
        self.bases.lock().unwrap().push(signature_base.to_vec());
        Box::pin(async { Ok(vec![7; 64]) })
    }
}

struct RecordingFapiSignatures {
    calls: Arc<Mutex<Vec<&'static str>>>,
    signer: Arc<RecordingFapiSigner>,
}

impl nazo_oauth_server::contracts::fapi_resource::FapiHttpMessageSignatures
    for RecordingFapiSignatures
{
    fn enabled(&self) -> bool {
        self.calls.lock().unwrap().push("enabled");
        true
    }
    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a nazo_http_signatures::VerifiedInput,
    ) -> nazo_oauth_server::contracts::fapi_resource::FapiFuture<
        'a,
        Result<(), nazo_oauth_server::contracts::fapi_resource::FapiSignatureVerificationError>,
    > {
        panic!("no token must skip request signature verification")
    }
    fn response_signature(
        &self,
    ) -> Result<
        Arc<dyn nazo_oauth_server::contracts::fapi_resource::FapiResponseSignature>,
        nazo_oauth_server::contracts::fapi_resource::FapiSignatureOperationError,
    > {
        self.calls.lock().unwrap().push("response_signature");
        Ok(self.signer.clone())
    }
}

#[actix_web::test]
async fn framework_boundary_transport_fapi_signed_error_preserves_body_and_content_digest() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let bases = Arc::new(Mutex::new(Vec::new()));
    let endpoint = Data::new(nazo_http_actix::FapiResourceEndpoint::new(
        "https://issuer.example",
        "https://mtls.issuer.example",
        300,
        Arc::new(NoFapiAuthorizer),
        Arc::new(NoFapiMtls),
        Arc::new(RecordingFapiSignatures {
            calls: calls.clone(),
            signer: Arc::new(RecordingFapiSigner {
                bases: bases.clone(),
            }),
        }),
    ));
    let response = nazo_http_actix::fapi_resource(
        endpoint,
        TestRequest::get().uri("/fapi/resource").to_http_request(),
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &["enabled", "response_signature"]
    );
    let expected_body = br#"{"error":"invalid_token","error_description":"Request failed."}"#;
    assert_eq!(
        response.headers().get("content-digest").unwrap(),
        nazo_http_signatures::content_digest(expected_body).as_str()
    );
    assert!(response.headers().contains_key("signature-input"));
    assert!(response.headers().contains_key("signature"));
    {
        let signature_base = bases.lock().unwrap();
        assert_eq!(signature_base.len(), 1);
        assert!(
            signature_base[0]
                .windows(b"content-digest".len())
                .any(|window| window == b"content-digest")
        );
        assert!(
            signature_base[0]
                .windows(b"@status".len())
                .any(|window| window == b"@status")
        );
    }
    assert_eq!(ready_body_bytes(response).await, expected_body);
}

fn signed_boundary_dpop_proof(
    htu: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
    jti: &str,
) -> String {
    let key = SigningKey::from_bytes(&[7; 32]);
    let jwk = json!({"kty":"OKP", "crv":"Ed25519", "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())});
    let header = json!({"typ":"dpop+jwt", "alg":"EdDSA", "jwk":jwk});
    let mut claims =
        json!({"htm":"POST", "htu":htu, "iat":chrono::Utc::now().timestamp(), "jti":jti});
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[derive(Default)]
struct RecordingDpopState {
    calls: Mutex<Vec<String>>,
    nonces: Mutex<HashSet<String>>,
    replay: Mutex<HashSet<String>>,
}

impl DpopStateStorePort for RecordingDpopState {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("replay:{jkt}:{jti}:{ttl_seconds}"));
            Ok(self.replay.lock().unwrap().insert(format!("{jkt}:{jti}")))
        })
    }
    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("issue_nonce:{ttl_seconds}"));
            self.nonces.lock().unwrap().insert(nonce.to_owned());
            Ok(())
        })
    }
    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("validate_nonce:{nonce}"));
            Ok(self.nonces.lock().unwrap().contains(nonce))
        })
    }
}

#[actix_web::test]
async fn framework_boundary_transport_dpop_nonce_then_replay_store_order() {
    let store = RecordingDpopState::default();
    let proof_without_nonce =
        signed_boundary_dpop_proof("https://issuer.example/token", None, None, "stable-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", proof_without_nonce))
        .to_http_request();
    let first = nazo_oauth_server::security::dpop::validate_dpop_proof(
        &store,
        crate::http::authorization::test_support::test_security_audit(),
        "https://issuer.example",
        "https://mtls.example",
        DpopNoncePolicy::Required,
        http::dpop::dpop_request_facts(&req),
        None,
        None,
    )
    .await;
    let nonce = match first {
        Err(DpopError::UseNonce(nonce)) => nonce,
        other => panic!("expected nonce challenge, got {other:?}"),
    };
    assert_eq!(store.calls.lock().unwrap().len(), 1);
    assert!(store.calls.lock().unwrap()[0].starts_with("issue_nonce:"));
    let proof = signed_boundary_dpop_proof(
        "https://issuer.example/token",
        Some(&nonce),
        None,
        "stable-jti",
    );
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", proof))
        .to_http_request();
    assert!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Required,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await
        .unwrap()
        .is_some()
    );
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Required,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await,
        Err(DpopError::ReplayDetected(_))
    ));
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[1], format!("validate_nonce:{nonce}"));
    assert!(calls[2].contains(":stable-jti:"));
    assert_eq!(calls[3], format!("validate_nonce:{nonce}"));
    assert_eq!(calls[4], calls[2]);
}

#[actix_web::test]
async fn framework_boundary_transport_dpop_ath_and_htu_fail_before_state_port() {
    let store = RecordingDpopState::default();
    let wrong_htu =
        signed_boundary_dpop_proof("https://attacker.example/token", None, None, "htu-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", wrong_htu))
        .to_http_request();
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Optional,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await,
        Err(DpopError::InvalidProof)
    ));
    let missing_ath =
        signed_boundary_dpop_proof("https://issuer.example/token", None, None, "ath-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", missing_ath))
        .to_http_request();
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Optional,
            http::dpop::dpop_request_facts(&req),
            Some("access-token"),
            None
        )
        .await,
        Err(DpopError::InvalidProof)
    ));
    assert!(store.calls.lock().unwrap().is_empty());
}

#[derive(Clone, Default)]
struct CasRegistrationStore {
    hash_after_authentication: Arc<Mutex<Option<String>>>,
    state: Arc<Mutex<(Option<nazo_auth::OAuthClient>, Option<String>)>>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl nazo_http_actix::DynamicRegistrationClientStore for CasRegistrationStore {
    fn insert<'a>(
        &'a self,
        prepared: &'a nazo_auth::PreparedClientRegistration,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        let client = nazo_auth::OAuthClient {
            id: uuid::Uuid::now_v7(),
            tenant_id: prepared.tenant.tenant_id.as_uuid(),
            realm_id: prepared.tenant.realm_id.as_uuid(),
            organization_id: prepared.tenant.organization_id.as_uuid(),
            registration: prepared.registration.clone(),
            require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
            is_active: true,
        };
        *self.state.lock().unwrap() = (
            Some(client.clone()),
            prepared.registration_access_token_blake3.clone(),
        );
        self.calls.lock().unwrap().push("insert");
        Box::pin(async move { Ok(client) })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, Option<nazo_auth::OAuthClient>> {
        self.calls.lock().unwrap().push("lookup");
        let state = self.state.lock().unwrap();
        let found = state.0.clone().filter(|client| {
            client.tenant_id == tenant_id
                && client.client_id == client_id
                && client.is_active
                && state.1.as_deref() == Some(token_hash)
        });
        Box::pin(async move { Ok(found) })
    }

    fn has_client_secret(
        &self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'_, bool> {
        self.calls.lock().unwrap().push("has_secret");
        // Model a concurrent rotation after the handler authenticated its snapshot.
        if let Some(hash) = self.hash_after_authentication.lock().unwrap().take() {
            self.state.lock().unwrap().1 = Some(hash);
        }
        Box::pin(async { Ok(false) })
    }

    fn client_secret_salt(
        &self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async { Ok(None) })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _candidate_digest: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }

    fn rotate_credentials<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _client_secret_hash: Option<&'a str>,
        _expected_registration_access_token_hash: &'a str,
        _new_registration_access_token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        panic!("PUT must use replace_registration CAS")
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a nazo_auth::OAuthClient,
        _client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        self.calls.lock().unwrap().push("replace_cas");
        let mut state = self.state.lock().unwrap();
        if !state.0.as_ref().is_some_and(|stored| {
            stored.tenant_id == client.tenant_id && stored.id == client.id && stored.is_active
        }) || state.1.as_deref() != Some(expected_registration_access_token_hash)
        {
            return Box::pin(async {
                Err(nazo_auth::DynamicRegistrationDependencyError::StaleCredentials)
            });
        }
        // PostgreSQL replaces metadata, then rereads the row with its stored identity.
        let stored = state.0.as_mut().unwrap();
        let client_id = stored.client_id.clone();
        stored.registration = client.registration.clone();
        stored.registration.client_id = client_id;
        stored.require_mtls_bound_tokens = client.require_mtls_bound_tokens;
        let updated = stored.clone();
        state.1 = new_registration_access_token_hash.map(str::to_owned);
        Box::pin(async move { Ok(updated) })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _client_id: uuid::Uuid,
        _expected_registration_access_token_hash: &'a str,
    ) -> nazo_http_actix::DynamicRegistrationFuture<'a, bool> {
        panic!("DELETE must not run")
    }
}

#[derive(Clone, Default)]
struct RegistrationSecurity {
    issued: Arc<Mutex<u8>>,
}

impl nazo_auth::SectorIdentifierResolverPort for RegistrationSecurity {
    fn resolve<'a>(&'a self, _uri: &'a str) -> nazo_auth::SectorIdentifierFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksResolverPort
    for RegistrationSecurity
{
    fn resolve<'a>(
        &'a self,
        _uri: &'a str,
        _expected_kid: Option<&'a str>,
    ) -> nazo_oauth_server::contracts::dynamic_client_registration::RemoteJwksFuture<'a> {
        Box::pin(async { Ok(json!({"keys": []})) })
    }
}

impl nazo_auth::AdminClientCryptoPort for RegistrationSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        vec!["RS256".to_owned(), "PS256".to_owned()]
    }
    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
    }
    fn validate_jwks(&self, _jwks: &Value) -> Result<(), String> {
        Ok(())
    }
    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty())
            .then_some(())
            .ok_or_else(|| "invalid DN".to_owned())
    }
    fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
        1
    }
    fn contains_signing_key(&self, _jwks: &Value) -> bool {
        true
    }
    fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
        true
    }
}

impl nazo_auth::DynamicRegistrationSecretPort for RegistrationSecurity {
    fn random_token(&self) -> String {
        let mut issued = self.issued.lock().unwrap();
        *issued += 1;
        format!("registration-token-{issued}")
    }
    fn token_hash(&self, token: &str) -> String {
        format!("token-hash:{token}")
    }
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}

impl nazo_auth::ClientSecretDigesterPort for RegistrationSecurity {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        format!("digest:{secret}:{pepper}:{salt}")
    }
}

impl nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationRequestGuard
    for RegistrationSecurity
{
    fn accepts_new_requests(&self) -> bool {
        true
    }
    fn enforce_rate_limit<'a>(
        &'a self,
        _source_ip: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationRateLimitError>,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async { Ok(()) })
    }
    fn audit(&self, _event: &'static str, _client: &nazo_auth::OAuthClient, _source_ip: &str) {}
}

fn cas_registration_endpoint(
    store: CasRegistrationStore,
    security: RegistrationSecurity,
) -> nazo_http_actix::DynamicRegistrationEndpoint {
    let application = Arc::new(nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationApplication::new(
        nazo_oauth_server::domain::dynamic_registration::DynamicRegistrationConfig {
            tenant: nazo_identity::TenantContext::default_system(),
            issuer: "https://issuer.example".to_owned(),
            default_audience: "https://api.example".to_owned(),
            pairwise_subject_secret: None,
            client_secret_pepper: "pepper".to_owned(),
            initial_access_token: Some("initial-token".to_owned()),
            rate_limit_window_seconds: 60,
            rate_limit_max_requests: 100,
            id_token_signing_algs: vec!["RS256", "PS256"],
            response_signing_algs: vec!["RS256", "PS256"],
            request_object_encryption_algs: vec!["RSA-OAEP-256"],
            request_object_encryption_encs: vec!["A256GCM"],
        },
        Arc::new(store),
        Arc::new(security.clone()),
        nazo_oauth_server::contracts::dynamic_client_registration::DynamicRegistrationSecurityServices::new(
            Arc::new(security.clone()),
            Arc::new(security.clone()),
            Arc::new(security.clone()),
            Arc::new(security.clone()),
        ),
        Arc::new(security),
    ));
    nazo_http_actix::DynamicRegistrationEndpoint::new(
        application,
        nazo_http_actix::ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
}

#[actix_web::test]
async fn framework_boundary_transport_dcr_put_cas_revokes_old_registration_token() {
    use actix_web::{App, test, web};
    let store = CasRegistrationStore::default();
    let endpoint = cas_registration_endpoint(store.clone(), RegistrationSecurity::default());
    let app = test::init_service(
        App::new()
            .app_data(Data::new(endpoint))
            .route(
                "/register",
                web::post().to(nazo_http_actix::dynamic_client_registration),
            )
            .service(
                web::resource("/register/{client_id}")
                    .route(web::put().to(nazo_http_actix::client_configuration_put))
                    .route(web::get().to(nazo_http_actix::client_configuration_get)),
            ),
    )
    .await;
    let created = test::call_service(&app, test::TestRequest::post().uri("/register")
        .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
        .set_json(json!({"grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body: Value = test::read_body_json(created).await;
    let client_id = created_body["client_id"].as_str().unwrap();
    let old_token = created_body["registration_access_token"].as_str().unwrap();
    let path = format!("/register/{client_id}");
    let identity = {
        let state = store.state.lock().unwrap();
        let client = state.0.as_ref().unwrap();
        (
            client.id,
            client.tenant_id,
            client.realm_id,
            client.organization_id,
        )
    };
    let updated = test::call_service(&app, test::TestRequest::put().uri(&path)
        .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
        .set_json(json!({"client_id":client_id,"client_name":"Updated Client","grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated_body: Value = test::read_body_json(updated).await;
    let new_token = updated_body["registration_access_token"].as_str().unwrap();
    assert_ne!(new_token, old_token);
    assert_eq!(updated_body["client_id"], client_id);
    assert_eq!(updated_body["client_name"], "Updated Client");
    assert_eq!(
        updated_body["registration_client_uri"],
        format!("https://issuer.example{path}")
    );
    assert_eq!(
        store.state.lock().unwrap().0.as_ref().unwrap().client_id,
        client_id
    );
    assert_eq!(
        store
            .state
            .lock()
            .unwrap()
            .0
            .as_ref()
            .unwrap()
            .client_name
            .as_str(),
        "Updated Client"
    );
    assert_eq!(
        store.state.lock().unwrap().1.as_deref(),
        Some(format!("token-hash:{new_token}").as_str())
    );
    assert_eq!(
        store.state.lock().unwrap().0.as_ref().unwrap().tenant_id,
        nazo_identity::TenantContext::default_system()
            .tenant_id
            .as_uuid()
    );
    let stale = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        test::read_body(stale).await.as_ref(),
        br#"{"error":"invalid_token","error_description":"Registration access token is missing or invalid."}"#
    );
    let current = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&path)
            .insert_header((header::AUTHORIZATION, format!("Bearer {new_token}")))
            .to_request(),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let current_body: Value = test::read_body_json(current).await;
    assert_eq!(current_body["client_id"], client_id);
    assert_eq!(current_body["client_name"], "Updated Client");
    assert_eq!(current_body["registration_access_token"], new_token);
    {
        let state = store.state.lock().unwrap();
        let client = state.0.as_ref().unwrap();
        assert_eq!(
            (
                client.id,
                client.tenant_id,
                client.realm_id,
                client.organization_id
            ),
            identity
        );
    }
    let calls = store.calls.lock().unwrap();
    assert_eq!(
        calls.as_slice(),
        &[
            "insert",
            "lookup",
            "has_secret",
            "replace_cas",
            "lookup",
            "lookup"
        ]
    );
    assert_eq!(
        store.state.lock().unwrap().1.as_deref(),
        Some(format!("token-hash:{new_token}").as_str())
    );
}

#[actix_web::test]
async fn framework_boundary_transport_dcr_put_stale_cas_preserves_registration() {
    use actix_web::{App, test, web};
    let store = CasRegistrationStore::default();
    let app = test::init_service(
        App::new()
            .app_data(Data::new(cas_registration_endpoint(
                store.clone(),
                RegistrationSecurity::default(),
            )))
            .route(
                "/register",
                web::post().to(nazo_http_actix::dynamic_client_registration),
            )
            .route(
                "/register/{client_id}",
                web::put().to(nazo_http_actix::client_configuration_put),
            ),
    )
    .await;
    let created = test::call_service(&app, test::TestRequest::post().uri("/register")
        .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
        .set_json(json!({"client_name":"Original Client","grant_types":["authorization_code"],"redirect_uris":["https://client.example/callback"],"scope":"profile"})).to_request()).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body: Value = test::read_body_json(created).await;
    let client_id = created_body["client_id"].as_str().unwrap();
    let old_token = created_body["registration_access_token"].as_str().unwrap();
    let before = format!("{:?}", store.state.lock().unwrap().0.as_ref().unwrap());
    let concurrent_hash = "token-hash:concurrently-rotated-token";
    *store.hash_after_authentication.lock().unwrap() = Some(concurrent_hash.to_owned());
    let rejected = test::call_service(&app, test::TestRequest::put().uri(&format!("/register/{client_id}"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {old_token}")))
        .set_json(json!({"client_id":client_id,"client_name":"Rejected Update","grant_types":["authorization_code"],"redirect_uris":["https://client.example/changed"],"scope":"profile"})).to_request()).await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(test::read_body(rejected).await.as_ref(), br#"{"error":"invalid_token","error_description":"Registration access token is missing or invalid."}"#);
    let state = store.state.lock().unwrap();
    assert_eq!(format!("{:?}", state.0.as_ref().unwrap()), before);
    assert_eq!(state.1.as_deref(), Some(concurrent_hash));
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &["insert", "lookup", "has_secret", "replace_cas"]
    );
}
mod real_userinfo_contract {
    use crate::test_support::{DatabaseUserFixture, TestInfrastructure};
    use actix_web::{
        HttpRequest, HttpResponse,
        http::{StatusCode, header},
        web::{Bytes, Data},
    };
    use chrono::{DateTime, Utc};
    use diesel::{
        sql_query,
        sql_types::{Bool, Text, Uuid as SqlUuid},
    };
    use diesel_async::RunQueryDsl;
    use nazo_auth::*;
    use nazo_identity::DEFAULT_ORGANIZATION_ID;
    use nazo_identity::DEFAULT_REALM_ID;
    use nazo_identity::DEFAULT_TENANT_ID;
    use nazo_identity::SubjectClaims;
    use nazo_oauth_server::domain::userinfo::{
        ServerUserinfoOperations, UserinfoConfig, UserinfoHandles,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    // Observe existing semantic ports; the production handler and business service are unchanged.
    struct ObservedRepository {
        inner: nazo_postgres::TokenIssuanceRepository,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }
    impl TokenRepositoryPort for ObservedRepository {
        fn access_token_revoked<'a>(&'a self, tenant: Uuid, jti: &'a str) -> TokenFuture<'a, bool> {
            self.calls.lock().unwrap().push("revocation");
            self.inner.access_token_revoked(tenant, jti)
        }
        fn active_subject_claims(
            &self,
            tenant: Uuid,
            user: Uuid,
        ) -> TokenFuture<'_, Option<SubjectClaims>> {
            self.calls.lock().unwrap().push("subject");
            self.inner.active_subject_claims(tenant, user)
        }
        fn client_by_protocol_id<'a>(
            &'a self,
            tenant: Uuid,
            client: &'a str,
        ) -> TokenFuture<'a, Option<OAuthClient>> {
            self.calls.lock().unwrap().push("client");
            self.inner.client_by_protocol_id(tenant, client)
        }
        fn validate_response_key_ring(&self) -> TokenFuture<'_, ()> {
            panic!("unexpected key-ring repository call")
        }
        fn commit_token_issuance<'a>(
            &'a self,
            _: CommitTokenIssuance,
        ) -> TokenFuture<'a, CommitTokenIssuanceResult> {
            panic!("unexpected issuance")
        }
        fn token_issuance_by_grant<'a>(
            &'a self,
            _: Uuid,
            _: Uuid,
            _: &'a str,
        ) -> TokenFuture<'a, Option<TokenIssuanceRecord>> {
            panic!("unexpected grant lookup")
        }
        fn refresh_token<'a>(
            &'a self,
            _: Uuid,
            _: &'a str,
        ) -> TokenFuture<'a, Option<RefreshToken>> {
            panic!("unexpected refresh lookup")
        }
        fn inspect_lost_response_successor<'a>(
            &'a self,
            _: &'a RefreshToken,
            _: Uuid,
            _: DateTime<Utc>,
        ) -> TokenFuture<'a, Option<RefreshToken>> {
            panic!("unexpected successor lookup")
        }
        fn revoke_issued_tokens<'a>(
            &'a self,
            _: Uuid,
            _: Uuid,
            _: &'a str,
            _: Option<DateTime<Utc>>,
            _: Option<Uuid>,
        ) -> TokenFuture<'a, ()> {
            panic!("unexpected token revocation")
        }
        fn refresh_family_active(&self, _: Uuid, _: Uuid, _: Uuid) -> TokenFuture<'_, bool> {
            panic!("unexpected refresh family lookup")
        }
        fn revoke_token<'a>(&'a self, _: TokenRevocation<'a>) -> TokenFuture<'a, usize> {
            panic!("unexpected revoke_token")
        }
    }

    struct NoDpopState;
    impl DpopStateStorePort for NoDpopState {
        fn consume_replay<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: u64,
        ) -> DpopStateFuture<'a, bool> {
            panic!("Bearer must not consume DPoP replay state")
        }
        fn issue_nonce<'a>(&'a self, _: &'a str, _: u64) -> DpopStateFuture<'a, ()> {
            panic!("Bearer must not issue a DPoP nonce")
        }
        fn validate_nonce<'a>(&'a self, _: &'a str) -> DpopStateFuture<'a, bool> {
            panic!("Bearer must not validate a DPoP nonce")
        }
    }

    async fn state() -> TestInfrastructure {
        let mut state = super::live_transport_state().await;
        let mut settings = (*state.settings).clone();
        settings.endpoint.trusted_proxy_cidrs =
            vec![nazo_http_actix::IpCidr::parse("127.0.0.1/32").unwrap()];
        state.settings = Arc::new(settings);
        state
    }

    fn endpoint(
        state: &TestInfrastructure,
        calls: Arc<Mutex<Vec<&'static str>>>,
    ) -> Data<nazo_http_actix::UserinfoEndpoint> {
        let token_state: Arc<dyn TokenStateStorePort> = Arc::new(
            nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        );
        let service = nazo_oauth_server::services::ServerTokenService::new(
            ObservedRepository {
                inner: nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
                calls,
            },
            token_state,
            state.keyset.clone(),
        );
        let handles = UserinfoHandles::new(
            Arc::new(NoDpopState),
            crate::http::authorization::test_support::test_security_audit_arc(),
            state.keyset.clone(),
            UserinfoConfig::new(
                state.settings.endpoint.issuer.as_str(),
                state.settings.protocol.default_audience.as_str(),
                state.settings.endpoint.mtls_endpoint_base_url.as_str(),
                state.settings.protocol.dpop_nonce_policy,
            ),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .unwrap(),
            ),
        );
        Data::new(nazo_http_actix::UserinfoEndpoint::new(
            Arc::new(ServerUserinfoOperations::new(Arc::new(service), handles)),
            Arc::new(crate::http::mtls::ServerMtlsThumbprintExtractor::new(
                state.settings.endpoint.trusted_proxy_cidrs.clone(),
            )),
        ))
    }

    fn request(token: &str, dpop: &str) -> HttpRequest {
        let mut request = actix_web::test::TestRequest::get()
            .uri("/userinfo")
            .app_data(Data::new(crate::http::mtls::MtlsCertificateSource::new(
                crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
            )))
            .peer_addr("127.0.0.1:12345".parse().unwrap())
            .insert_header(("client-cert", ":not-base64!:"))
            .insert_header((header::AUTHORIZATION, format!("Bearer {token}")));
        if !dpop.is_empty() {
            request = request.insert_header(("dpop", dpop));
        }
        request.to_http_request()
    }

    async fn signed_token(
        state: &TestInfrastructure,
        user: Uuid,
        client: &str,
        bound: bool,
    ) -> String {
        use crate::adapters::security::tokens::{AccessTokenJwtInput, make_jwt};
        make_jwt(
            &state.keyset,
            &state.settings.endpoint.issuer,
            AccessTokenJwtInput {
                tenant_id: DEFAULT_TENANT_ID,
                subject: &user.to_string(),
                user_id: Some(user),
                subject_type: "user",
                client_id: client,
                audiences: &["resource://default".to_owned()],
                scopes: &["openid".to_owned()],
                authorization_details: &json!([]),
                userinfo_claims: &[],
                userinfo_claim_requests: &[],
                ttl: 300,
                dpop_jkt: None,
                mtls_x5t_s256: bound.then_some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
                actor: None,
            },
        )
        .await
        .expect("real access token must sign")
        .token
    }

    async fn assert_error(response: HttpResponse, description: &str) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .map(|h| h.to_str().unwrap())
            .collect();
        assert_eq!(
            challenges,
            vec![format!(
                "Bearer error=\"invalid_token\", error_description=\"{description}\""
            )]
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(response.headers().get(header::LOCATION).is_none());
        assert!(response.headers().get("dpop-nonce").is_none());
        let bytes = actix_web::body::to_bytes(response.into_body())
            .await
            .unwrap();
        let golden =
            format!("{{\"error\":\"invalid_token\",\"error_description\":\"{description}\"}}");
        assert_eq!(bytes.as_ref(), golden.as_bytes());
    }

    #[actix_web::test]
    async fn invalid_token_precedes_malformed_certificate_without_repository_or_dpop_calls() {
        let state = state().await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let response = nazo_http_actix::userinfo(
            endpoint(&state, calls.clone()),
            request("not-a-jwt", "not-a-jwt"),
            Bytes::new(),
        )
        .await;
        assert_error(response, "Request failed.").await;
        assert!(
            calls.lock().unwrap().is_empty(),
            "invalid token must stop before revocation, subject and client ports"
        );
    }

    #[actix_web::test]
    async fn mtls_bound_token_rejects_malformed_certificate_before_subject_and_client_ports() {
        let state = state().await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let token = signed_token(&state, Uuid::now_v7(), "t00-unused-userinfo-client", true).await;
        let response = nazo_http_actix::userinfo(
            endpoint(&state, calls.clone()),
            request(&token, "not-a-jwt"),
            Bytes::new(),
        )
        .await;
        assert_error(
            response,
            "mTLS-bound access token requires a verified client certificate.",
        )
        .await;
        assert_eq!(*calls.lock().unwrap(), ["revocation"]);
    }

    async fn insert_subject_and_client(state: &TestInfrastructure, client: &str) -> Uuid {
        let mut conn = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        let user = sql_query(
            r#"
            INSERT INTO users (tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level)
            VALUES ($1, $2, $3, $4, $5, 'unused-t00-userinfo-hash', $6, false, true, 'user', 0)
            RETURNING *
        "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client)
        .bind::<Text, _>(format!("{client}@example.com"))
        .bind::<Bool, _>(true)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .unwrap();
        sql_query(r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
                tls_client_auth_san_ip, tls_client_auth_san_email,
                allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,
                require_par_request_object, is_active, security_policy,
                post_logout_redirect_uris, backchannel_logout_session_required)
            VALUES ($1, $2, $3, $4, 'T00 UserInfo Client', 'confidential',
                NULL, '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
                '["resource://default"]'::jsonb, '["authorization_code"]'::jsonb,
                'client_secret_post', false, false, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb, false, false, false, true,
                '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}'::jsonb,
                '[]'::jsonb, true)
        "#).bind::<SqlUuid, _>(DEFAULT_TENANT_ID).bind::<SqlUuid, _>(DEFAULT_REALM_ID)
            .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID).bind::<Text, _>(client)
            .execute(&mut conn).await.unwrap();
        user.id
    }

    #[actix_web::test]
    async fn unbound_bearer_ignores_malformed_dpop_and_certificate_and_returns_exact_claims() {
        let state = state().await;
        let client = format!("t00-userinfo-{}", Uuid::now_v7().simple());
        let user = insert_subject_and_client(&state, &client).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let token = signed_token(&state, user, &client, false).await;
        for dpop in ["not-a-jwt", "   "] {
            calls.lock().unwrap().clear();
            let response = nazo_http_actix::userinfo(
                endpoint(&state, calls.clone()),
                request(&token, dpop),
                Bytes::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).unwrap(),
                "no-store"
            );
            assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            assert_eq!(
                response.headers().get_all(header::WWW_AUTHENTICATE).count(),
                0
            );
            assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 0);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert!(response.headers().get("dpop-nonce").is_none());
            let bytes = actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap();
            // The random subject remains in the comparison; it is not deleted or normalized away.
            assert_eq!(bytes.as_ref(), format!("{{\"sub\":\"{user}\"}}").as_bytes());
            assert_eq!(*calls.lock().unwrap(), ["revocation", "subject", "client"]);
        }
        let mut conn = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(&client)
            .execute(&mut conn)
            .await
            .unwrap();
        sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user)
            .execute(&mut conn)
            .await
            .unwrap();
    }
}
mod fapi_signed_contract {
    use actix_web::{
        HttpRequest,
        body::to_bytes,
        http::{StatusCode, header},
        test::TestRequest,
        web::{Bytes, Data},
    };
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    use nazo_http_actix::*;
    use nazo_http_signatures::*;
    use nazo_oauth_server::contracts::fapi_resource::*;
    use nazo_resource_server::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug)]
    enum Outcome {
        Success,
        Revoked,
        SignatureReplay,
        LookupUnavailable,
        ChangedBody,
    }

    #[derive(Clone)]
    struct Ports {
        outcome: Outcome,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl nazo_http_actix::mtls::MtlsThumbprintExtractor for Ports {
        fn resolve(&self, _: &HttpRequest) -> Option<String> {
            self.calls.lock().unwrap().push("mtls");
            None
        }
    }
    impl FapiResourceAuthorizer for Ports {
        fn authorize<'a>(
            &'a self,
            request: ProtectedResourceAuthorizationRequest<'a>,
            context: ProtectedResourceAuthorizationContext<'a>,
        ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>>
        {
            self.calls.lock().unwrap().push("authorize");
            assert_eq!(request.access_token, "access-token");
            assert_eq!(context.method, "POST");
            assert_eq!(
                context.target_uris,
                &[
                    "https://issuer.example/fapi/resource",
                    "https://mtls.example/fapi/resource"
                ]
            );
            let outcome = self.outcome;
            Box::pin(async move {
                if matches!(outcome, Outcome::Revoked) {
                    return Err(FapiAuthorizationError::Protocol(
                        ProtectedResourceAuthorizationError::Revoked,
                    ));
                }
                Ok(ProtectedResourceAuthorizationResult {
                    token: VerifiedAccessToken {
                        issuer: "https://issuer.example".to_owned(),
                        subject: "subject-1".to_owned(),
                        tenant_id: Some("00000000-0000-0000-0000-000000000001".to_owned()),
                        client_id: "client-1".to_owned(),
                        audiences: vec!["resource-1".to_owned()],
                        scopes: vec!["openid".to_owned()],
                        jti: "token-jti".to_owned(),
                        exp: i64::MAX,
                        cnf: None,
                        authorization_details: serde_json::Value::Null,
                    },
                    sender_constraint: VerifiedSenderConstraintProof::default(),
                })
            })
        }
    }
    impl FapiHttpMessageSignatures for Ports {
        fn enabled(&self) -> bool {
            self.calls.lock().unwrap().push("enabled");
            true
        }
        fn verify_and_consume<'a>(
            &'a self,
            tenant: &'a str,
            client: &'a str,
            input: &'a VerifiedInput,
        ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
            self.calls.lock().unwrap().push("verify_and_consume");
            assert_eq!(tenant, "00000000-0000-0000-0000-000000000001");
            assert_eq!(client, "client-1");
            SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .verify(
                    input.signature_base(),
                    &Signature::from_slice(input.signature()).unwrap(),
                )
                .unwrap();
            let outcome = self.outcome;
            Box::pin(async move {
                match outcome {
                    Outcome::SignatureReplay => Err(FapiSignatureVerificationError::Replay),
                    Outcome::LookupUnavailable => {
                        Err(FapiSignatureVerificationError::LookupUnavailable)
                    }
                    Outcome::Success => Ok(()),
                    Outcome::Revoked | Outcome::ChangedBody => {
                        panic!("revoked authorization must not access signature state")
                    }
                }
            })
        }
        fn response_signature(
            &self,
        ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
            self.calls.lock().unwrap().push("response_signature");
            Ok(Arc::new(self.clone()))
        }
    }
    impl FapiResponseSignature for Ports {
        fn kid(&self) -> &str {
            "response-key"
        }
        fn algorithm(&self) -> &str {
            "ed25519"
        }
        fn sign<'a>(
            &'a self,
            base: &'a [u8],
        ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
            self.calls.lock().unwrap().push("sign");
            let signature = SigningKey::from_bytes(&[7; 32])
                .sign(base)
                .to_bytes()
                .to_vec();
            Box::pin(async move { Ok(signature) })
        }
    }

    #[actix_web::test]
    async fn real_fapi_authorization_and_signature_failures_preserve_signed_wire_and_port_order() {
        const TARGET: &str = "https://issuer.example/fapi/resource";
        const BODY: &[u8] = b"{\"signed\": true, \"space\":\"  \"}\n";
        for outcome in [
            Outcome::Success,
            Outcome::Revoked,
            Outcome::SignatureReplay,
            Outcome::LookupUnavailable,
            Outcome::ChangedBody,
        ] {
            let request_digest = content_digest(BODY);
            let request_headers = [
                ("authorization", "Bearer access-token"),
                ("content-digest", request_digest.as_str()),
                ("x-fapi-interaction-id", "t00-interaction"),
            ];
            let prepared = prepare_request(
                RequestInput {
                    method: "POST",
                    target_uri: TARGET,
                    headers: &request_headers,
                    body: BODY,
                },
                RequestPolicy {
                    created: chrono::Utc::now().timestamp(),
                    keyid: "client-key",
                    algorithm: "ed25519",
                    covered_headers: &[],
                },
            )
            .unwrap();
            let signature = SigningKey::from_bytes(&[3; 32]).sign(prepared.signature_base());
            let fields = prepared.finish(&signature.to_bytes());
            let calls = Arc::new(Mutex::new(Vec::new()));
            let ports = Arc::new(Ports {
                outcome,
                calls: calls.clone(),
            });
            let endpoint = Data::new(FapiResourceEndpoint::new(
                "https://issuer.example",
                "https://mtls.example",
                60,
                ports.clone(),
                ports.clone(),
                ports,
            ));
            let request = TestRequest::post()
                .uri("/fapi/resource")
                .insert_header((header::AUTHORIZATION, "Bearer access-token"))
                .insert_header(("content-digest", request_digest.as_str()))
                .insert_header(("x-fapi-interaction-id", "t00-interaction"))
                .insert_header(("signature-input", fields.signature_input.as_str()))
                .insert_header(("signature", fields.signature.as_str()))
                .to_http_request();
            const CHANGED: &[u8] = br#"{"signed":true,"space":"  "}"#;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(BODY).unwrap(),
                serde_json::from_slice::<serde_json::Value>(CHANGED).unwrap()
            );
            let sent = if matches!(outcome, Outcome::ChangedBody) {
                CHANGED
            } else {
                BODY
            };
            let response = fapi_resource(endpoint, request, Bytes::from_static(sent)).await;
            let (status, expected_body, challenge) = match outcome {
                Outcome::Success => (StatusCode::OK, br#"{"aud":"resource-1","client_id":"client-1","scope":"openid","sub":"subject-1"}"#.as_slice(), None),
                Outcome::Revoked => (StatusCode::UNAUTHORIZED, br#"{"error":"invalid_token","error_description":"Request failed."}"#.as_slice(), Some(r#"Bearer error="invalid_token", error_description="Request failed.""#)),
                Outcome::SignatureReplay => (StatusCode::UNAUTHORIZED, br#"{"error":"invalid_token","error_description":"HTTP message signature replay detected."}"#.as_slice(), Some(r#"Bearer error="invalid_token", error_description="HTTP message signature replay detected.""#)),
                Outcome::LookupUnavailable => (StatusCode::SERVICE_UNAVAILABLE, br#"{"error":"server_error","error_description":"Request failed."}"#.as_slice(), Some(r#"Bearer error="server_error", error_description="Request failed.""#)),
                Outcome::ChangedBody => (StatusCode::UNAUTHORIZED, br#"{"error":"invalid_token","error_description":"HTTP message signature is missing or invalid."}"#.as_slice(), Some(r#"Bearer error="invalid_token", error_description="HTTP message signature is missing or invalid.""#)),
            };
            assert_eq!(response.status(), status, "{outcome:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let challenges: Vec<_> = response
                .headers()
                .get_all(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(challenges, challenge.into_iter().collect::<Vec<_>>());
            assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 0);
            assert!(response.headers().get(header::LOCATION).is_none());
            assert_eq!(
                response.headers().get("content-digest").unwrap(),
                content_digest(expected_body).as_str()
            );
            if matches!(outcome, Outcome::Success) {
                assert_eq!(
                    response.headers().get("x-fapi-interaction-id").unwrap(),
                    "t00-interaction"
                );
                assert_eq!(
                    response.headers().get(header::CACHE_CONTROL).unwrap(),
                    "no-store"
                );
                assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
            }
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
            let headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                .collect();
            let headers_ref: Vec<_> = headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let body = to_bytes(response.into_body()).await.unwrap();
            assert_eq!(body.as_ref(), expected_body, "{outcome:?}");
            let original_headers: Vec<_> = request_headers
                .iter()
                .copied()
                .filter(|(name, _)| {
                    !matches!(outcome, Outcome::ChangedBody) || *name != "content-digest"
                })
                .collect();
            let verified = parse_response_for_verification(
                ResponseInput {
                    status: status.as_u16(),
                    headers: &headers_ref,
                    body: &body,
                },
                OriginalRequest {
                    input: RequestInput {
                        method: "POST",
                        target_uri: TARGET,
                        headers: &original_headers,
                        body: if matches!(outcome, Outcome::ChangedBody) {
                            b""
                        } else {
                            BODY
                        },
                    },
                    signature_fields: Some(&fields),
                },
                response_fields,
                VerificationPolicy {
                    now: chrono::Utc::now().timestamp(),
                    max_age_seconds: 60,
                    future_skew_seconds: 5,
                },
            )
            .unwrap();
            SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .verify(
                    verified.signature_base(),
                    &Signature::from_slice(verified.signature()).unwrap(),
                )
                .unwrap();
            assert_eq!(verified.keyid(), "response-key");
            assert_eq!(verified.algorithm(), "ed25519");
            let base = std::str::from_utf8(verified.signature_base()).unwrap();
            assert_eq!(
                base.contains(&request_digest),
                !matches!(outcome, Outcome::ChangedBody),
                "only a valid original digest may be bound"
            );
            let expected_calls: &[&str] = if matches!(outcome, Outcome::ChangedBody) {
                &["enabled", "response_signature", "sign"]
            } else if matches!(outcome, Outcome::Revoked) {
                &["enabled", "mtls", "authorize", "response_signature", "sign"]
            } else {
                &[
                    "enabled",
                    "mtls",
                    "authorize",
                    "verify_and_consume",
                    "response_signature",
                    "sign",
                ]
            };
            assert_eq!(
                calls.lock().unwrap().as_slice(),
                expected_calls,
                "{outcome:?}"
            );
        }
    }
}

mod ciba_device_contract {
    use crate::test_support::{
        ClientSigningFixture, TestInfrastructure, client_signing_fixture, valkey::valkey_set_ex,
    };
    use actix_web::{
        HttpRequest, HttpResponse,
        test::TestRequest,
        web::{Data, Form},
    };
    use chrono::Utc;
    use diesel::{
        sql_query,
        sql_types::{Bool, Text, Uuid as SqlUuid},
    };
    use diesel_async::RunQueryDsl;
    use nazo_auth::{CibaAuthenticationContext, CibaRequestState, CibaStatus};
    use nazo_identity::DEFAULT_ORGANIZATION_ID;
    use nazo_identity::DEFAULT_REALM_ID;
    use nazo_identity::DEFAULT_TENANT_ID;
    use nazo_oauth_server::contracts::token_forms::TokenForm;
    use nazo_oauth_server::domain::rows::ClientRow;
    use nazo_oauth_server::services::ServerCibaService;
    use nazo_oauth_server::services::ServerTokenService;
    use nazo_oauth_server::token::ciba::{
        CIBA_GRANT_TYPE, CibaTokenContext, CibaTokenHandles, token_ciba,
    };
    use nazo_oauth_server::token::issue::TokenIssuanceContext;
    use nazo_postgres::get_conn;
    use nazo_valkey::CibaStore;
    use serde_json::{Value, json};
    use std::sync::{Arc, OnceLock};
    use uuid::Uuid;
    fn ciba_token_form(auth_req_id: String) -> TokenForm {
        TokenForm {
            grant_type: CIBA_GRANT_TYPE.to_owned(),
            code: None,
            device_code: None,
            auth_req_id: Some(auth_req_id),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            device_secret: None,
            scope: None,
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
            assertion: None,
            requested_token_type: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audiences: Vec::new(),
            has_audience_param: false,
        }
    }

    async fn store_ciba_state(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: &str,
        status: CibaStatus,
    ) {
        store_ciba_state_with_user(state, client, auth_req_id, Uuid::now_v7(), status).await;
    }

    async fn store_ciba_state_with_user(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: &str,
        user_id: Uuid,
        status: CibaStatus,
    ) {
        let now = Utc::now().timestamp();
        let authentication_context = match status {
            CibaStatus::Approved => Some(CibaAuthenticationContext {
                auth_time: now,
                amr: vec!["pwd".to_owned()],
                oidc_sid: Some(format!("ciba-test-session-{user_id}")),
            }),
            CibaStatus::Pending | CibaStatus::Denied => None,
        };
        CibaStore::new(&state.valkey_connection())
            .create(
                auth_req_id,
                &CibaRequestState {
                    client_id: client.client_id.clone(),
                    user_id,
                    scopes: vec!["openid".to_owned()],
                    audiences: vec!["resource://default".to_owned()],
                    acr: None,
                    authentication_context,
                    binding_message: None,
                    issued_at: now,
                    status,
                    interval_seconds: 5,
                    expires_at: now + 600,
                    retention_expires_at: now + 720,
                    last_poll_at: None,
                    ping_notification: None,
                },
            )
            .await
            .expect("CIBA state should be stored");
    }

    async fn persist_ciba_test_client(state: &TestInfrastructure, client: &ClientRow) {
        nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
            .insert(client, None, None)
            .await
            .expect("CIBA test client should be persisted");
    }

    async fn insert_ciba_user(state: &TestInfrastructure, user_id: Uuid) {
        insert_ciba_user_with_email(state, user_id, &format!("ciba-user-{user_id}@example.test"))
            .await;
    }

    async fn insert_ciba_user_with_email(state: &TestInfrastructure, user_id: Uuid, email: &str) {
        let mut connection = get_conn(&state.diesel_db)
            .await
            .expect("CIBA test database connection should be available");
        sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(user_id)
            .execute(&mut connection)
            .await
            .expect("CIBA test user cleanup should succeed");
        sql_query(
            "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash,\
            is_active, mfa_enabled, email_verified, role, admin_level\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, TRUE, 'user', 0)",
        )
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(format!("ciba-user-{user_id}"))
        .bind::<Text, _>(email.to_owned())
        .bind::<Text, _>("ciba-test-password-hash")
        .bind::<Bool, _>(true)
        .execute(&mut connection)
        .await
        .expect("CIBA test user should insert");
    }

    fn ciba_test_mtls_certificate() -> &'static crate::test_support::Rfc9440CertificateFixture {
        static CERTIFICATE: OnceLock<crate::test_support::Rfc9440CertificateFixture> =
            OnceLock::new();
        CERTIFICATE.get_or_init(|| crate::test_support::rfc9440_certificate_fixture("ciba-test"))
    }

    fn configure_ciba_test_mtls_proxy(state: &mut TestInfrastructure) {
        let mut settings = (*state.settings).clone();
        settings.endpoint.trusted_proxy_cidrs = vec![
            nazo_http_actix::IpCidr::parse("127.0.0.1/32")
                .expect("trusted proxy CIDR should parse"),
        ];
        state.settings = Arc::new(settings);
    }

    async fn call_ciba_token_with_mtls_for_test(
        state: &TestInfrastructure,
        client: &ClientRow,
        auth_req_id: String,
    ) -> HttpResponse {
        let certificate = ciba_test_mtls_certificate();
        let req = actix_web::test::TestRequest::post()
            .uri("/token")
            .app_data(actix_web::web::Data::new(
                crate::http::mtls::MtlsCertificateSource::new(
                    crate::http::mtls::MtlsCertificateSourceMode::Rfc9440,
                ),
            ))
            .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
            .insert_header(("client-cert", certificate.header.as_str()))
            .to_http_request();
        call_ciba_token_with_request_for_test(state, client, auth_req_id, req).await
    }

    fn ciba_private_key_jwt_client_with_alg(
        kid: &str,
        fixture: &ClientSigningFixture,
    ) -> ClientRow {
        let public_jwk = fixture.public_jwk(kid);
        let mut client = client_row! {
            id: Uuid::now_v7(),
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
            client_id: "client-1".to_owned(),
            client_name: "CIBA Client".to_owned(),
            client_type: "confidential".to_owned(),
            client_secret_hash: None,
            redirect_uris: json!(["https://client.example/callback"]),
            scopes: json!(["openid", "profile", "email", "offline_access"]),
            allowed_audiences: json!(["resource://default"]),
            grant_types: json!([CIBA_GRANT_TYPE, "refresh_token"]),
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
            backchannel_logout_session_required: true,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: true,
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
        };
        client.security_policy.allow_cross_device_flows = true;
        client
    }

    async fn store_device_session(state: &TestInfrastructure, session_id: &str, user_id: Uuid) {
        let payload = nazo_oauth_server::sessions::SessionPayload {
            user_id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("device-oidc-{session_id}")),
        };
        valkey_set_ex(
            &state.valkey,
            nazo_valkey::test_support::state_storage_key(format!("oauth:session:{session_id}")),
            serde_json::to_string(&payload).expect("device session should serialize"),
            state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("device session should store");
    }

    async fn call_ciba_token_with_request_for_test(
        state: &TestInfrastructure,
        client: &ClientRow,
        id: String,
        req: HttpRequest,
    ) -> HttpResponse {
        let connection = state.valkey_connection();
        let token_service = ServerTokenService::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
            Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
            state.keyset.clone(),
        );
        let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
        let modules = state.active_module_snapshot();
        let authorization =
            crate::http::token::issue::test_support::test_authorization_service(state);
        let issuance = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        let handles = CibaTokenHandles::new(
            Arc::new(ServerCibaService::new(Arc::new(CibaStore::new(
                &connection,
            )))),
            Arc::new(nazo_postgres::UserRepository::new(state.diesel_db.clone())),
            Arc::new(crate::http::token::ciba::ciba_config(
                state.settings.as_ref(),
            )),
        );
        let client_ip = nazo_http_actix::ClientIpConfig::new(
            &state.settings.endpoint.trusted_proxy_cidrs,
            state.settings.endpoint.client_ip_header_mode,
        );
        let facts = crate::http::token::dispatch::token_request_facts(&req, &client_ip);
        present_token_result(
            token_ciba(
                CibaTokenContext {
                    token_service: &token_service,
                    issuance: &issuance,
                    handles: &handles,
                    request: &facts,
                },
                client,
                &ciba_token_form(id),
                None,
                "private_key_jwt",
            )
            .await,
        )
    }

    fn present_token_result(
        result: Result<
            nazo_oauth_server::contracts::token_endpoint::TokenEndpointSuccess,
            nazo_oauth_server::contracts::oauth_error::OAuthEndpointError,
        >,
    ) -> HttpResponse {
        match result {
            Ok(success) => nazo_http_actix::token_endpoint_success_response(success),
            Err(error) => nazo_http_actix::oauth_endpoint_error_response(error),
        }
    }

    #[derive(Debug)]
    struct Wire {
        status: u16,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    }
    async fn wire(response: HttpResponse) -> Wire {
        let status = response.status().as_u16();
        let mut headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        headers.sort();
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("body bytes")
            .to_vec();
        Wire {
            status,
            headers,
            body,
        }
    }
    fn json_headers(no_store: bool, pragma: bool) -> Vec<(String, Vec<u8>)> {
        let mut headers = vec![("content-type".to_owned(), b"application/json".to_vec())];
        if no_store {
            headers.push(("cache-control".to_owned(), b"no-store".to_vec()));
        }
        if pragma {
            headers.push(("pragma".to_owned(), b"no-cache".to_vec()));
        }
        headers.sort();
        headers
    }
    async fn token_error(response: HttpResponse, expected: &[u8]) {
        let actual = wire(response).await;
        assert_eq!(actual.status, 400, "{actual:?}");
        assert_eq!(actual.headers, json_headers(true, true));
        assert_eq!(actual.body, expected);
    }
    fn verify_jwt(state: &TestInfrastructure, token: &str, audience: &str, subject: &str) -> Value {
        let header = jsonwebtoken::decode_header(token).expect("issued compact JWT header");
        assert_ne!(header.alg, jsonwebtoken::Algorithm::HS256);
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_value(state.keyset.snapshot().jwks())
                .expect("server verification JWKS");
        let jwk = jwks
            .find(header.kid.as_deref().expect("issued JWT kid"))
            .expect("issued kid belongs to keyset");
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk).expect("public decoding key");
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.leeway = 0;
        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .expect("issued JWT signature and claims")
            .claims;
        assert_eq!(claims["sub"], subject);
        let now = Utc::now().timestamp();
        let iat = claims["iat"].as_i64().expect("iat integer");
        let exp = claims["exp"].as_i64().expect("exp integer");
        assert!(iat <= now && now - iat <= 60);
        assert!(exp > now && exp > iat);
        claims
    }
    async fn ciba_fixture() -> (TestInfrastructure, ClientRow) {
        let mut state = super::live_transport_state().await;
        configure_ciba_test_mtls_proxy(&mut state);
        state.keyset =
            crate::test_support::test_key_manager_with_auxiliary(jsonwebtoken::Algorithm::PS256);
        let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
        let mut client = ciba_private_key_jwt_client_with_alg("golden-ciba", &key);
        client.client_id = format!("golden-ciba-{}", client.id);
        client.require_mtls_bound_tokens = true;
        persist_ciba_test_client(&state, &client).await;
        (state, client)
    }
    #[actix_web::test]
    async fn real_ciba_pending_slow_down_terminal_and_single_use_replay_wire() {
        let (state, client) = ciba_fixture().await;
        let pending = format!("golden-pending-{}", Uuid::now_v7());
        store_ciba_state(&state, &client, &pending, CibaStatus::Pending).await;
        token_error(call_ciba_token_with_mtls_for_test(&state, &client, pending.clone()).await, br#"{"error":"authorization_pending","error_description":"CIBA authorization is pending."}"#).await;
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, pending).await,
            br#"{"error":"slow_down","error_description":"CIBA polling too fast."}"#,
        )
        .await;
        let denied = format!("golden-denied-{}", Uuid::now_v7());
        store_ciba_state(&state, &client, &denied, CibaStatus::Denied).await;
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, denied).await,
            br#"{"error":"access_denied","error_description":"CIBA authorization was denied."}"#,
        )
        .await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let approved = format!("golden-approved-{}", Uuid::now_v7());
        store_ciba_state_with_user(&state, &client, &approved, user, CibaStatus::Approved).await;
        let first =
            wire(call_ciba_token_with_mtls_for_test(&state, &client, approved.clone()).await).await;
        assert_eq!(first.status, 200, "{first:?}");
        assert_eq!(first.headers, json_headers(true, true));
        let body: Value = serde_json::from_slice(&first.body).expect("token JSON");
        let access = verify_jwt(
            &state,
            body["access_token"].as_str().expect("access token"),
            "resource://default",
            &user.to_string(),
        );
        assert_eq!(
            access["cnf"]["x5t#S256"],
            ciba_test_mtls_certificate().thumbprint
        );
        assert_eq!(access["client_id"], client.client_id);
        assert_eq!(
            access["exp"].as_i64().unwrap() - access["iat"].as_i64().unwrap(),
            body["expires_in"].as_i64().unwrap()
        );
        let id = verify_jwt(
            &state,
            body["id_token"].as_str().expect("id token"),
            &client.client_id,
            &user.to_string(),
        );
        assert_eq!(id["amr"], json!(["pwd"]));
        assert!(id["auth_time"].as_i64().is_some());
        assert!(body.get("refresh_token").is_none());
        assert!(
            CibaStore::load(&CibaStore::new(&state.valkey_connection()), &approved)
                .await
                .expect("post issuance state")
                .is_none()
        );
        token_error(
            call_ciba_token_with_mtls_for_test(&state, &client, approved).await,
            br#"{"error":"invalid_grant","error_description":"CIBA auth_req_id is expired."}"#,
        )
        .await;
    }

    #[actix_web::test]
    async fn real_device_decision_csrf_session_preserve_state_then_deny_wire() {
        use crate::http::token::device::{DeviceDecisionForm, device_decision};
        use crate::http::token::device_config::DeviceHttpConfig;
        use nazo_oauth_server::services::ServerDeviceGrantService;
        use nazo_oauth_server::token::device::DeviceDecisionHandles;
        let state = super::live_transport_state().await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let sid = format!("golden-session-{}", Uuid::now_v7());
        store_device_session(&state, &sid, user).await;
        let now = Utc::now();
        let payload = nazo_auth::DeviceAuthorizationPayload {
            client_id: format!("golden-device-{}", Uuid::now_v7()),
            client_name: "Golden Device".into(),
            scopes: vec!["openid".into()],
            resource_indicators: vec!["resource://default".into()],
            authorization_details: json!([]),
            interval_seconds: 5,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(10),
        };
        let service = ServerDeviceGrantService::new(Arc::new(nazo_valkey::DeviceStore::new(
            &state.valkey_connection(),
        )));
        let device_code = format!("golden-device-code-{}", Uuid::now_v7());
        let user_code = format!("GOLDEN{}", Uuid::now_v7().simple()).to_uppercase();
        let (_, code) = service
            .create_unique(&payload, 600, || device_code.clone(), || user_code.clone())
            .await
            .expect("device persisted");
        let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
            state.diesel_db.clone(),
            state.settings.as_ref(),
        )
        .expect("runtime");
        let sessions =
            Data::new(crate::http::sessions::test_support::profile_session_handles(&state));
        let config = Data::new(DeviceHttpConfig::from(state.settings.as_ref()));
        let rate_limit = &state.settings.identity.rate_limit;
        let handles = Data::new(DeviceDecisionHandles::new(
            Arc::new(crate::http::token::issue::test_support::test_authorization_service(&state)),
            Arc::new(service),
            Arc::new(nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            )),
            Arc::new(
                crate::http::token::device_config::device_config_from_settings(
                    state.settings.as_ref(),
                ),
            ),
            runtime.snapshot_store(),
            Arc::new(
                crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                    .expect("empty resolver should build"),
            ),
            Arc::new(
                nazo_oauth_server::rate_limit::TokenManagementRequestLimiter::new(
                    Arc::new(nazo_valkey::RateLimitStore::new(&state.valkey_connection())),
                    rate_limit.window_seconds,
                    rate_limit.token_management_max_requests,
                ),
            ),
            Arc::new(crate::adapters::audit::TenantSecurityAudit::new(
                state.settings.tenant.context.tenant_id,
            )),
        ));
        let check_state = ServerDeviceGrantService::new(Arc::new(nazo_valkey::DeviceStore::new(
            &state.valkey_connection(),
        )));
        let before = serde_json::to_value(
            check_state
                .pending_request_for_user_code(&code, Utc::now)
                .await
                .expect("read pending"),
        )
        .unwrap();
        for (session, csrf, expected_status) in [
            (true, None, 400),
            (true, Some("wrong"), 400),
            (false, Some("golden-csrf"), 401),
            (true, Some("golden-csrf"), 200),
        ] {
            let mut request = TestRequest::post().uri("/device/decision");
            if session {
                request = request.cookie(actix_web::cookie::Cookie::new(
                    state.settings.session.session_cookie_name.clone(),
                    sid.clone(),
                ));
            }
            request = request.cookie(actix_web::cookie::Cookie::new(
                state.settings.session.csrf_cookie_name.clone(),
                "golden-csrf",
            ));
            let form: DeviceDecisionForm = serde_json::from_value(
                json!({"user_code":code,"decision":"deny","csrf_token":csrf}),
            )
            .expect("device form");
            let response = wire(
                device_decision(
                    handles.clone(),
                    sessions.clone(),
                    config.clone(),
                    request.to_http_request(),
                    Form(form),
                )
                .await,
            )
            .await;
            assert_eq!(response.status, expected_status, "{response:?}");
            if expected_status == 400 {
                assert_eq!(response.headers, json_headers(false, false));
                assert_eq!(
                    response.body,
                    br#"{"error":"invalid_request","error_description":"Request failed."}"#
                );
            } else if expected_status == 401 {
                assert_eq!(
                    response.body,
                    br#"{"error":"login_required","error_description":"Request failed."}"#
                );
                assert_eq!(
                    response
                        .headers
                        .iter()
                        .filter(|(k, _)| k != "set-cookie")
                        .cloned()
                        .collect::<Vec<_>>(),
                    json_headers(false, false)
                );
                let cookies: Vec<_> = response
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "set-cookie")
                    .collect();
                assert_eq!(cookies.len(), 2);
                for name in [
                    &state.settings.session.session_cookie_name,
                    &state.settings.session.csrf_cookie_name,
                ] {
                    let raw = cookies
                        .iter()
                        .find(|(_, v)| v.starts_with(format!("{name}=").as_bytes()))
                        .expect("clearing cookie");
                    let cookie =
                        actix_web::cookie::Cookie::parse(std::str::from_utf8(&raw.1).unwrap())
                            .unwrap();
                    assert_eq!(cookie.value(), "");
                    assert_eq!(cookie.path(), Some("/"));
                    assert_eq!(cookie.http_only(), Some(true));
                    assert_eq!(cookie.same_site(), Some(actix_web::cookie::SameSite::Lax));
                    assert_eq!(
                        cookie.secure().unwrap_or(false),
                        state.settings.session.cookie_secure
                    );
                    assert_eq!(cookie.max_age().unwrap().whole_seconds(), 0);
                    assert!(
                        cookie
                            .expires_datetime()
                            .expect("removal expiry")
                            .unix_timestamp()
                            < Utc::now().timestamp()
                    );
                }
            } else {
                assert!(response.headers.is_empty());
                assert!(response.body.is_empty());
            }
            let after = serde_json::to_value(
                check_state
                    .pending_request_for_user_code(&code, Utc::now)
                    .await
                    .expect("read after decision"),
            )
            .unwrap();
            if expected_status != 200 {
                assert_eq!(
                    after, before,
                    "rejected browser request must not consume device state"
                );
            } else {
                assert!(after.is_null());
            }
        }
    }
    #[actix_web::test]
    async fn real_persisted_idempotent_issuance_raw_bytes_and_header_difference() {
        use nazo_auth::{TokenIssuanceMode, TokenRepositoryPort};
        use nazo_oauth_server::token::issue::issue_token_response;
        let (state, client) = ciba_fixture().await;
        let user = Uuid::now_v7();
        insert_ciba_user(&state, user).await;
        let connection = state.valkey_connection();
        let repository = crate::test_support::token_issuance_repository(state.diesel_db.clone());
        let service = ServerTokenService::new(
            crate::test_support::token_issuance_repository(state.diesel_db.clone()),
            Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(&connection)),
            state.keyset.clone(),
        );
        let config = crate::http::token::issue::token_issuance_config(state.settings.as_ref());
        let modules = state.active_module_snapshot();
        let authorization =
            crate::http::token::issue::test_support::test_authorization_service(&state);
        let context = TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
            security_audit: crate::http::authorization::test_support::test_security_audit(),
            remote_client_documents: crate::test_support::test_remote_client_documents(),
        };
        let grant = format!("golden-idempotent-{}", Uuid::now_v7());
        let auth_time = Utc::now().timestamp();
        let issue = || nazo_oauth_server::domain::oauth::TokenIssue {
            user_id: Some(user),
            subject: user.to_string(),
            scopes: vec!["openid".into()],
            authorization_details: json!([]),
            audiences: vec!["resource://default".into()],
            nonce: None,
            auth_time: Some(auth_time),
            amr: vec!["pwd".into()],
            oidc_sid: Some(format!("golden-idempotent-{user}")),
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            refresh_id_token_sid: None,
            include_refresh: false,
            refresh_token_policy:
                nazo_oauth_server::domain::oauth::RefreshTokenPolicy::PreserveExisting,
            dpop_jkt: None,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256: Some(ciba_test_mtls_certificate().thumbprint.clone()),
            refresh_token_mtls_x5t_s256: None,
            refresh_token_client_attestation_jkt: None,
            refresh_token_scopes: None,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        };
        let first = wire(present_token_result(
            issue_token_response(
                &context,
                &service,
                &client,
                TokenIssuanceMode::Idempotent {
                    grant_key: grant.clone(),
                },
                issue(),
            )
            .await,
        ))
        .await;
        assert_eq!(first.status, 200, "{first:?}");
        assert_eq!(first.headers, json_headers(true, true));
        let record = repository
            .token_issuance_by_grant(DEFAULT_TENANT_ID, client.id, &grant)
            .await
            .expect("persisted issuance lookup")
            .expect("issuance exists");
        assert_eq!(
            record
                .response_body
                .as_deref()
                .expect("durable response bytes"),
            first.body.as_slice()
        );
        let replay = wire(present_token_result(
            issue_token_response(
                &context,
                &service,
                &client,
                TokenIssuanceMode::Idempotent { grant_key: grant },
                issue(),
            )
            .await,
        ))
        .await;
        assert_eq!(replay.status, 200, "{replay:?}");
        assert_eq!(replay.headers, json_headers(true, false));
        assert_eq!(replay.body, first.body);
        let body: Value = serde_json::from_slice(&first.body).expect("issuance response JSON");
        let access = verify_jwt(
            &state,
            body["access_token"].as_str().unwrap(),
            "resource://default",
            &user.to_string(),
        );
        assert_eq!(
            access["cnf"]["x5t#S256"],
            ciba_test_mtls_certificate().thumbprint
        );
        assert_eq!(
            access["exp"].as_i64().unwrap() - access["iat"].as_i64().unwrap(),
            body["expires_in"].as_i64().unwrap()
        );
        let id = verify_jwt(
            &state,
            body["id_token"].as_str().unwrap(),
            &client.client_id,
            &user.to_string(),
        );
        assert_eq!(id["auth_time"], auth_time);
        assert_eq!(id["amr"], json!(["pwd"]));
    }
}

mod authorization_contract {
    use super::live_transport_state;
    use crate::http::authorization::AuthorizationEndpoint;
    use crate::test_support::TestInfrastructure;
    use actix_web::{
        body::to_bytes,
        http::{StatusCode, header},
        test::TestRequest,
        web::{Bytes, Data},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use diesel::sql_query;
    use diesel::sql_types::{Text, Uuid as SqlUuid};
    use diesel_async::RunQueryDsl;
    use nazo_valkey::test_support::KeysInterface;
    use serde_json::{Value, json};

    const CALLBACK: &str = "https://client.example/callback";

    fn endpoint(state: &TestInfrastructure) -> Data<AuthorizationEndpoint> {
        let dependencies =
            crate::http::authorization::test_support::TestAuthorizationDependencies::new(state);
        Data::new(dependencies.endpoint())
    }
    async fn client(
        state: &TestInfrastructure,
        jwks: Option<Value>,
    ) -> (nazo_auth::OAuthClient, String) {
        let request = serde_json::from_value(json!({
            "client_name": format!("T00 authorization {}", uuid::Uuid::now_v7()),
            "client_type": "confidential", "redirect_uris": [CALLBACK],
            "scopes": ["openid"], "allowed_audiences": ["resource://one", "resource://two"],
            "grant_types": ["authorization_code"], "token_endpoint_auth_method": "client_secret_post",
            "jwks": jwks
        })).expect("registration request");
        let resolver =
            crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(&[])
                .expect("resolver");
        let prepared = nazo_auth::prepare_client_registration(
            request,
            &nazo_auth::AdminClientPolicy {
                tenant: state.settings.tenant.context,
                pairwise_subject_secret: None,
                client_secret_pepper: state.settings.protocol.client_secret_pepper.clone(),
            },
            &resolver,
            &nazo_key_management::ClientRegistrationCrypto::new(state.keyset.clone()),
        )
        .await
        .expect("prepare real registration");
        let secret = prepared
            .issued_secret
            .clone()
            .expect("confidential client secret");
        let client = nazo_auth::insert_prepared_client(
            &nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            &prepared,
        )
        .await
        .expect("persist client");
        (client, secret)
    }

    async fn authorized_response(
        state: &TestInfrastructure,
        client: &nazo_auth::OAuthClient,
        response_mode: &str,
        state_value: &str,
    ) -> actix_web::HttpResponse {
        let user_id = uuid::Uuid::now_v7();
        let sid = format!("t00-auth-{user_id}");
        let now = chrono::Utc::now().timestamp();
        let mut connection = nazo_postgres::get_conn(&state.diesel_db)
            .await
            .expect("authorization fixture DB connection");
        sql_query(
            "INSERT INTO users (id, tenant_id, realm_id, organization_id, username, email, \
             password_hash, is_active, mfa_enabled, email_verified, role, admin_level) \
             VALUES ($1, $2, $3, $4, $5, $6, 't00-auth-fixture', TRUE, FALSE, TRUE, 'user', 0)",
        )
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(nazo_identity::DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(nazo_identity::DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(nazo_identity::DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(format!("t00-auth-{user_id}"))
        .bind::<Text, _>(format!("t00-auth-{user_id}@example.test"))
        .execute(&mut connection)
        .await
        .expect("authorization fixture user insert");
        sql_query(
            "INSERT INTO user_client_grants (tenant_id, user_id, client_id, first_authorized_at, \
             last_authorized_at, last_scopes, last_authorization_details, authorization_count) \
             VALUES ($1, $2, $3, now(), now(), '[\"openid\"]'::jsonb, '[]'::jsonb, 1)",
        )
        .bind::<SqlUuid, _>(nazo_identity::DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .expect("authorization fixture grant insert");
        drop(connection);
        let payload = nazo_oauth_server::sessions::SessionPayload {
            user_id,
            auth_time: now,
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        crate::test_support::valkey::valkey_set_ex(
            &state.valkey,
            nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}")),
            serde_json::to_string(&payload).expect("session serializes"),
            state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("authorization fixture session insert");
        let challenge = "A".repeat(43);
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", client.client_id.as_str()),
                ("response_type", "code"),
                ("redirect_uri", CALLBACK),
                ("scope", "openid"),
                ("state", state_value),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
                ("response_mode", response_mode),
            ])
            .finish();
        crate::http::authorization::request::authorize_get(
            endpoint(state),
            TestRequest::get()
                .uri(&format!("/oauth/authorize?{query}"))
                .cookie(actix_web::cookie::Cookie::new(
                    state.settings.session.session_cookie_name.clone(),
                    sid,
                ))
                .to_http_request(),
        )
        .await
    }

    #[actix_web::test]
    async fn t00_par_repeated_resources_ignore_repeated_extensions_and_persist_exact_fields() {
        let state = live_transport_state().await;
        let (client, secret) = client(&state, None).await;
        let endpoint = endpoint(&state);
        let challenge = "A".repeat(43);
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", client.client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("response_type", "code"),
                ("redirect_uri", CALLBACK),
                ("scope", "openid"),
                ("state", "state<&\""),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("resource", "resource://one"),
                ("resource", "resource://two"),
                ("unknown_extension", "first"),
                ("unknown_extension", "second"),
            ])
            .finish();
        let before = chrono::Utc::now();
        let response = crate::http::authorization::par::par(
            endpoint,
            TestRequest::post()
                .uri("/oauth/par")
                .peer_addr("198.51.100.201:21001".parse().unwrap())
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .to_http_request(),
            Bytes::from(form),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let bytes = to_bytes(response.into_body()).await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let uri = value["request_uri"].as_str().unwrap();
        let token = uri
            .strip_prefix("urn:ietf:params:oauth:request_uri:")
            .expect("PAR URI namespace");
        assert!(URL_SAFE_NO_PAD.decode(token).unwrap().len() >= 32);
        let ttl = state.settings.protocol.par_ttl_seconds;
        assert_eq!(
            bytes.as_ref(),
            format!("{{\"expires_in\":{ttl},\"request_uri\":\"{uri}\"}}").as_bytes()
        );
        let key = nazo_valkey::test_support::par_storage_key(uri);
        let raw: String = state.valkey.get(&key).await.expect("persisted raw PAR");
        let stored: Value = serde_json::from_str(&raw).unwrap();
        let issued: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(stored["issued_at"].clone()).unwrap();
        let expires: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(stored["expires_at"].clone()).unwrap();
        assert!(issued >= before && issued <= chrono::Utc::now());
        assert_eq!(expires - issued, chrono::Duration::seconds(ttl as i64));
        assert_eq!(
            stored,
            json!({"client_id": client.client_id, "params": {
            "client_id": client.client_id, "response_type": "code", "redirect_uri": CALLBACK,
            "scope": "openid", "state": "state<&\"", "code_challenge": challenge,
            "code_challenge_method": "S256", "resource": "nazo-internal-resource-set:[\"resource://one\",\"resource://two\"]"
        }, "issued_at": issued, "expires_at": expires})
        );
        let remaining: i64 = state.valkey.ttl(&key).await.unwrap();
        assert!(remaining > 0 && remaining <= ttl as i64);
    }

    #[actix_web::test]
    async fn t00_par_duplicate_body_is_rejected_before_unknown_client_lookup() {
        let state = live_transport_state().await;
        let rate_key = nazo_valkey::test_support::state_storage_key(format!(
            "oauth:rate:token_management:{}",
            nazo_oauth_server::crypto::blake3_hex("198.51.100.202")
        ));
        let previous: Option<u64> = state.valkey.get(&rate_key).await.unwrap();
        let response = crate::http::authorization::par::par(
            endpoint(&state),
            TestRequest::post()
                .peer_addr("198.51.100.202:21002".parse().unwrap())
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .to_http_request(),
            Bytes::from_static(b"client_id=not-registered&client_id=not-registered"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));
        assert_eq!(
            to_bytes(response.into_body()).await.unwrap().as_ref(),
            "{\"error\":\"invalid_request\",\"error_description\":\"Request failed.\"}".as_bytes()
        );
        let current: u64 = state.valkey.get(&rate_key).await.unwrap();
        assert_eq!(current, previous.unwrap_or_default() + 1);
        let rate_ttl: i64 = state.valkey.ttl(&rate_key).await.unwrap();
        assert!(
            rate_ttl > 0 && rate_ttl <= state.settings.identity.rate_limit.window_seconds as i64
        );
    }

    #[actix_web::test]
    async fn t00_jar_invalid_unsigned_and_tampered_objects_never_redirect_to_attacker() {
        let state = live_transport_state().await;
        let signer = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
        let (client, _) = client(
            &state,
            Some(json!({"keys": [signer.public_jwk("t00-jar")]})),
        )
        .await;
        let endpoint = endpoint(&state);
        let now = chrono::Utc::now().timestamp();
        let claims = json!({"iss": client.client_id, "client_id": client.client_id, "aud": "https://issuer.example",
            "iat": now, "exp": now + 90, "jti": uuid::Uuid::now_v7(), "response_type": "code",
            "redirect_uri": "https://attacker.example/steal", "scope": "openid"});
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let mut signing_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        signing_header.kid = Some("t00-jar".to_owned());
        let mut original = claims.clone();
        original["redirect_uri"] = json!(CALLBACK);
        let signed = signer.encode_jwt(&signing_header, &original);
        let parts: Vec<_> = signed.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            parts[2]
        );
        for object in ["not-a-jwt".to_owned(), unsigned, tampered] {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("client_id", client.client_id.as_str()),
                    ("request", object.as_str()),
                    ("response_type", "code"),
                    ("redirect_uri", CALLBACK),
                ])
                .finish();
            let response = crate::http::authorization::request::authorize_get(
                endpoint.clone(),
                TestRequest::get()
                    .uri(&format!("/oauth/authorize?{query}"))
                    .to_http_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(
                response.headers().get(header::LOCATION).unwrap(),
                "https://client.example/callback?error=invalid_request_object&iss=https%3A%2F%2Fissuer.example"
            );
            assert!(to_bytes(response.into_body()).await.unwrap().is_empty());
        }
    }

    #[actix_web::test]
    async fn t00_jarm_signature_and_all_claims_are_bound_to_database_client() {
        let state = live_transport_state().await;
        let (client, _) = client(&state, None).await;
        let before = chrono::Utc::now().timestamp();
        let response = authorized_response(&state, &client, "jwt", "golden-state").await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = url::Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            location.origin().ascii_serialization(),
            "https://client.example"
        );
        assert_eq!(location.path(), "/callback");
        let pairs: Vec<_> = location.query_pairs().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "response");
        let token = pairs[0].1.as_ref();
        let header = jsonwebtoken::decode_header(token).unwrap();
        assert_eq!(header.alg, state.keyset.snapshot().active_alg);
        assert_eq!(header.typ.as_deref(), Some("oauth-authz-resp+jwt"));
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_value(state.keyset.snapshot().jwks()).unwrap();
        let key = jwks
            .find(header.kid.as_deref().expect("signing kid"))
            .expect("published verification key");
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_issuer(&["https://issuer.example"]);
        validation.set_audience(&[&client.client_id]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        let decoded = jsonwebtoken::decode::<Value>(
            token,
            &jsonwebtoken::DecodingKey::from_jwk(key).unwrap(),
            &validation,
        )
        .expect("real JARM signature and claims");
        let claims = decoded.claims;
        let code = claims["code"].as_str().expect("real authorization code");
        assert!(!code.is_empty());
        let issued = claims["iat"].as_i64().unwrap();
        assert!(issued >= before && issued <= chrono::Utc::now().timestamp());
        let jti = claims["jti"].as_str().unwrap();
        assert_eq!(uuid::Uuid::parse_str(jti).unwrap().get_version_num(), 7);
        assert_eq!(
            claims,
            json!({"iss": "https://issuer.example", "aud": client.client_id,
            "iat": issued, "nbf": issued, "exp": issued + state.settings.protocol.auth_code_ttl_seconds as i64,
            "jti": jti, "code": code, "state": "golden-state"})
        );
        assert!(to_bytes(response.into_body()).await.unwrap().is_empty());
    }

    #[actix_web::test]
    async fn t00_form_post_exact_document_and_security_headers_bind_observed_nonce() {
        let state = live_transport_state().await;
        let (client, _) = client(&state, None).await;
        let response = authorized_response(&state, &client, "form_post", "state<&\"'").await;
        assert_eq!(response.status(), StatusCode::OK);
        for (name, value) in [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("referrer-policy", "no-referrer"),
            ("x-frame-options", "DENY"),
        ] {
            assert_eq!(response.headers().get(name).unwrap(), value);
        }
        assert!(!response.headers().contains_key(header::LOCATION));
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let nonce = csp.strip_prefix("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action https://client.example; script-src 'nonce-")
            .and_then(|tail| tail.strip_suffix('\'')).expect("exact CSP structure");
        assert!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len() >= 32);
        let body = to_bytes(response.into_body()).await.unwrap();
        let document = std::str::from_utf8(&body).expect("form_post is UTF-8");
        let code = document
            .split("name=\"code\" value=\"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
            .expect("real authorization code input");
        assert!(!code.is_empty());
        let expected = format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Continue</title></head><body><form method=\"post\" action=\"https://client.example/callback\">\n<input type=\"hidden\" name=\"code\" value=\"{code}\">\n<input type=\"hidden\" name=\"state\" value=\"state&lt;&amp;&quot;&#x27;\">\n<input type=\"hidden\" name=\"iss\" value=\"https://issuer.example\">\n<noscript><button type=\"submit\">Continue</button></noscript></form><script nonce=\"{nonce}\">document.forms[0].submit();</script></body></html>"
        );
        assert_eq!(body.as_ref(), expected.as_bytes());

        let escaped = nazo_http_actix::form_post_authorization_response(
            CALLBACK,
            &[
                ("code".to_owned(), "code<&\"'".to_owned()),
                ("state".to_owned(), "state<&\"'".to_owned()),
                ("iss".to_owned(), "https://issuer.example".to_owned()),
            ],
            None,
            nonce,
        );
        let escaped_body = to_bytes(escaped.into_body()).await.unwrap();
        let escaped_expected = expected.replace(
            &format!("name=\"code\" value=\"{code}\""),
            "name=\"code\" value=\"code&lt;&amp;&quot;&#x27;\"",
        );
        assert_eq!(escaped_body.as_ref(), escaped_expected.as_bytes());
    }
}
mod mtls_real_boundary {
    use crate::http::mtls::{self, ServerMtlsThumbprintExtractor};
    use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web::Data};
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use diesel::{
        sql_query,
        sql_types::{Text, Uuid as SqlUuid},
    };
    use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
    use nazo_http_actix::IpCidr;
    use nazo_http_actix::mtls::MtlsThumbprintExtractor;
    use nazo_identity::DEFAULT_ORGANIZATION_ID;
    use nazo_identity::DEFAULT_REALM_ID;
    use nazo_identity::DEFAULT_TENANT_ID;
    use nazo_oauth_server::token::client_auth::{
        ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
        authenticate_client_with_dependencies,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use sha2::{Digest as _, Sha256};
    use std::sync::Arc;

    struct Material {
        ca: CertifiedIssuer<'static, KeyPair>,
        leaf: rcgen::Certificate,
        key: KeyPair,
    }

    fn material() -> Material {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "T00 tenant CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let mut params = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "T00 client");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &ca).unwrap();
        Material { ca, leaf, key }
    }

    #[actix_web::test]
    async fn framework_boundary_transport_direct_tls_captures_real_peer_certificate() {
        use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
        let material = material();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(material.ca.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .allow_unauthenticated()
        .build()
        .unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = params.signed_by(&server_key, &material.ca).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        let server = HttpServer::new(|| {
            App::new()
                .app_data(Data::new(mtls::MtlsCertificateSource::new(
                    mtls::MtlsCertificateSourceMode::DirectTls,
                )))
                .route(
                    "/identity",
                    actix_web::web::get().to(|request: HttpRequest| async move {
                        let resolver = ServerMtlsThumbprintExtractor::new(Vec::new());
                        HttpResponse::Ok().body(
                            resolver
                                .resolve(&request)
                                .unwrap_or_else(|| "absent".to_owned()),
                        )
                    }),
                )
        })
        .workers(1)
        .on_connect(move |io, extensions| {
            mtls::capture_direct_tls_client_certificate(io, extensions, Some(verifier.as_ref()))
        })
        .bind_rustls_0_23(("127.0.0.1", 0), tls)
        .unwrap();
        let url = format!("https://localhost:{}/identity", server.addrs()[0].port());
        let server = server.run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        let root = reqwest::Certificate::from_pem(material.ca.pem().as_bytes()).unwrap();
        let anonymous = reqwest::Client::builder()
            .no_proxy()
            .tls_backend_rustls()
            .tls_certs_only([root.clone()])
            .build()
            .unwrap();
        let response = anonymous
            .get(&url)
            .header(
                "client-cert",
                format!(":{}:", STANDARD.encode(material.leaf.der())),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"absent");
        let identity = reqwest::Identity::from_pem(
            format!(
                "{}{}{}",
                material.leaf.pem(),
                material.ca.pem(),
                material.key.serialize_pem()
            )
            .as_bytes(),
        )
        .unwrap();
        let authenticated = reqwest::Client::builder()
            .no_proxy()
            .tls_backend_rustls()
            .tls_certs_only([root])
            .identity(identity)
            .build()
            .unwrap();
        let response = authenticated
            .get(&url)
            .header("client-cert", ":AA==:")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            URL_SAFE_NO_PAD
                .encode(Sha256::digest(material.leaf.der()))
                .as_bytes()
        );
        drop(authenticated);
        drop(anonymous);
        handle.stop(true).await;
    }

    #[actix_web::test]
    async fn framework_boundary_transport_rfc9440_same_resolver_observes_tenant_ca_revocation() {
        let state = super::live_transport_state().await;
        let material = material();
        let trusted = vec![IpCidr::parse("192.0.2.0/24").unwrap()];
        let resolver = ServerMtlsThumbprintExtractor::new(trusted.clone());
        let certificate_header = format!(":{}:", STANDARD.encode(material.leaf.der()));
        let make_request = |peer: &str| {
            actix_web::test::TestRequest::post()
                .uri("/token")
                .app_data(Data::new(mtls::MtlsCertificateSource::new(
                    mtls::MtlsCertificateSourceMode::Rfc9440,
                )))
                .peer_addr(peer.parse().unwrap())
                .insert_header(("client-cert", certificate_header.as_str()))
                .to_http_request()
        };
        let request = make_request("192.0.2.1:443");
        let untrusted = make_request("198.51.100.1:443");
        let expected_thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(material.leaf.der()));
        assert_eq!(
            resolver.resolve(&request).as_deref(),
            Some(expected_thumbprint.as_str())
        );
        assert!(resolver.resolve(&untrusted).is_none());
        assert!(
            mtls::request_mtls_client_certificate(&request, &[]).is_none(),
            "cached certificate cannot bypass a changed peer policy"
        );
        let certificate = mtls::request_mtls_client_certificate(&request, &trusted).unwrap();
        assert!(!certificate.deployment_trusted_chain);
        assert_eq!(
            certificate.certificate_chain_der,
            vec![material.leaf.der().to_vec()]
        );
        let facts = ClientAuthRequestFacts::new("/token", Some(certificate.clone()));
        let name = format!("t00-ca-{}", uuid::Uuid::now_v7());
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query(r#"INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            redirect_uris, scopes, allowed_audiences, grant_types, token_endpoint_auth_method,
            tls_client_auth_subject_dn, require_dpop_bound_tokens, require_mtls_bound_tokens,
            tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array, allow_client_assertion_endpoint_audience,
            require_par_request_object, is_active, security_policy, post_logout_redirect_uris,
            backchannel_logout_session_required)
            VALUES ($1,$2,$3,$4,'T00 CA','confidential','[]','["openid"]','["resource://default"]',
            '["client_credentials"]','tls_client_auth',$5,false,true,'[]','[]','[]','[]',
            false,false,false,true,
            '{"version":1,"assurance":"baseline","require_signed_authorization_request":false,"require_signed_authorization_response":false,"require_signed_introspection_response":false,"session_management":false,"allow_cross_device_flows":false,"allow_confidential_oidc_without_pkce":false}',
            '[]',true)"#)
            .bind::<SqlUuid,_>(DEFAULT_TENANT_ID).bind::<SqlUuid,_>(DEFAULT_REALM_ID)
            .bind::<SqlUuid,_>(DEFAULT_ORGANIZATION_ID).bind::<Text,_>(&name)
            .bind::<Text,_>(certificate.subject_dn.as_deref().unwrap())
            .execute(&mut connection).await.unwrap();
        drop(connection);
        let mut client = nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone())
            .by_client_id(DEFAULT_TENANT_ID, &name)
            .await
            .unwrap()
            .unwrap();
        let valkey = state.valkey_connection();
        let service = nazo_oauth_server::services::ServerAuthorizationService::new(
            nazo_postgres::AuthorizationFlowRepository::new(
                state.diesel_db.clone(),
                DEFAULT_TENANT_ID,
            ),
            Arc::new(nazo_valkey::AuthorizationStateAdapter::new(&valkey)),
            state.keyset.clone(),
        );
        let config = ClientAuthConfig::new(
            &state.settings.endpoint.issuer,
            &state.settings.protocol.client_secret_pepper,
            crate::test_support::test_remote_client_documents(),
            crate::http::authorization::test_support::test_security_audit(),
        );
        let credentials = nazo_auth::PresentedClientCredentials {
            client_id: Some(name),
            client_secret: None,
            client_assertion: None,
            method: "tls_client_auth".to_owned(),
        };
        let context = nazo_auth::ClientAuthenticationContext::ConfidentialOnly;
        assert!(matches!(
            authenticate_client_with_dependencies(
                &service,
                config,
                &facts,
                &mut client,
                &credentials,
                context
            )
            .await,
            Err(TokenManagementClientAuthError::InvalidClient)
        ));
        let tenant = nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap();
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        connection.batch_execute("BEGIN").await.unwrap();
        let anchor = nazo_postgres::insert_operator_managed_trust_anchor_on_connection(
            &mut connection,
            nazo_postgres::OperatorManagedTrustAnchor {
                tenant_id: tenant,
                client_id: client.id,
                certificate_pem: &material.ca.pem(),
                certificate_sha256: &Sha256::digest(material.ca.der())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                subject_dn: "CN=T00 tenant CA",
                not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
                not_after: chrono::Utc::now() + chrono::Duration::hours(1),
            },
        )
        .await
        .unwrap();
        connection.batch_execute("COMMIT").await.unwrap();
        drop(connection);
        assert!(
            authenticate_client_with_dependencies(
                &service,
                config,
                &facts,
                &mut client,
                &credentials,
                context
            )
            .await
            .is_ok()
        );
        let absent_facts = crate::http::token::client_auth_request_facts(&untrusted, &trusted);
        assert!(matches!(
            authenticate_client_with_dependencies(
                &service,
                config,
                &absent_facts,
                &mut client,
                &credentials,
                context
            )
            .await,
            Err(TokenManagementClientAuthError::InvalidClient)
        ));
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        connection.batch_execute("BEGIN").await.unwrap();
        assert!(
            nazo_postgres::revoke_operator_managed_trust_anchor_on_connection(
                &mut connection,
                tenant,
                anchor
            )
            .await
            .unwrap()
        );
        connection.batch_execute("COMMIT").await.unwrap();
        drop(connection);
        assert_eq!(
            resolver.resolve(&request).as_deref(),
            Some(expected_thumbprint.as_str())
        );
        assert!(
            service
                .mtls_trust_anchor_bundle(client.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            matches!(
                authenticate_client_with_dependencies(
                    &service,
                    config,
                    &facts,
                    &mut client,
                    &credentials,
                    context
                )
                .await,
                Err(TokenManagementClientAuthError::InvalidClient)
            ),
            "same captured certificate and same service must observe revocation"
        );
        let mut connection = nazo_postgres::get_conn(&state.diesel_db).await.unwrap();
        sql_query("DELETE FROM oauth_client_mtls_trust_anchor_events WHERE request_id = $1")
            .bind::<SqlUuid, _>(anchor)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE id = $1")
            .bind::<SqlUuid, _>(anchor)
            .execute(&mut connection)
            .await
            .unwrap();
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(client.id)
            .execute(&mut connection)
            .await
            .unwrap();
    }
}
