use crate::http::Request;
use bytes::Bytes;
use http::{StatusCode, header};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use nazo_oauth_server::contracts::fapi_resource::{
    FapiAuthorizationError, FapiFuture, FapiHttpMessageSignatures, FapiResourceAuthorizer,
    FapiResponseSignature, FapiSignatureOperationError, FapiSignatureVerificationError,
};
use nazo_resource_server::{
    ProtectedResourceAuthorizationResult, VerifiedAccessToken, VerifiedSenderConstraintProof,
};
use serde_json::{Value, json};

use nazo_http_signatures::{content_digest, content_digest_field_matches};

use super::*;

struct Authorizer {
    calls: Arc<AtomicUsize>,
}

impl FapiResourceAuthorizer for Authorizer {
    fn authorize<'a>(
        &'a self,
        _request: ProtectedResourceAuthorizationRequest<'a>,
        _context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async {
            Ok(ProtectedResourceAuthorizationResult {
                token: VerifiedAccessToken {
                    client_epoch: None,
                    user_epoch: None,
                    user_id: None,
                    subject_type: None,
                    issuer: "https://auth.example".to_owned(),
                    subject: "subject-1".to_owned(),
                    tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
                    client_id: "client-1".to_owned(),
                    audiences: vec!["resource-1".to_owned()],
                    scopes: vec!["openid".to_owned(), "profile".to_owned()],
                    jti: "jti-1".to_owned(),
                    exp: i64::MAX,
                    cnf: None,
                    authorization_details: Value::Null,
                },
                sender_constraint: VerifiedSenderConstraintProof::default(),
            })
        })
    }
}

struct NoMtls;

impl MtlsThumbprintExtractor for NoMtls {
    fn resolve(&self, _request: &Request) -> Option<String> {
        None
    }
}

struct DisabledSignatures;

impl FapiHttpMessageSignatures for DisabledSignatures {
    fn acquire_request(&self) -> Option<nazo_runtime_modules::RequestLease> {
        None
    }

    fn verify_and_consume<'a>(
        &'a self,
        _tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a ParsedSignatureInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
        Box::pin(async { unreachable!("disabled signatures are not verified") })
    }

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
        Err(FapiSignatureOperationError::Unavailable)
    }
}

#[derive(Clone, Copy)]
enum AuthorizationOutcome {
    Success,
    UseNonce,
    NonceUnavailable,
    InvalidDpop,
}

struct RecordingAuthorizer {
    calls: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Vec<String>>>>,
    outcome: AuthorizationOutcome,
}

impl FapiResourceAuthorizer for RecordingAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: ProtectedResourceAuthorizationRequest<'a>,
        context: ProtectedResourceAuthorizationContext<'a>,
    ) -> FapiFuture<'a, Result<ProtectedResourceAuthorizationResult, FapiAuthorizationError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.targets.lock().unwrap().push(
            context
                .target_uris
                .iter()
                .map(|target| (*target).to_owned())
                .collect(),
        );
        let outcome = self.outcome;
        Box::pin(async move {
            match outcome {
                AuthorizationOutcome::Success => Ok(successful_authorization()),
                AuthorizationOutcome::UseNonce => {
                    Err(FapiAuthorizationError::UseDpopNonce("nonce-1".to_owned()))
                }
                AuthorizationOutcome::NonceUnavailable => {
                    Err(FapiAuthorizationError::DpopNonceUnavailable)
                }
                AuthorizationOutcome::InvalidDpop => Err(FapiAuthorizationError::Protocol(
                    ProtectedResourceAuthorizationError::InvalidDpopProof(
                        DpopProofVerifierError::InvalidSignature,
                    ),
                )),
            }
        })
    }
}

fn successful_authorization() -> ProtectedResourceAuthorizationResult {
    ProtectedResourceAuthorizationResult {
        token: VerifiedAccessToken {
            client_epoch: None,
            user_epoch: None,
            user_id: None,
            subject_type: None,
            issuer: "https://auth.example".to_owned(),
            subject: "subject-1".to_owned(),
            tenant_id: Some("01900000-0000-7000-8000-000000000001".to_owned()),
            client_id: "client-1".to_owned(),
            audiences: vec!["resource-1".to_owned()],
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            jti: "jti-1".to_owned(),
            exp: i64::MAX,
            cnf: None,
            authorization_details: Value::Null,
        },
        sender_constraint: VerifiedSenderConstraintProof::default(),
    }
}

struct TestResponseSigner {
    fail: bool,
    bases: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FapiResponseSignature for TestResponseSigner {
    fn kid(&self) -> &str {
        "response-key"
    }

    fn algorithm(&self) -> &str {
        "ed25519"
    }

    fn sign<'a>(
        &'a self,
        signature_base: &'a [u8],
    ) -> FapiFuture<'a, Result<Vec<u8>, FapiSignatureOperationError>> {
        self.bases.lock().unwrap().push(signature_base.to_vec());
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(FapiSignatureOperationError::Unavailable)
            } else {
                Ok(vec![7; 64])
            }
        })
    }
}

struct EnabledSignatures {
    verification: Result<(), FapiSignatureVerificationError>,
    verify_calls: Arc<AtomicUsize>,
    verified_tenants: Arc<Mutex<Vec<String>>>,
    signer: Arc<TestResponseSigner>,
}

impl FapiHttpMessageSignatures for EnabledSignatures {
    fn acquire_request(&self) -> Option<nazo_runtime_modules::RequestLease> {
        test_module_lease(true)
    }

    fn verify_and_consume<'a>(
        &'a self,
        tenant_id: &'a str,
        _client_id: &'a str,
        _input: &'a ParsedSignatureInput,
    ) -> FapiFuture<'a, Result<(), FapiSignatureVerificationError>> {
        self.verify_calls.fetch_add(1, Ordering::Relaxed);
        self.verified_tenants
            .lock()
            .unwrap()
            .push(tenant_id.to_owned());
        let result = self.verification;
        Box::pin(async move { result })
    }

    fn response_signature(
        &self,
    ) -> Result<Arc<dyn FapiResponseSignature>, FapiSignatureOperationError> {
        Ok(self.signer.clone())
    }
}

struct SignatureTestState {
    endpoint: FapiResourceEndpoint,
    authorizer_calls: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Vec<String>>>>,
    verify_calls: Arc<AtomicUsize>,
    verified_tenants: Arc<Mutex<Vec<String>>>,
    bases: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn signature_endpoint(
    outcome: AuthorizationOutcome,
    verification: Result<(), FapiSignatureVerificationError>,
    signer_fails: bool,
) -> SignatureTestState {
    let authorizer_calls = Arc::new(AtomicUsize::new(0));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let verify_calls = Arc::new(AtomicUsize::new(0));
    let verified_tenants = Arc::new(Mutex::new(Vec::new()));
    let bases = Arc::new(Mutex::new(Vec::new()));
    let endpoint = FapiResourceEndpoint::new(
        "https://auth.example",
        "https://mtls.auth.example",
        60,
        Arc::new(RecordingAuthorizer {
            calls: authorizer_calls.clone(),
            targets: targets.clone(),
            outcome,
        }),
        Arc::new(NoMtls),
        Arc::new(EnabledSignatures {
            verification,
            verify_calls: verify_calls.clone(),
            verified_tenants: verified_tenants.clone(),
            signer: Arc::new(TestResponseSigner {
                fail: signer_fails,
                bases: bases.clone(),
            }),
        }),
    );
    SignatureTestState {
        endpoint,
        authorizer_calls,
        targets,
        verify_calls,
        verified_tenants,
        bases,
    }
}

fn request_signature_fields(method: &str, body: &[u8], dpop: Option<&str>) -> SignatureFields {
    let authorization = "Bearer access-token";
    let digest = (!body.is_empty()).then(|| content_digest(body));
    let mut headers = vec![("authorization", authorization)];
    if let Some(dpop) = dpop {
        headers.push(("dpop", dpop));
    }
    if let Some(digest) = digest.as_deref() {
        headers.push(("content-digest", digest));
    }
    nazo_http_signatures::prepare_request(
        RequestInput {
            method,
            target_uri: "https://auth.example/fapi/resource",
            headers: &headers,
            body,
        },
        nazo_http_signatures::RequestPolicy {
            created: Utc::now().timestamp(),
            keyid: "client-key",
            algorithm: "ed25519",
            covered_headers: &[],
        },
    )
    .unwrap()
    .finish(&[3; 64])
}

fn endpoint(calls: Arc<AtomicUsize>) -> FapiResourceEndpoint {
    FapiResourceEndpoint::new(
        "https://auth.example",
        "https://mtls.auth.example",
        60,
        Arc::new(Authorizer { calls }),
        Arc::new(NoMtls),
        Arc::new(DisabledSignatures),
    )
}

#[test]
fn handler_extracts_calls_core_and_preserves_success_contract() {
    futures_executor::block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = endpoint(calls.clone());
        let request = http::Request::builder()
            .header(header::HOST, "auth.example")
            .uri("/fapi/resource")
            .header(header::AUTHORIZATION, "Bearer access-token")
            .header("x-fapi-interaction-id", "interaction-1")
            .body(Bytes::new())
            .unwrap();
        let response = {
            let request = request;
            fapi_resource(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get("x-fapi-interaction-id").unwrap(),
            "interaction-1"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert!(!response.headers().contains_key("signature-input"));
        assert!(!response.headers().contains_key("signature"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({
                "sub": "subject-1",
                "client_id": "client-1",
                "scope": "openid profile",
                "aud": "resource-1"
            })
        );
    });
}

#[test]
fn fapi_resource_rejects_form_body_access_tokens_without_signature_module() {
    futures_executor::block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = endpoint(calls.clone());
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Bytes::from("access_token=form-token"))
                .unwrap();
            fapi_resource(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({
                "error": "invalid_request",
                "error_description": "Only one access token transport method may be used."
            })
        );
    });
}

#[test]
fn missing_token_preserves_bearer_error_and_skips_core() {
    futures_executor::block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = endpoint(calls.clone());
        let response = {
            let request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .body(Bytes::new())
                .unwrap();
            fapi_resource(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer error=\"invalid_token\", error_description=\"Request failed.\""
        );
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({"error":"invalid_token","error_description":"Request failed."})
        );
    });
}

#[test]
fn signed_get_uses_one_authorization_call_and_signs_the_success_response() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = &state.endpoint;
        let fields = request_signature_fields("GET", b"", None);
        let response = {
            let request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::AUTHORIZATION, "Bearer access-token")
                .header("signature-input", fields.signature_input)
                .header("signature", fields.signature)
                .body(Bytes::new())
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            *state.verified_tenants.lock().unwrap(),
            vec!["01900000-0000-7000-8000-000000000001".to_owned()]
        );
        assert!(response.headers().contains_key("signature-input"));
        assert!(response.headers().contains_key("signature"));
        let digest = response
            .headers()
            .get("content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = response.into_body();
        assert!(content_digest_field_matches(&digest, &body));
        assert_eq!(
            *state.targets.lock().unwrap(),
            vec![vec!["https://auth.example/fapi/resource".to_owned(),]]
        );
        let bases = state.bases.lock().unwrap();
        let base = std::str::from_utf8(&bases[0]).unwrap();
        assert!(base.contains("\"@status\""));
        assert!(base.contains("\"@method\";req"));
        assert!(base.contains("\"@target-uri\";req"));
        assert!(base.contains("\"signature\";req"));
    });
}

#[test]
fn signed_post_binds_the_received_request_digest() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = &state.endpoint;
        let body = b"operation=read";
        let digest = content_digest(body);
        let fields = request_signature_fields("POST", body, None);
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::AUTHORIZATION, "Bearer access-token")
                .header("content-digest", digest.as_str())
                .header("signature-input", fields.signature_input)
                .header("signature", fields.signature)
                .body(Bytes::from(body.as_slice()))
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
        let bases = state.bases.lock().unwrap();
        let base = std::str::from_utf8(&bases[0]).unwrap();
        assert!(base.contains("\"content-digest\";req"));
        assert!(base.contains(digest.as_str()));
    });
}

#[test]
fn malformed_or_duplicate_signature_fields_fail_before_authorization_without_signing() {
    futures_executor::block_on(async {
        for duplicate in [false, true] {
            let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
            let app = &state.endpoint;
            let mut request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::AUTHORIZATION, "Bearer access-token");
            if duplicate {
                request = request
                    .header("signature-input", "sig=()")
                    .header("signature-input", "sig=()")
                    .header("signature", "sig=:AA=:");
            }
            let response = {
                let request = request.body(Bytes::new()).unwrap();
                fapi_resource(app, &request, request.body()).await
            };

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
            assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
            assert!(!response.headers().contains_key("signature-input"));
            assert!(state.bases.lock().unwrap().is_empty());
            assert!(!response.headers().contains_key("signature"));
            assert!(!response.headers().contains_key(header::CACHE_CONTROL));
        }
    });
}

#[test]
fn duplicate_dpop_header_preserves_invalid_dpop_contract_and_skips_core() {
    futures_executor::block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = endpoint(calls.clone());
        let response = {
            let request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::AUTHORIZATION, "DPoP access-token")
                .header("dpop", "first")
                .header("dpop", "second")
                .body(Bytes::new())
                .unwrap();
            fapi_resource(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "DPoP error=\"invalid_dpop_proof\""
        );
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({
                "error": "invalid_dpop_proof",
                "error_description": "DPoP proof is malformed."
            })
        );
    });
}

#[test]
fn nonce_challenge_and_nonce_dependency_failure_keep_http_contracts_without_private_signing() {
    futures_executor::block_on(async {
        for (outcome, status, error, description, challenge) in [
            (
                AuthorizationOutcome::UseNonce,
                StatusCode::UNAUTHORIZED,
                "use_dpop_nonce",
                "Authorization server requires nonce in DPoP proof.",
                "DPoP error=\"use_dpop_nonce\"",
            ),
            (
                AuthorizationOutcome::NonceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "DPoP nonce validation is unavailable.",
                "DPoP error=\"server_error\"",
            ),
        ] {
            let state = signature_endpoint(outcome, Ok(()), false);
            let app = &state.endpoint;
            let fields = request_signature_fields("GET", b"", Some("proof"));
            let response = {
                let request = http::Request::builder()
                    .header(header::HOST, "auth.example")
                    .uri("/fapi/resource")
                    .header(header::AUTHORIZATION, "Bearer access-token")
                    .header("dpop", "proof")
                    .header("signature-input", fields.signature_input)
                    .header("signature", fields.signature)
                    .body(Bytes::new())
                    .unwrap();
                fapi_resource(app, &request, request.body()).await
            };

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                challenge
            );
            if matches!(outcome, AuthorizationOutcome::UseNonce) {
                assert_eq!(response.headers().get("dpop-nonce").unwrap(), "nonce-1");
            }
            assert!(!response.headers().contains_key("signature-input"));
            assert!(state.bases.lock().unwrap().is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(response.body()).unwrap(),
                json!({"error": error, "error_description": description})
            );
        }
    });
}

#[test]
fn signature_verification_failures_preserve_status_without_private_signing() {
    futures_executor::block_on(async {
        for (verification, status) in [
            (
                Err(FapiSignatureVerificationError::Invalid),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Err(FapiSignatureVerificationError::Replay),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Err(FapiSignatureVerificationError::LookupUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                Err(FapiSignatureVerificationError::ReplayUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let state = signature_endpoint(AuthorizationOutcome::Success, verification, false);
            let app = &state.endpoint;
            let fields = request_signature_fields("GET", b"", None);
            let response = {
                let request = http::Request::builder()
                    .header(header::HOST, "auth.example")
                    .uri("/fapi/resource")
                    .header(header::AUTHORIZATION, "Bearer access-token")
                    .header("signature-input", fields.signature_input)
                    .header("signature", fields.signature)
                    .body(Bytes::new())
                    .unwrap();
                fapi_resource(app, &request, request.body()).await
            };

            assert_eq!(response.status(), status);
            assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
            assert_eq!(state.verify_calls.load(Ordering::Relaxed), 1);
            assert!(!response.headers().contains_key("signature-input"));
            assert!(state.bases.lock().unwrap().is_empty());
            assert!(!response.headers().contains_key("signature"));
        }
    });
}

#[test]
fn response_signer_failure_returns_an_empty_unsigned_503() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), true);
        let app = &state.endpoint;
        let fields = request_signature_fields("GET", b"", None);
        let response = {
            let request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::AUTHORIZATION, "Bearer access-token")
                .header("signature-input", fields.signature_input)
                .header("signature", fields.signature)
                .body(Bytes::new())
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key("signature-input"));
        assert!(!response.headers().contains_key("signature"));
        assert!(response.into_body().is_empty());
    });
}

#[test]
fn response_signing_preserves_body_storage_and_multiple_physical_header_values() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let fields = request_signature_fields("GET", b"", None);
        let request = http::Request::builder()
            .header(header::HOST, "auth.example")
            .uri("/fapi/resource")
            .header(header::AUTHORIZATION, "Bearer access-token")
            .header("signature-input", fields.signature_input)
            .header("signature", fields.signature)
            .body(Bytes::new())
            .unwrap();
        let request_body = Bytes::new();
        let original = CapturedRequest::capture(
            "https://auth.example/fapi/resource".to_owned(),
            &request,
            &request_body,
        );
        let body = Bytes::from(serde_json::to_vec(&json!({"ok": true})).unwrap());
        let pointer = body.as_ptr();
        let response = http::Response::builder()
            .status(StatusCode::OK)
            .header(header::SET_COOKIE, "first=1; Secure")
            .header(header::SET_COOKIE, "second=2; Secure")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap();

        let signed = sign_response(&state.endpoint, &original, response).await;
        assert_eq!(signed.status(), StatusCode::OK);
        assert_eq!(
            signed.headers().get_all(header::SET_COOKIE).iter().count(),
            2
        );
        assert!(signed.headers().contains_key("signature-input"));
        assert!(signed.headers().contains_key("signature"));
        let digest = signed
            .headers()
            .get("content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = signed.into_body();
        assert_eq!(body.as_ptr(), pointer);
        assert!(content_digest_field_matches(&digest, &body));
    });
}

#[test]
fn signature_enabled_endpoint_rejects_form_body_access_tokens_before_core() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = &state.endpoint;
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Bytes::from("access_token=form-token"))
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 0);
        assert_eq!(state.verify_calls.load(Ordering::Relaxed), 0);
        assert!(!response.headers().contains_key("signature-input"));
        assert!(state.bases.lock().unwrap().is_empty());
        assert!(!response.headers().contains_key("signature"));
        assert_eq!(
            serde_json::from_slice::<Value>(response.body()).unwrap(),
            json!({
                "error": "invalid_request",
                "error_description": "Only one access token transport method may be used."
            })
        );
    });
}

#[test]
fn bearer_dpop_and_mtls_protocol_errors_keep_exact_http_contracts() {
    futures_executor::block_on(async {
        use nazo_resource_server::ProtectedResourceDependencyError;

        let cases = vec![
            (
                ProtectedResourceAuthorizationError::InvalidToken(
                    ResourceServerVerifierError::AudienceMismatch,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidToken(
                    ResourceServerVerifierError::Expired,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidTenantBoundary,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::Revoked,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Request failed.",
                "Bearer error=\"invalid_token\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DependencyUnavailable(
                    ProtectedResourceDependencyError::RevocationLookupUnavailable,
                ),
                AccessTokenAuthScheme::Bearer,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
                "Bearer error=\"server_error\", error_description=\"Request failed.\"",
            ),
            (
                ProtectedResourceAuthorizationError::TokenNotDpopBound,
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Token is not DPoP-bound.",
                "DPoP error=\"invalid_token\"",
            ),
            (
                ProtectedResourceAuthorizationError::MissingSenderConstraint,
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof is required.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::MissingSenderConstraint,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "mTLS-bound access token requires a verified client certificate.",
                "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token requires a verified client certificate.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DpopBindingMismatch,
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "DPoP binding mismatch.",
                "DPoP error=\"invalid_token\"",
            ),
            (
                ProtectedResourceAuthorizationError::ReplayDetected,
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof jti has already been used.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::MalformedProof,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof is malformed.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::ReplayDetected,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof jti has already been used.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::InvalidDpopProof(
                    DpopProofVerifierError::InvalidSignature,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof validation failed.",
                "DPoP error=\"invalid_dpop_proof\"",
            ),
            (
                ProtectedResourceAuthorizationError::MtlsBindingMismatch,
                AccessTokenAuthScheme::Bearer,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "mTLS-bound access token certificate mismatch.",
                "Bearer error=\"invalid_token\", error_description=\"mTLS-bound access token certificate mismatch.\"",
            ),
            (
                ProtectedResourceAuthorizationError::DependencyUnavailable(
                    ProtectedResourceDependencyError::DpopNonceStoreUnavailable,
                ),
                AccessTokenAuthScheme::DPoP,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "DPoP nonce validation is unavailable.",
                "DPoP error=\"server_error\"",
            ),
        ];

        for (error, scheme, status, code, description, challenge) in cases {
            let response = protocol_error_response(error, scheme);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
                challenge
            );
            let body = response.into_body();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error": code, "error_description": description})
            );
        }

        let nonce = nazo_oauth_server::crypto::random_urlsafe_token();
        let response = protocol_error_response(
            ProtectedResourceAuthorizationError::UseDpopNonce(nonce.clone()),
            AccessTokenAuthScheme::DPoP,
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("dpop-nonce").unwrap(),
            nonce.as_str()
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "DPoP error=\"use_dpop_nonce\""
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&response.into_body()).unwrap(),
            json!({
                "error": "use_dpop_nonce",
                "error_description": "Authorization server requires nonce in DPoP proof."
            })
        );
    });
}

fn test_module_lease(enabled: bool) -> Option<nazo_runtime_modules::RequestLease> {
    use nazo_runtime_modules::{
        ActiveModuleSnapshot, CapabilityAdmission, ModuleId, ModuleRevision, SnapshotStore,
    };
    SnapshotStore::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(1),
        accepting: if enabled {
            [ModuleId::HttpMessageSignatures].into()
        } else {
            Default::default()
        },
        draining: Default::default(),
    })
    .lease(
        ModuleId::HttpMessageSignatures,
        CapabilityAdmission::NewRequest,
    )
}

#[test]
fn missing_token_and_invalid_dpop_never_invoke_response_signer() {
    futures_executor::block_on(async {
        for with_token in [false, true] {
            let state = signature_endpoint(AuthorizationOutcome::InvalidDpop, Ok(()), true);
            let mut request = http::Request::builder()
                .header(header::HOST, "auth.example")
                .uri("/fapi/resource");
            if with_token {
                let fields = request_signature_fields("GET", b"", None);
                request = request
                    .header(header::AUTHORIZATION, "Bearer access-token")
                    .header("signature-input", fields.signature_input)
                    .header("signature", fields.signature);
            }
            let response = fapi_resource(
                &state.endpoint,
                &request.body(Bytes::new()).unwrap(),
                &Bytes::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(state.bases.lock().unwrap().is_empty());
            assert!(!response.headers().contains_key("signature"));
        }
    });
}

#[test]
fn resource_target_binds_actual_alias_and_signed_query() {
    futures_executor::block_on(async {
        let state = signature_endpoint(AuthorizationOutcome::Success, Ok(()), false);
        let app = &state.endpoint;
        let fields = request_signature_fields("GET", b"", None);
        let response = {
            let request = http::Request::builder()
                .uri("/fapi/resource?view=full")
                .header(header::HOST, "mtls.auth.example")
                .header("forwarded", "host=auth.example;proto=https")
                .header(header::AUTHORIZATION, "Bearer access-token")
                .header("signature-input", fields.signature_input)
                .header("signature", fields.signature)
                .body(Bytes::new())
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            *state.targets.lock().unwrap(),
            vec![vec!["https://mtls.auth.example/fapi/resource".to_owned()]]
        );
        {
            let bases = state.bases.lock().unwrap();
            assert!(
                std::str::from_utf8(&bases[0])
                    .unwrap()
                    .contains("https://mtls.auth.example/fapi/resource?view=full")
            );
        }
        let response = {
            let request = http::Request::builder()
                .uri("/fapi/resource")
                .header(header::HOST, "unbound.example")
                .header("x-forwarded-host", "auth.example")
                .header(header::AUTHORIZATION, "Bearer access-token")
                .body(Bytes::new())
                .unwrap();
            fapi_resource(app, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.authorizer_calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.bases.lock().unwrap().len(), 1);
    });
}
