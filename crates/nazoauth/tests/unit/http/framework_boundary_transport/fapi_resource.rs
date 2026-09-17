use std::sync::{Arc, Mutex};

use actix_web::{
    http::{StatusCode, header},
    test::TestRequest,
    web::{Bytes, Data},
};

use super::{NoFapiMtls, ready_body_bytes};

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
