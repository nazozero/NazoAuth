use crate::http::Response;
use bytes::Bytes;
use http::{StatusCode, header};
use std::sync::Mutex;

use nazo_identity::ports::RepositoryError;
use nazo_identity::registration::RegisteredAccount;
use nazo_oauth_server::contracts::local_registration::LocalRegistrationFuture;
use serde_json::{Value, json};
use uuid::Uuid;

use super::*;

struct FakeOperations {
    sent: Mutex<Vec<(String, String)>>,
    registrations: Mutex<Vec<RegisterLocalAccountInput>>,
    send_result: Mutex<Result<SendVerificationCodeOutcome, SendVerificationCodeError>>,
    register_result: Mutex<Result<RegisteredAccount, RegisterLocalAccountError>>,
}

impl LocalRegistrationOperations for FakeOperations {
    fn send_verification_code<'a>(
        &'a self,
        normalized_email: &'a str,
        peer_subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<SendVerificationCodeOutcome, SendVerificationCodeError>>
    {
        self.sent
            .lock()
            .unwrap()
            .push((normalized_email.to_owned(), peer_subject.to_owned()));
        let result = self.send_result.lock().unwrap().clone();
        Box::pin(async move { result })
    }

    fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>> {
        self.registrations.lock().unwrap().push(input);
        let result = self.register_result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

struct RecordingRateLimit {
    subjects: Mutex<Vec<String>>,
    result: Mutex<Result<(), AuthenticationRateLimitError>>,
}

impl AuthenticationRateLimit for RecordingRateLimit {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>> {
        self.subjects.lock().unwrap().push(subject.to_owned());
        let result = *self.result.lock().unwrap();
        Box::pin(async move { result })
    }
}

fn account() -> RegisteredAccount {
    RegisteredAccount {
        id: Uuid::from_u128(4),
        email: "alice@example.test".to_owned(),
    }
}

fn endpoint(
    send_result: Result<SendVerificationCodeOutcome, SendVerificationCodeError>,
    register_result: Result<RegisteredAccount, RegisterLocalAccountError>,
    rate_result: Result<(), AuthenticationRateLimitError>,
    trusted_proxies: &[crate::http::IpCidr],
    header_mode: crate::http::ClientIpHeaderMode,
    dev_response_enabled: bool,
) -> (
    LocalRegistrationEndpoint,
    Arc<FakeOperations>,
    Arc<RecordingRateLimit>,
) {
    let operations = Arc::new(FakeOperations {
        sent: Mutex::new(Vec::new()),
        registrations: Mutex::new(Vec::new()),
        send_result: Mutex::new(send_result),
        register_result: Mutex::new(register_result),
    });
    let rate_limit = Arc::new(RecordingRateLimit {
        subjects: Mutex::new(Vec::new()),
        result: Mutex::new(rate_result),
    });
    (
        LocalRegistrationEndpoint::new(
            operations.clone(),
            rate_limit.clone(),
            ClientIpConfig::new(trusted_proxies, header_mode),
            dev_response_enabled,
        ),
        operations,
        rate_limit,
    )
}

async fn body_json(response: Response) -> Value {
    serde_json::from_slice(&response.into_body()).unwrap()
}

#[test]
fn transport_normalizes_email_and_preserves_raw_peer_cooldown_subject() {
    futures_executor::block_on(async {
        let (endpoint, operations, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Sent {
                code: "123456".to_owned(),
            }),
            Ok(account()),
            Ok(()),
            &[],
            crate::http::ClientIpHeaderMode::None,
            false,
        );
        let response = send_code(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .extension(crate::integration::ConnectionFacts {
                    peer_addr: Some("203.0.113.10:49152".parse().unwrap()),
                    ..Default::default()
                })
                .body(Bytes::new())
                .unwrap(),
            SendCodeRequest {
                email: " Alice@Example.TEST ".to_owned(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            operations.sent.lock().unwrap().as_slice(),
            &[("alice@example.test".to_owned(), "203.0.113.10".to_owned())]
        );
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["203.0.113.10"]
        );
        let body = body_json(response).await;
        assert_eq!(body["success"], true);
        assert!(body.get("verification_code").is_none());
    });
}

#[test]
fn untrusted_forwarded_header_cannot_spoof_rate_limit_subject() {
    futures_executor::block_on(async {
        let trusted = crate::http::IpCidr::parse("10.0.0.0/8").unwrap();
        let (endpoint, _, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[trusted],
            crate::http::ClientIpHeaderMode::XForwardedFor,
            false,
        );
        let request = http::Request::builder()
            .method("POST")
            .extension(crate::integration::ConnectionFacts {
                peer_addr: Some("203.0.113.10:49152".parse().unwrap()),
                ..Default::default()
            })
            .header("x-forwarded-for", "198.51.100.5")
            .body(Bytes::new())
            .unwrap();
        let _ = send_code(
            &endpoint,
            &request,
            SendCodeRequest {
                email: "alice@example.test".to_owned(),
            },
        )
        .await;
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["203.0.113.10"]
        );
    });
}

#[test]
fn trusted_proxy_header_controls_both_rate_limit_and_peer_cooldown() {
    futures_executor::block_on(async {
        let trusted = crate::http::IpCidr::parse("10.0.0.0/8").unwrap();
        let (endpoint, operations, rate_limit) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[trusted],
            crate::http::ClientIpHeaderMode::XForwardedFor,
            false,
        );
        let request = http::Request::builder()
            .method("POST")
            .extension(crate::integration::ConnectionFacts {
                peer_addr: Some("10.1.2.3:49152".parse().unwrap()),
                ..Default::default()
            })
            .header("x-forwarded-for", "198.51.100.5")
            .body(Bytes::new())
            .unwrap();
        let _ = send_code(
            &endpoint,
            &request,
            SendCodeRequest {
                email: "alice@example.test".to_owned(),
            },
        )
        .await;
        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            &["198.51.100.5"]
        );
        assert_eq!(operations.sent.lock().unwrap()[0].1, "198.51.100.5");
    });
}

#[test]
fn rate_limit_runs_before_validation_and_preserves_retry_contract() {
    futures_executor::block_on(async {
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Err(AuthenticationRateLimitError::Limited {
                retry_after_seconds: 17,
            }),
            &[],
            crate::http::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            RegisterRequest {
                email: "not an email".to_owned(),
                verification_code: "123456".to_owned(),
                password: "password".to_owned(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "17");
        assert!(operations.registrations.lock().unwrap().is_empty());
        assert_eq!(
            body_json(response).await["error"],
            "temporarily_unavailable"
        );
    });
}

#[test]
fn register_trims_only_code_whitespace_and_returns_public_identity() {
    futures_executor::block_on(async {
        let expected = account();
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(expected.clone()),
            Ok(()),
            &[],
            crate::http::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            RegisterRequest {
                email: "ALICE@EXAMPLE.TEST".to_owned(),
                verification_code: "  123456  ".to_owned(),
                password: "correct horse battery staple".to_owned(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        {
            let calls = operations.registrations.lock().unwrap();
            assert_eq!(calls[0].email, "alice@example.test");
            assert_eq!(calls[0].verification_code, "123456");
        }
        assert_eq!(
            body_json(response).await,
            json!({"id": expected.id, "email": "alice@example.test"})
        );
    });
}

#[test]
fn error_mapping_preserves_status_and_oauth_code() {
    futures_executor::block_on(async {
        let cases = [
            (
                RegisterLocalAccountError::InvalidPasswordLength,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                RegisterLocalAccountError::InvalidVerificationCode,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
            ),
            (
                RegisterLocalAccountError::Conflict,
                StatusCode::CONFLICT,
                "invalid_request",
            ),
            (
                RegisterLocalAccountError::PasswordHash(RepositoryError::Unavailable),
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
            ),
        ];
        for (error, status, code) in cases {
            let (endpoint, _, _) = endpoint(
                Ok(SendVerificationCodeOutcome::Suppressed),
                Err(error),
                Ok(()),
                &[],
                crate::http::ClientIpHeaderMode::None,
                false,
            );
            let response = register(
                &endpoint,
                &http::Request::builder()
                    .method("POST")
                    .body(Bytes::new())
                    .unwrap(),
                RegisterRequest {
                    email: "alice@example.test".to_owned(),
                    verification_code: "123456".to_owned(),
                    password: "password".to_owned(),
                },
            )
            .await;
            assert_eq!(response.status(), status);
            assert_eq!(body_json(response).await["error"], code);
        }
    });
}

#[test]
fn development_code_is_exposed_only_when_enabled_and_newly_sent() {
    futures_executor::block_on(async {
        let (enabled, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Sent {
                code: "654321".to_owned(),
            }),
            Ok(account()),
            Ok(()),
            &[],
            crate::http::ClientIpHeaderMode::None,
            true,
        );
        let response = send_code(
            &enabled,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            SendCodeRequest {
                email: "alice@example.test".to_owned(),
            },
        )
        .await;
        let body = body_json(response).await;
        if cfg!(debug_assertions) {
            assert_eq!(body["verification_code"], "654321");
        } else {
            assert!(body.get("verification_code").is_none());
        }

        let (suppressed, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[],
            crate::http::ClientIpHeaderMode::None,
            true,
        );
        let response = send_code(
            &suppressed,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            SendCodeRequest {
                email: "alice@example.test".to_owned(),
            },
        )
        .await;
        assert!(body_json(response).await.get("verification_code").is_none());
    });
}

#[test]
fn unavailable_rate_limit_fails_closed_before_registration() {
    futures_executor::block_on(async {
        let (endpoint, operations, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Err(AuthenticationRateLimitError::Unavailable),
            &[],
            crate::http::ClientIpHeaderMode::None,
            false,
        );
        let response = register(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            RegisterRequest {
                email: "alice@example.test".to_owned(),
                verification_code: "123456".to_owned(),
                password: "password".to_owned(),
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_json(response).await["error"], "server_error");
        assert!(operations.registrations.lock().unwrap().is_empty());
    });
}

#[test]
fn route_methods_cors_cache_and_security_headers_remain_exact() {
    futures_executor::block_on(async {
        let (endpoint, _, _) = endpoint(
            Ok(SendVerificationCodeOutcome::Suppressed),
            Ok(account()),
            Ok(()),
            &[],
            crate::http::ClientIpHeaderMode::None,
            false,
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("/auth/send-code")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from_static(br#"{"email":"alice@example.test"}"#))
            .unwrap();
        let mut post = send_code(
            &endpoint,
            &request,
            crate::http::parse_json(&request).unwrap(),
        )
        .await;
        crate::http::apply_security_headers(post.headers_mut(), false);
        assert_eq!(post.status(), StatusCode::OK);
        assert_eq!(
            post.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(post.headers().get(header::CACHE_CONTROL).is_none());
        assert!(post.headers().get(header::PRAGMA).is_none());
        assert!(
            post.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(post.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            post.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert!(post.headers().contains_key("content-security-policy"));

        let request = http::Request::builder().method("POST").uri("/auth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::from_static(br#"{"email":"alice@example.test","verification_code":"123456","password":"correct horse battery staple"}"#)).unwrap();
        let mut register_post = register(
            &endpoint,
            &request,
            crate::http::parse_json(&request).unwrap(),
        )
        .await;
        crate::http::apply_security_headers(register_post.headers_mut(), false);
        assert_eq!(register_post.status(), StatusCode::CREATED);
        assert!(register_post.headers().get(header::CACHE_CONTROL).is_none());
        assert!(register_post.headers().get(header::PRAGMA).is_none());
        assert!(
            register_post
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            register_post
                .headers()
                .get(header::X_FRAME_OPTIONS)
                .unwrap(),
            "DENY"
        );

        for path in ["/auth/send-code", "/auth/register"] {
            for method in [http::Method::GET, http::Method::OPTIONS] {
                let mut response = crate::routes::resolve(&method, path).unwrap_err();
                crate::http::apply_security_headers(response.headers_mut(), false);
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
                assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");
                assert!(
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .is_none()
                );
                assert_eq!(
                    response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                    "DENY"
                );
            }
        }
    });
}
