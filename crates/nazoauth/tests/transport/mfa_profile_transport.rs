use bytes::Bytes;
use cookie::Cookie;
use http::{Method, StatusCode, header};
use std::sync::Arc;

use crate::http::{
    ClientIpConfig, ClientIpHeaderMode, MfaProfileConfig, MfaProfileEndpoint,
    mfa_backup_codes_regenerate, mfa_disable, mfa_options, mfa_step_up, mfa_totp_begin,
    mfa_totp_confirm, mfa_verify, parse_mfa_json,
};
use nazo_oauth_server::contracts::local_registration::AuthenticationRateLimitError;
use nazo_oauth_server::contracts::mfa_profile::{
    MfaBackupCodesRegenerated, MfaChallengeCommand, MfaChallengeSuccess, MfaCodeCommand,
    MfaProfileError, MfaProfileErrorKind, MfaProfileFuture, MfaProfileOperations,
    MfaRequestContext, MfaSessionRotation, MfaStepUpSuccess, MfaTotpConfirmation,
    MfaTotpEnrollment,
};

#[derive(Clone, Default)]
struct Operations {
    verify_error: Option<MfaProfileError>,
    step_up_error: Option<MfaProfileError>,
    disable_changed: bool,
    verifications: Arc<std::sync::Mutex<Vec<MfaChallengeCommand>>>,
}

impl MfaProfileOperations for Operations {
    fn begin_totp(&self, _context: MfaRequestContext) -> MfaProfileFuture<'_, MfaTotpEnrollment> {
        Box::pin(async {
            Ok(MfaTotpEnrollment {
                secret_base32: "SECRET".to_owned(),
                otpauth_uri: "otpauth://totp/example".to_owned(),
            })
        })
    }

    fn confirm_totp(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaTotpConfirmation> {
        Box::pin(async {
            Ok(MfaTotpConfirmation {
                rotation: rotation(),
                backup_codes: vec!["12345-67890".to_owned()],
            })
        })
    }

    fn verify_challenge(
        &self,
        command: MfaChallengeCommand,
    ) -> MfaProfileFuture<'_, MfaChallengeSuccess> {
        self.verifications.lock().unwrap().push(command);
        let error = self.verify_error.clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(MfaChallengeSuccess {
                    rotation: rotation(),
                    method: "otp",
                    remembered_device_token: None,
                }),
            }
        })
    }

    fn step_up(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaStepUpSuccess> {
        let error = self.step_up_error.clone();
        Box::pin(async move {
            match error {
                Some(error) => Err(error),
                None => Ok(MfaStepUpSuccess {
                    rotation: rotation(),
                    method: "otp",
                }),
            }
        })
    }

    fn regenerate_backup_codes(
        &self,
        _command: MfaCodeCommand,
    ) -> MfaProfileFuture<'_, MfaBackupCodesRegenerated> {
        Box::pin(async {
            Ok(MfaBackupCodesRegenerated {
                rotation: rotation(),
                backup_codes: vec!["12345-67890".to_owned()],
            })
        })
    }

    fn disable(&self, _command: MfaCodeCommand) -> MfaProfileFuture<'_, bool> {
        let changed = self.disable_changed;
        Box::pin(async move { Ok(changed) })
    }
}

#[test]
fn user_agent_binding_is_only_collected_for_remembered_devices() {
    futures_executor::block_on(async {
        let operations = Operations::default();
        let observed = operations.verifications.clone();
        let app = endpoint_with(operations);
        for (remember, agent) in [
            (false, Some(" test-agent ")),
            (true, Some(" test-agent ")),
            (true, Some("   ")),
            (true, None),
        ] {
            let mut request = authenticated_request(Method::POST, "/auth/mfa/verify")
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(agent) = agent {
                request = request.header(header::USER_AGENT, agent);
            }
            assert_eq!(
                {
                    let request = request
                        .body(Bytes::from(
                            serde_json::to_vec(
                                &serde_json::json!({"code":"123456", "remember_device": remember}),
                            )
                            .unwrap(),
                        ))
                        .unwrap();
                    let mut response = match parse_mfa_json(&request) {
                        Ok(payload) => mfa_verify(&app, &request, payload).await,
                        Err(response) => response,
                    };
                    crate::http::apply_security_headers(response.headers_mut(), false);
                    response
                }
                .status(),
                StatusCode::OK
            );
        }
        let observed = observed.lock().unwrap();
        assert_eq!(observed.len(), 4);
        assert!(!observed[0].remember_device);
        assert!(observed[0].user_agent_hash.is_none());
        assert!(observed[1].remember_device);
        assert_eq!(
            observed[1].user_agent_hash.as_deref(),
            Some(blake3::hash(b"test-agent").to_hex().as_str())
        );
        assert!(observed[2].user_agent_hash.is_none());
        assert!(observed[3].user_agent_hash.is_none());
    });
}

#[test]
fn missing_mfa_challenge_does_not_clear_an_authenticated_session() {
    futures_executor::block_on(async {
        let app = endpoint_with(Operations {
            verify_error: Some(MfaProfileError::new(MfaProfileErrorKind::ChallengeMissing)),
            ..Operations::default()
        });

        let response = {
            let request = authenticated_request(Method::POST, "/auth/mfa/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(r#"{"code":"000000","remember_device":false}"#))
                .unwrap();
            let mut response = match parse_mfa_json(&request) {
                Ok(payload) => mfa_verify(&app, &request, payload).await,
                Err(response) => response,
            };
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            0
        );
        assert_contract_headers(response.headers());
    });
}

fn rotation() -> MfaSessionRotation {
    MfaSessionRotation {
        session_id: "new-session".to_owned(),
        csrf_token: "new-csrf".to_owned(),
    }
}

fn endpoint() -> MfaProfileEndpoint {
    endpoint_with(Operations {
        disable_changed: true,
        ..Operations::default()
    })
}

fn endpoint_with(operations: Operations) -> MfaProfileEndpoint {
    MfaProfileEndpoint::new(
        Arc::new(operations),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        MfaProfileConfig::new("session", "csrf", "remembered", 300, 600, true),
    )
}

fn authenticated_request(method: Method, path: &str) -> http::request::Builder {
    http::Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::COOKIE,
            (cookie::Cookie::new("session", "old-session")).to_string(),
        )
        .header(
            header::COOKIE,
            (cookie::Cookie::new("csrf", "old-csrf")).to_string(),
        )
        .header("x-csrf-token", "old-csrf")
}

#[test]
fn static_mfa_routes_lock_methods_cors_security_headers_and_no_store() {
    futures_executor::block_on(async {
        let app = endpoint();

        let paths = [
            "/auth/mfa/verify",
            "/auth/me/mfa/totp/begin",
            "/auth/me/mfa/totp/confirm",
            "/auth/me/mfa/step-up",
            "/auth/me/mfa/backup-codes/regenerate",
            "/auth/me/mfa/disable",
        ];
        for path in paths {
            let response = {
                let request = http::Request::builder()
                    .uri(path)
                    .body(Bytes::new())
                    .unwrap();
                let mut response =
                    crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_contract_headers(response.headers());

            let request = authenticated_request(Method::POST, path)
                .header(header::CONTENT_TYPE, "application/json");
            let request = if path.ends_with("/begin") {
                request.body(Bytes::new()).unwrap()
            } else {
                request.body(Bytes::from(r#"{"code":"123456"}"#)).unwrap()
            };
            let response = {
                let request = request;
                let mut response = match path {
                    "/auth/mfa/verify" => {
                        mfa_verify(&app, &request, parse_mfa_json(&request).unwrap()).await
                    }
                    "/auth/me/mfa/totp/begin" => mfa_totp_begin(&app, &request).await,
                    "/auth/me/mfa/totp/confirm" => {
                        mfa_totp_confirm(&app, &request, parse_mfa_json(&request).unwrap()).await
                    }
                    "/auth/me/mfa/step-up" => {
                        mfa_step_up(&app, &request, parse_mfa_json(&request).unwrap()).await
                    }
                    "/auth/me/mfa/backup-codes/regenerate" => {
                        mfa_backup_codes_regenerate(
                            &app,
                            &request,
                            parse_mfa_json(&request).unwrap(),
                        )
                        .await
                    }
                    "/auth/me/mfa/disable" => {
                        mfa_disable(&app, &request, parse_mfa_json(&request).unwrap()).await
                    }
                    _ => unreachable!(),
                };
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_contract_headers(response.headers());

            let response = {
                let request = http::Request::builder()
                    .method(Method::OPTIONS)
                    .uri(path)
                    .body(Bytes::new())
                    .unwrap();
                assert_eq!(
                    crate::routes::resolve(request.method(), request.uri().path())
                        .unwrap()
                        .method
                        .endpoint,
                    crate::integration::Endpoint::MfaOptions
                );
                let mut response = mfa_options().await;
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_contract_headers(response.headers());
        }

        let profile_preflight = {
            let request = http::Request::builder()
                .method(Method::OPTIONS)
                .uri("/auth/me/mfa/step-up")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Bytes::new())
                .unwrap();
            let mut response = crate::http::cors_preflight(
                crate::http::CorsPolicy::AuthApi,
                &request,
                &["https://app.example".to_owned()],
            )
            .unwrap();
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(
            profile_preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&header::HeaderValue::from_static("https://app.example"))
        );

        let challenge_preflight = {
            let request = http::Request::builder()
                .method(Method::OPTIONS)
                .uri("/auth/mfa/verify")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Bytes::new())
                .unwrap();
            assert_eq!(
                crate::routes::resolve(request.method(), request.uri().path())
                    .unwrap()
                    .method
                    .endpoint,
                crate::integration::Endpoint::MfaOptions
            );
            let mut response = mfa_options().await;
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert!(
            challenge_preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    });
}

#[test]
fn malformed_json_and_rate_limit_fail_closed_with_stable_http_contract() {
    futures_executor::block_on(async {
        let app = endpoint_with(Operations {
            step_up_error: Some(MfaProfileError::rate_limit(
                AuthenticationRateLimitError::Limited {
                    retry_after_seconds: 7,
                },
            )),
            ..Operations::default()
        });

        let malformed = {
            let request = authenticated_request(Method::POST, "/auth/me/mfa/step-up")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from("{"))
                .unwrap();
            let mut response = match parse_mfa_json(&request) {
                Ok(payload) => mfa_step_up(&app, &request, payload).await,
                Err(response) => response,
            };
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_contract_headers(malformed.headers());

        let limited = {
            let request = authenticated_request(Method::POST, "/auth/me/mfa/step-up")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(r#"{"code":"123456"}"#))
                .unwrap();
            let mut response = match parse_mfa_json(&request) {
                Ok(payload) => mfa_step_up(&app, &request, payload).await,
                Err(response) => response,
            };
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            limited.headers().get(header::RETRY_AFTER),
            Some(&header::HeaderValue::from_static("7"))
        );
        assert_contract_headers(limited.headers());
        assert_eq!(
            limited.headers().get_all(header::SET_COOKIE).iter().count(),
            0
        );
    });
}

#[test]
fn disabling_only_clears_remembered_device_cookie_when_state_changed() {
    futures_executor::block_on(async {
        for (changed, expected_cookies) in [(false, 0), (true, 1)] {
            let app = endpoint_with(Operations {
                disable_changed: changed,
                ..Operations::default()
            });
            let response = {
                let request = authenticated_request(Method::POST, "/auth/me/mfa/disable")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Bytes::from(r#"{"code":"123456"}"#))
                    .unwrap();
                let mut response = match parse_mfa_json(&request) {
                    Ok(payload) => mfa_disable(&app, &request, payload).await,
                    Err(response) => response,
                };
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::OK);
            assert_contract_headers(response.headers());
            assert_eq!(
                response
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .count(),
                expected_cookies
            );
        }
    });
}

#[test]
fn successful_step_up_rotates_session_and_csrf_as_a_no_store_pair() {
    futures_executor::block_on(async {
        let app = endpoint();
        let response = {
            let request = authenticated_request(Method::POST, "/auth/me/mfa/step-up")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(r#"{"code":"123456"}"#))
                .unwrap();
            let mut response = match parse_mfa_json(&request) {
                Ok(payload) => mfa_step_up(&app, &request, payload).await,
                Err(response) => response,
            };
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_contract_headers(response.headers());
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| Cookie::parse(value.to_str().unwrap()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.name() == "session" && cookie.http_only() == Some(true))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.name() == "csrf" && cookie.http_only() != Some(true))
        );
    });
}

fn assert_contract_headers(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        headers.get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
    assert_eq!(
        headers.get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json"))
    );
    assert!(headers.contains_key("x-content-type-options"));
}
