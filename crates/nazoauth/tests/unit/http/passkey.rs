use crate::http::Response;
use bytes::Bytes;
use cookie::Cookie;
use http::{StatusCode, header};
use std::sync::Mutex;

use nazo_identity::{
    PasskeyLoginBegin, PasskeyRegistrationBegin, TenantId, UserId, session::SessionRecord,
};
use nazo_oauth_server::contracts::passkey::PasskeyFuture;
use serde_json::Value;

use super::*;

#[derive(Debug, Eq, PartialEq)]
struct CapturedLoginFinish {
    ceremony_id: String,
    source_ip: String,
    previous_session_id: Option<String>,
    csrf_verified: bool,
    remembered_mfa: Option<RememberedMfaProof>,
}

struct LoginOperations {
    finishes: Mutex<Vec<CapturedLoginFinish>>,
    result: Mutex<Option<Result<LoginSuccess, PasskeyEndpointError>>>,
}

impl PasskeyLoginOperations for LoginOperations {
    fn login_begin(&self, _email: String) -> PasskeyFuture<'_, PasskeyLoginBegin> {
        Box::pin(async { Err(PasskeyEndpointError::Core(PasskeyError::LoginFailed)) })
    }

    fn login_finish(&self, command: PasskeyLoginFinishCommand) -> PasskeyFuture<'_, LoginSuccess> {
        self.finishes.lock().unwrap().push(CapturedLoginFinish {
            ceremony_id: command.ceremony_id,
            source_ip: command.source_ip,
            previous_session_id: command.previous_session_id,
            csrf_verified: command.csrf_verified,
            remembered_mfa: command.remembered_mfa,
        });
        let result = self.result.lock().unwrap().take().unwrap();
        Box::pin(async move { result })
    }
}

struct RateLimit {
    subjects: Mutex<Vec<String>>,
    result: Result<(), AuthenticationRateLimitError>,
}

impl AuthenticationRateLimit for RateLimit {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> nazo_oauth_server::contracts::local_registration::LocalRegistrationFuture<
        'a,
        Result<(), AuthenticationRateLimitError>,
    > {
        self.subjects.lock().unwrap().push(subject.to_owned());
        let result = self.result;
        Box::pin(async move { result })
    }
}

struct ProfileOperations {
    contexts: Mutex<Vec<PasskeyProfileContext>>,
}

impl PasskeyProfileOperations for ProfileOperations {
    fn registration_begin(
        &self,
        context: PasskeyProfileContext,
        _label: Option<String>,
    ) -> PasskeyFuture<'_, PasskeyRegistrationBegin> {
        self.contexts.lock().unwrap().push(context);
        Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
    }

    fn registration_finish(
        &self,
        command: PasskeyRegistrationFinishCommand,
    ) -> PasskeyFuture<'_, PasskeyCredential> {
        self.contexts.lock().unwrap().push(command.context);
        Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
    }

    fn list_summaries(
        &self,
        context: PasskeyProfileContext,
    ) -> PasskeyFuture<'_, Vec<PasskeyCredentialSummary>> {
        self.contexts.lock().unwrap().push(context);
        Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
    }

    fn delete(&self, context: PasskeyProfileContext, _passkey_id: Uuid) -> PasskeyFuture<'_, ()> {
        self.contexts.lock().unwrap().push(context);
        Box::pin(async { Err(PasskeyEndpointError::SessionMissing) })
    }
}

fn login_endpoint(
    result: Result<LoginSuccess, PasskeyEndpointError>,
    rate_result: Result<(), AuthenticationRateLimitError>,
) -> (PasskeyLoginEndpoint, Arc<LoginOperations>, Arc<RateLimit>) {
    let operations = Arc::new(LoginOperations {
        finishes: Mutex::new(Vec::new()),
        result: Mutex::new(Some(result)),
    });
    let rate_limit = Arc::new(RateLimit {
        subjects: Mutex::new(Vec::new()),
        result: rate_result,
    });
    (
        PasskeyLoginEndpoint::new(
            operations.clone(),
            rate_limit.clone(),
            ClientIpConfig::new(&[], crate::http::ClientIpHeaderMode::None),
            PasskeyLoginConfig::new("session", "csrf", "remembered", 900, true),
        ),
        operations,
        rate_limit,
    )
}

fn profile_endpoint() -> (PasskeyProfileEndpoint, Arc<ProfileOperations>) {
    let operations = Arc::new(ProfileOperations {
        contexts: Mutex::new(Vec::new()),
    });
    (
        PasskeyProfileEndpoint::new(
            operations.clone(),
            PasskeyProfileConfig::new("session", "csrf", true),
        ),
        operations,
    )
}

fn login_success() -> LoginSuccess {
    LoginSuccess {
        session_id: "new-session".to_owned(),
        csrf_token: "new-csrf".to_owned(),
        session: SessionRecord::new(
            UserId::new(Uuid::from_u128(1)).unwrap(),
            0,
            jiff::Timestamp::now().as_second(),
            vec!["passkey".to_owned()],
            false,
            Some("oidc-session".to_owned()),
        ),
    }
}

fn authentication_response() -> AuthenticationResponse {
    AuthenticationResponse {
        id: "credential".to_owned(),
        authenticator_data: "authenticator-data".to_owned(),
        signature: "signature".to_owned(),
        client_data_json: "client-data".to_owned(),
        user_handle: None,
    }
}

async fn response_json(response: Response) -> Value {
    assert_no_store(response.headers());
    serde_json::from_slice(&response.into_body()).unwrap()
}

fn assert_no_store(headers: &header::HeaderMap) {
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
}

#[test]
fn login_finish_extracts_security_context_and_sets_only_bound_session_material() {
    futures_executor::block_on(async {
        let (endpoint, operations, rate_limit) = login_endpoint(Ok(login_success()), Ok(()));
        let response = passkey_login_finish(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .extension(crate::integration::ConnectionFacts {
                    peer_addr: Some("203.0.113.9:45123".parse().unwrap()),
                    ..Default::default()
                })
                .header(
                    header::COOKIE,
                    (Cookie::new("session", "old-session")).to_string(),
                )
                .header(
                    header::COOKIE,
                    (Cookie::new("remembered", " remembered-secret ")).to_string(),
                )
                .header(header::USER_AGENT, " passkey-test-agent ")
                .body(Bytes::new())
                .unwrap(),
            Ok(PasskeyLoginFinishRequest {
                ceremony_id: "ceremony".to_owned(),
                response: authentication_response(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("session=new-session;"))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("csrf=new-csrf;"))
        );
        let body = response_json(response).await;
        assert_eq!(
            body,
            json!({"expires_in": 900, "csrf_token": "new-csrf", "mfa_required": false})
        );

        assert_eq!(
            rate_limit.subjects.lock().unwrap().as_slice(),
            ["203.0.113.9"]
        );
        let finishes = operations.finishes.lock().unwrap();
        assert_eq!(
            finishes.as_slice(),
            [CapturedLoginFinish {
                ceremony_id: "ceremony".to_owned(),
                source_ip: "203.0.113.9".to_owned(),
                previous_session_id: Some("old-session".to_owned()),
                csrf_verified: false,
                remembered_mfa: Some(RememberedMfaProof {
                    token_hash: blake3_hex("remembered-secret"),
                    user_agent_hash: Some(blake3_hex("passkey-test-agent")),
                }),
            }]
        );
    });
}

#[test]
fn login_only_allows_uv_initialization_with_the_existing_session_csrf_proof() {
    futures_executor::block_on(async {
        for (cookies, token, expected_session, expected_verified) in [
            (None, None, None, false),
            (Some("csrf=proof"), Some("proof"), None, false),
            (
                Some("session=old-session; csrf=proof"),
                None,
                Some("old-session"),
                false,
            ),
            (
                Some("session=old-session; csrf=proof"),
                Some("wrong"),
                Some("old-session"),
                false,
            ),
            (
                Some("session=old-session; csrf=proof"),
                Some("proof"),
                Some("old-session"),
                true,
            ),
        ] {
            let (endpoint, operations, _) = login_endpoint(Ok(login_success()), Ok(()));
            let mut request = http::Request::builder().method("POST");
            if let Some(cookies) = cookies {
                request = request.header(header::COOKIE, cookies);
            }
            if let Some(token) = token {
                request = request.header("x-csrf-token", token);
            }
            let response = passkey_login_finish(
                &endpoint,
                &request.body(Bytes::new()).unwrap(),
                Ok(PasskeyLoginFinishRequest {
                    ceremony_id: "ceremony".to_owned(),
                    response: authentication_response(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let finishes = operations.finishes.lock().unwrap();
            assert_eq!(finishes[0].csrf_verified, expected_verified);
            assert_eq!(finishes[0].previous_session_id.as_deref(), expected_session);
        }
    });
}

#[test]
fn rate_limit_response_preserves_retry_after_and_does_not_call_core() {
    futures_executor::block_on(async {
        let (endpoint, operations, _) = login_endpoint(
            Ok(login_success()),
            Err(AuthenticationRateLimitError::Limited {
                retry_after_seconds: 17,
            }),
        );
        let response = passkey_login_finish(
            &endpoint,
            &http::Request::builder()
                .method("POST")
                .body(Bytes::new())
                .unwrap(),
            Ok(PasskeyLoginFinishRequest {
                ceremony_id: "ceremony".to_owned(),
                response: authentication_response(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "17");
        assert_eq!(
            response_json(response).await["error"],
            "temporarily_unavailable"
        );
        assert!(operations.finishes.lock().unwrap().is_empty());
    });
}

#[test]
fn missing_profile_session_clears_both_cookies_with_exact_protocol_error() {
    futures_executor::block_on(async {
        let (endpoint, operations) = profile_endpoint();
        let response = passkey_list(
            &endpoint,
            &http::Request::builder()
                .header(
                    header::COOKIE,
                    (Cookie::new("session", "missing-session")).to_string(),
                )
                .body(Bytes::new())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(
            response_json(response).await,
            json!({
                "error": "login_required",
                "error_description": "Request failed."
            })
        );
        assert_eq!(operations.contexts.lock().unwrap().len(), 1);
    });
}

#[test]
fn write_rejects_invalid_csrf_before_session_or_core_lookup() {
    futures_executor::block_on(async {
        let (endpoint, operations) = profile_endpoint();
        let response = passkey_delete(
            &endpoint,
            &http::Request::builder()
                .method("DELETE")
                .header(
                    header::COOKIE,
                    (Cookie::new("session", "session-id")).to_string(),
                )
                .body(Bytes::new())
                .unwrap(),
            Uuid::from_u128(5),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({
                "error": "invalid_request",
                "error_description": "Request failed."
            })
        );
        assert!(operations.contexts.lock().unwrap().is_empty());
    });
}

#[test]
fn public_passkey_projection_excludes_tenant_user_and_credential_material() {
    futures_executor::block_on(async {
        let now = jiff::Timestamp::now();
        let credential = PasskeyCredential {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::new(Uuid::from_u128(2)).unwrap(),
            user_id: UserId::new(Uuid::from_u128(3)).unwrap(),
            credential: serde_json::from_value(json!({"id": [1,2,3], "counter": 9,
            "public_key_cose": [164,1,1,3,39,32,6,33], "transports": ["internal"],
            "aaguid": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}))
            .unwrap(),
            label: "Laptop".to_owned(),
            last_used_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let summary = PasskeyCredentialSummary::from(credential.clone());
        let list = response_json(passkey_list_response(std::slice::from_ref(&summary))).await;
        let public = &list["passkeys"][0];
        let public = public.as_object().unwrap();
        assert_eq!(public.len(), 7);
        assert_eq!(public["id"], json!(credential.id));
        assert_eq!(public["label"], "Laptop");
        assert_eq!(public["credential_id"], "AQID");
        assert_eq!(public["sign_count"], 9);
        for forbidden in ["tenant_id", "user_id", "credential"] {
            assert!(
                public.get(forbidden).is_none(),
                "must not expose {forbidden}"
            );
        }
        let created = response_json(passkey_created_response(credential.clone())).await;
        assert_eq!(created, list["passkeys"][0]);

        for response in [
            passkey_list_response(std::slice::from_ref(&summary)),
            passkey_created_response(credential),
            empty_response_no_store(StatusCode::NO_CONTENT),
        ] {
            assert_no_store(response.headers());
        }
    });
}

fn assert_security_headers(headers: &header::HeaderMap) {
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
}

#[test]
fn login_routes_preserve_post_only_no_cors_surface() {
    futures_executor::block_on(async {
        let (endpoint, _, _) = login_endpoint(Ok(login_success()), Ok(()));
        let service = endpoint;

        for path in ["/auth/passkey/begin", "/auth/passkey/finish"] {
            for method in [
                http::Method::GET,
                http::Method::DELETE,
                http::Method::OPTIONS,
            ] {
                let response = {
                    let request = http::Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .header(header::ORIGIN, "https://app.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .body(Bytes::new())
                        .unwrap();
                    let mut response =
                        crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
                    crate::http::apply_security_headers(response.headers_mut(), false);
                    response
                };
                assert_eq!(
                    response.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path}"
                );
                assert_eq!(response.headers().get(header::ALLOW).unwrap(), "POST");
                assert!(response.headers().get(header::CONTENT_TYPE).is_none());
                assert!(
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .is_none()
                );
                assert_security_headers(response.headers());
                assert!(response.into_body().is_empty());
            }
        }

        let malformed = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/auth/passkey/begin")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from("{}"))
                .unwrap();
            let mut response = passkey_login_begin(
                &service,
                &request,
                crate::http::parse_json(&request).map_err(|_| ()),
            )
            .await;
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_no_store(malformed.headers());
        assert_security_headers(malformed.headers());
        let body: Value = serde_json::from_slice::<Value>(malformed.body()).unwrap();
        assert_eq!(body["error"], "invalid_request");
    });
}

#[test]
fn profile_routes_preserve_wrong_method_cors_and_security_contract() {
    futures_executor::block_on(async {
        let allowed_origins = vec!["https://app.example".to_owned()];

        for (method, path, allowed_method) in [
            (http::Method::POST, "/auth/me/passkeys", "GET"),
            (
                http::Method::GET,
                "/auth/me/passkeys/registration/begin",
                "POST",
            ),
            (
                http::Method::DELETE,
                "/auth/me/passkeys/registration/finish",
                "POST",
            ),
            (
                http::Method::POST,
                "/auth/me/passkeys/00000000-0000-0000-0000-000000000001",
                "DELETE",
            ),
        ] {
            let response = {
                let request = http::Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .header(header::ORIGIN, "https://app.example")
                    .body(Bytes::new())
                    .unwrap();
                let mut response =
                    crate::routes::resolve(request.method(), request.uri().path()).unwrap_err();
                crate::http::apply_cors_headers(
                    crate::http::CorsPolicy::AuthApi,
                    &request,
                    &allowed_origins,
                    response.headers_mut(),
                );
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
            assert_eq!(
                response.headers().get(header::ALLOW).unwrap(),
                allowed_method
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://app.example"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .unwrap(),
                "true"
            );
            assert_security_headers(response.headers());
            assert!(response.into_body().is_empty());
        }
    });
}

#[test]
fn profile_routes_preserve_get_post_delete_options_preflight_contract() {
    futures_executor::block_on(async {
        let (endpoint, _) = profile_endpoint();
        let allowed_origins = vec!["https://app.example".to_owned()];
        let service = endpoint;

        for (path, method) in [
            ("/auth/me/passkeys", "GET"),
            ("/auth/me/passkeys/registration/begin", "POST"),
            ("/auth/me/passkeys/registration/finish", "POST"),
            (
                "/auth/me/passkeys/00000000-0000-0000-0000-000000000001",
                "DELETE",
            ),
        ] {
            let response = {
                let request = http::Request::builder()
                    .method(http::Method::OPTIONS)
                    .uri(path)
                    .header(header::ORIGIN, "https://app.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type, x-csrf-token",
                    )
                    .body(Bytes::new())
                    .unwrap();
                let mut response = crate::http::cors_preflight(
                    crate::http::CorsPolicy::AuthApi,
                    &request,
                    &allowed_origins,
                )
                .unwrap();
                crate::http::apply_security_headers(response.headers_mut(), false);
                response
            };
            assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
            assert!(response.headers().get(header::CONTENT_TYPE).is_none());
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "https://app.example"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                    .unwrap(),
                "true"
            );
            assert_security_headers(response.headers());
            assert!(response.into_body().is_empty());
        }

        let malformed = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/auth/me/passkeys/registration/finish")
                .header(header::ORIGIN, "https://app.example")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from("{}"))
                .unwrap();
            let mut response = passkey_registration_finish(
                &service,
                &request,
                crate::http::parse_json(&request).map_err(|_| ()),
            )
            .await;
            crate::http::apply_cors_headers(
                crate::http::CorsPolicy::AuthApi,
                &request,
                &allowed_origins,
                response.headers_mut(),
            );
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            malformed
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://app.example"
        );
        assert_no_store(malformed.headers());
        assert_security_headers(malformed.headers());
        let body: Value = serde_json::from_slice::<Value>(malformed.body()).unwrap();
        assert_eq!(body["error"], "invalid_request");

        let rejected = {
            let request = http::Request::builder()
                .method(http::Method::OPTIONS)
                .uri("/auth/me/passkeys")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "TRACE")
                .body(Bytes::new())
                .unwrap();
            let mut response = crate::http::cors_preflight(
                crate::http::CorsPolicy::AuthApi,
                &request,
                &allowed_origins,
            )
            .unwrap();
            crate::http::apply_security_headers(response.headers_mut(), false);
            response
        };
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(
            rejected
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_security_headers(rejected.headers());
    });
}
