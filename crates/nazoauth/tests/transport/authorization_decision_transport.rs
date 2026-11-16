pub use crate::http::{ClientIpConfig, SessionCookieConfig};
use crate::http::{Request, Response};
use bytes::Bytes;
use cookie::Cookie;
use http::{StatusCode, header};

use std::sync::{Arc, Mutex};

use crate::http::ClientIpHeaderMode;
use crate::http::{AuthorizationDecisionEndpoint, AuthorizationDecisionForm, authorize_decision};
use nazo_oauth_server::contracts::authorization_decision::{
    AuthorizationDecisionCommand, AuthorizationDecisionError, AuthorizationDecisionFuture,
    AuthorizationDecisionOperations, AuthorizationDecisionResponse,
};
use serde_json::{Value, json};

struct FakeOperations {
    result: Mutex<Result<AuthorizationDecisionResponse, AuthorizationDecisionError>>,
    commands: Mutex<Vec<AuthorizationDecisionCommand>>,
}

impl AuthorizationDecisionOperations for FakeOperations {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_> {
        self.commands.lock().unwrap().push(command);
        let result = self.result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn endpoint(
    result: Result<AuthorizationDecisionResponse, AuthorizationDecisionError>,
) -> (AuthorizationDecisionEndpoint, Arc<FakeOperations>) {
    let operations = Arc::new(FakeOperations {
        result: Mutex::new(result),
        commands: Mutex::new(Vec::new()),
    });
    (
        AuthorizationDecisionEndpoint::new(
            operations.clone(),
            SessionCookieConfig::new("session", "csrf", true),
            ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        ),
        operations,
    )
}

fn request(include_session: bool, csrf: Option<&str>) -> Request {
    let mut request = http::Request::builder()
        .method("POST")
        .extension(crate::integration::ConnectionFacts {
            peer_addr: Some("198.51.100.10:443".parse().unwrap()),
            ..Default::default()
        })
        .header(
            header::COOKIE,
            (Cookie::new("csrf", "csrf-token")).to_string(),
        );
    if include_session {
        request = request.header(
            header::COOKIE,
            (Cookie::new("session", "sid-1")).to_string(),
        );
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    request.body(Bytes::new()).unwrap()
}

fn form(decision: &str, csrf_token: Option<&str>) -> AuthorizationDecisionForm {
    AuthorizationDecisionForm {
        request_id: "request-1".to_owned(),
        decision: decision.to_owned(),
        csrf_token: csrf_token.map(str::to_owned),
    }
}

async fn response_json(response: Response) -> Value {
    serde_json::from_slice(&response.into_body()).unwrap()
}

#[test]
fn csrf_is_checked_before_decision_operations() {
    futures_executor::block_on(async {
        let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
            location: "https://client.example/callback?code=code".to_owned(),
        }));

        let response =
            authorize_decision(&endpoint, &request(true, None), form("approve", None)).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(operations.commands.lock().unwrap().is_empty());
        assert_eq!(response_json(response).await["error"], "invalid_request");
    });
}

#[test]
fn invalid_decision_is_rejected_before_session_or_operations() {
    futures_executor::block_on(async {
        let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
            location: "https://client.example/callback?code=code".to_owned(),
        }));

        let response = authorize_decision(
            &endpoint,
            &request(true, Some("csrf-token")),
            form("other", None),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(operations.commands.lock().unwrap().is_empty());
        assert_eq!(response_json(response).await["error"], "invalid_request");
    });
}

#[test]
fn missing_session_preserves_login_required_and_cookie_clearing() {
    futures_executor::block_on(async {
        let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
            location: "https://client.example/callback?code=code".to_owned(),
        }));

        let response = authorize_decision(
            &endpoint,
            &request(false, Some("csrf-token")),
            form("approve", None),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert!(operations.commands.lock().unwrap().is_empty());
        assert_eq!(response_json(response).await["error"], "login_required");
    });
}

#[test]
fn approved_transport_forwards_typed_command_and_preserves_redirect() {
    futures_executor::block_on(async {
        let location = "https://client.example/callback?code=code&state=state";
        let (endpoint, operations) = endpoint(Ok(AuthorizationDecisionResponse::Redirect {
            location: location.to_owned(),
        }));

        let response = authorize_decision(
            &endpoint,
            &request(true, Some("csrf-token")),
            form("approve", None),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), location);
        let commands = operations.commands.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].request_id, "request-1");
        assert_eq!(commands[0].session_id.as_str(), "sid-1");
        assert_eq!(commands[0].source_ip, "198.51.100.10");
        assert_eq!(
            commands[0].decision,
            nazo_auth::UserAuthorizationDecision::Approve
        );
    });
}

#[test]
fn form_post_decision_returns_no_store_auto_submit_document() {
    futures_executor::block_on(async {
        let (endpoint, _) = endpoint(Ok(AuthorizationDecisionResponse::FormPost {
            action: "https://client.example/callback".to_owned(),
            parameters: vec![("code".to_owned(), "code-value".to_owned())],
            session_state: Some("session-state".to_owned()),
            csp_nonce: "nonce-value".to_owned(),
        }));

        let response = authorize_decision(
            &endpoint,
            &request(true, Some("csrf-token")),
            form("approve", None),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = String::from_utf8(response.into_body().to_vec()).unwrap();
        assert!(body.contains("method=\"post\""));
        assert!(body.contains("name=\"code\" value=\"code-value\""));
        assert!(body.contains("name=\"session_state\" value=\"session-state\""));
    });
}

#[test]
fn domain_failures_keep_existing_status_and_oauth_error_contracts() {
    futures_executor::block_on(async {
        for (error, expected_status, expected_code, expected_description) in [
            (
                AuthorizationDecisionError::LoginRequired,
                StatusCode::UNAUTHORIZED,
                "login_required",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::SessionLookupUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::ConsentInvalid,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::ConsentReadUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::UserMismatch,
                StatusCode::FORBIDDEN,
                "access_denied",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::AuditUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::ApprovalUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Request failed.",
            ),
            (
                AuthorizationDecisionError::UnsupportedResponseMode,
                StatusCode::BAD_REQUEST,
                "unsupported_response_mode",
                "JWT-secured authorization responses are disabled.",
            ),
            (
                AuthorizationDecisionError::ResponseProtectionUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            ),
            (
                AuthorizationDecisionError::ResponseSigningUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            ),
        ] {
            let (endpoint, _) = endpoint(Err(error));
            let response = authorize_decision(
                &endpoint,
                &request(true, Some("csrf-token")),
                form("deny", None),
            )
            .await;
            assert_eq!(response.status(), expected_status, "error={error:?}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "error={error:?}"
            );
            assert_eq!(
                response_json(response).await,
                json!({
                    "error": expected_code,
                    "error_description": expected_description
                }),
                "error={error:?}"
            );
        }
    });
}
