use bytes::Bytes;
use http::{Method, StatusCode, header};
use std::sync::{Arc, Mutex};

use crate::http::{OidcLogoutConfig, OidcLogoutEndpoint, oidc_logout};
use nazo_oauth_server::contracts::oidc_logout::{
    OidcLogoutCommand, OidcLogoutError, OidcLogoutFuture, OidcLogoutOperations, OidcLogoutSuccess,
};

struct Operations {
    result: Mutex<Result<OidcLogoutSuccess, OidcLogoutError>>,
    commands: Mutex<Vec<OidcLogoutCommand>>,
}

impl OidcLogoutOperations for Operations {
    fn logout(&self, command: OidcLogoutCommand) -> OidcLogoutFuture<'_> {
        self.commands.lock().unwrap().push(command);
        let result = self.result.lock().unwrap().clone();
        Box::pin(async move { result })
    }
}

fn operations(result: Result<OidcLogoutSuccess, OidcLogoutError>) -> Arc<Operations> {
    Arc::new(Operations {
        result: Mutex::new(result),
        commands: Mutex::new(Vec::new()),
    })
}

fn endpoint(operations: Arc<Operations>) -> OidcLogoutEndpoint {
    OidcLogoutEndpoint::new(operations, OidcLogoutConfig::new("session", "csrf", true))
}

#[test]
fn get_and_form_post_preserve_parser_cookie_and_no_store_contracts() {
    futures_executor::block_on(async {
        let operations = operations(Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        }));
        let app = endpoint(operations.clone());

        for request in [
            http::Request::builder()
                .uri("/logout?client_id=%20client-a%20&unknown=ignored")
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("session", "sid")).to_string(),
                )
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("csrf", "csrf-value")).to_string(),
                )
                .header("x-csrf-token", "csrf-value")
                .body(Bytes::new())
                .unwrap(),
            http::Request::builder()
                .method("POST")
                .uri("/logout?client_id=client-a")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded; charset=utf-8",
                )
                .body(Bytes::from("state=state-a"))
                .unwrap(),
        ] {
            let response = {
                let request = request;
                {
                    let mut request = request;
                    let body = std::mem::take(request.body_mut());
                    oidc_logout(&app, &request, std::future::ready(Ok(body))).await
                }
            };
            assert_eq!(response.status(), StatusCode::OK);
            assert_no_store(response.headers());
            assert_eq!(
                response
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .count(),
                2
            );
        }
        let commands = operations.commands.lock().unwrap();
        assert_eq!(commands[0].request.client_id.as_deref(), Some(" client-a "));
        assert_eq!(commands[0].session_id.as_deref(), Some("sid"));
        assert!(commands[0].csrf_authorized);
        assert!(!commands[0].user_confirmed);
        assert_eq!(commands[1].request.state.as_deref(), Some("state-a"));
    });
}

#[test]
fn malformed_posts_fail_before_operations_and_do_not_clear_retryable_cookies() {
    futures_executor::block_on(async {
        let operations = operations(Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        }));
        let app = endpoint(operations.clone());

        let cases = [
            (
                http::Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Bytes::from("{}"))
                    .unwrap(),
                StatusCode::BAD_REQUEST,
            ),
            (
                http::Request::builder()
                    .method("POST")
                    .uri("/logout?client_id=a")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Bytes::from("client_id=b"))
                    .unwrap(),
                StatusCode::BAD_REQUEST,
            ),
            (
                http::Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Bytes::from(format!("state={}", "x".repeat(16 * 1024))))
                    .unwrap(),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                http::Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Bytes::from(
                        "_nazo_logout_confirm=false&_nazo_csrf=csrf-value",
                    ))
                    .unwrap(),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (request, expected) in cases {
            let response = {
                let request = request;
                {
                    let mut request = request;
                    let body = std::mem::take(request.body_mut());
                    oidc_logout(&app, &request, std::future::ready(Ok(body))).await
                }
            };
            assert_eq!(response.status(), expected);
            assert_eq!(
                response
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .count(),
                0
            );
        }
        assert!(operations.commands.lock().unwrap().is_empty());
    });
}

#[test]
fn unbound_logout_requires_explicit_csrf_bound_confirmation() {
    futures_executor::block_on(async {
        let operations = operations(Err(OidcLogoutError::ConfirmationRequired));
        let app = endpoint(operations.clone());

        let response = {
            let request = http::Request::builder().uri("/logout?client_id=client-a&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogout&state=state-a").header(header::COOKIE, (cookie::Cookie::new("session", "sid")).to_string()).header(header::COOKIE, (cookie::Cookie::new("csrf", "csrf-value")).to_string()).body(Bytes::new()).unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(response.headers());
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            0
        );
        let body = String::from_utf8(response.into_body().to_vec()).unwrap();
        assert!(body.contains("id=\"nazo-logout-confirmation\""));
        assert!(body.contains("name=\"_nazo_csrf\" value=\"csrf-value\""));
        assert!(body.contains("name=\"client_id\" value=\"client-a\""));
        assert!(
            body.contains("name=\"post_logout_redirect_uri\" value=\"https://rp.example/logout\"")
        );
        assert!(body.contains("name=\"state\" value=\"state-a\""));

        *operations.result.lock().unwrap() = Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        });
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("session", "sid")).to_string(),
                )
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("csrf", "csrf-value")).to_string(),
                )
                .body(Bytes::from(concat!(
                    "_nazo_logout_confirm=true&_nazo_csrf=csrf-value",
                    "&client_id=client-a",
                    "&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogout",
                    "&state=state-a"
                )))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_store(response.headers());
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        let body = String::from_utf8(response.into_body().to_vec()).unwrap();
        assert!(body.contains("id=\"nazo-logout-success\""));

        let commands = operations.commands.lock().unwrap();
        assert_eq!(commands.len(), 2);
        assert!(!commands[0].user_confirmed);
        assert!(commands[1].user_confirmed);
        assert_eq!(commands[1].request.client_id.as_deref(), Some("client-a"));
        assert_eq!(
            commands[1].request.post_logout_redirect_uri.as_deref(),
            Some("https://rp.example/logout")
        );
        assert_eq!(commands[1].request.state.as_deref(), Some("state-a"));
    });
}

#[test]
fn invalid_rp_parameters_are_not_preserved_and_confirmation_errors_do_not_loop() {
    futures_executor::block_on(async {
        let operations = operations(Err(OidcLogoutError::InvalidIdTokenHint));
        let app = endpoint(operations.clone());

        let response = {
            let request = http::Request::builder().uri("/logout?id_token_hint=invalid&client_id=client-a&post_logout_redirect_uri=https%3A%2F%2Frp.example%2Flogout").header(header::COOKIE, (cookie::Cookie::new("session", "sid")).to_string()).header(header::COOKIE, (cookie::Cookie::new("csrf", "csrf-value")).to_string()).body(Bytes::new()).unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(response.into_body().to_vec()).unwrap();
        assert!(body.contains("id=\"nazo-logout-confirmation\""));
        assert!(!body.contains("name=\"id_token_hint\""));
        assert!(!body.contains("name=\"client_id\""));
        assert!(!body.contains("name=\"post_logout_redirect_uri\""));

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/logout")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("session", "sid")).to_string(),
                )
                .header(
                    header::COOKIE,
                    (cookie::Cookie::new("csrf", "csrf-value")).to_string(),
                )
                .body(Bytes::from(
                    "_nazo_logout_confirm=true&_nazo_csrf=csrf-value",
                ))
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(response.into_body().to_vec()).unwrap();
        assert!(!body.contains("nazo-logout-confirmation"));
    });
}

#[test]
fn frontchannel_document_escapes_urls_and_redirect_and_clears_cookies() {
    futures_executor::block_on(async {
        let operations = operations(Ok(OidcLogoutSuccess {
            redirect_uri: Some(
                "https://client.example/after?x='</script>&\r\n\u{2028}\u{2029}\\".to_owned(),
            ),
            frontchannel_logout_urls: vec!["https://client.example/front?x=\"<&".to_owned()],
        }));
        let app = endpoint(operations);
        let response = {
            let request = http::Request::builder()
                .uri("/logout")
                .body(Bytes::new())
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/html; charset=utf-8"
            ))
        );
        assert_no_store(response.headers());
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count();
        let body = response.into_body();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(cookies, 2);
        assert!(body.contains("&quot;&lt;&amp;"));
        assert!(body.contains("\\'\\u003c/script\\u003e\\u0026"));
        assert!(body.contains("\\r\\n\\u2028\\u2029\\\\"));
        assert!(body.contains("id=\"nazo-frontchannel-logout-continue\""));
        assert!(body.contains("href=\"https://client.example/after?x=&#39;&lt;/script&gt;&amp;"));
        assert!(!body.contains("'</script>"));
    });
}

#[test]
fn valkey_delete_failure_is_retryable_and_never_clears_cookies() {
    futures_executor::block_on(async {
        let operations = operations(Err(OidcLogoutError::SessionDeleteUnavailable));
        let app = endpoint(operations);
        let response = {
            let request = http::Request::builder()
                .method(Method::GET)
                .uri("/logout")
                .body(Bytes::new())
                .unwrap();
            {
                let mut request = request;
                let body = std::mem::take(request.body_mut());
                oidc_logout(&app, &request, std::future::ready(Ok(body))).await
            }
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_no_store(response.headers());
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            0
        );
        let body: serde_json::Value =
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": "server_error",
                "error_description": "back-channel logout persistence failed."
            })
        );
    });
}

#[test]
fn options_remains_unhandled_and_never_invokes_logout_operations() {
    futures_executor::block_on(async {
        let operations = operations(Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        }));
        let response = {
            let request = http::Request::builder()
                .method(Method::OPTIONS)
                .uri("/logout")
                .body(Bytes::new())
                .unwrap();
            crate::routes::resolve(request.method(), request.uri().path()).unwrap_err()
        };
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            0
        );
        assert!(operations.commands.lock().unwrap().is_empty());
    });
}

fn assert_no_store(headers: &header::HeaderMap) {
    assert_eq!(
        headers.get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        headers.get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
}

#[test]
fn logout_checks_query_and_content_type_before_polling_a_body() {
    futures_executor::block_on(async {
        let endpoint = endpoint(operations(Ok(OidcLogoutSuccess {
            redirect_uri: None,
            frontchannel_logout_urls: Vec::new(),
        })));
        for (method, uri, status) in [
            (Method::GET, "/logout", StatusCode::OK),
            (
                Method::POST,
                "/logout?client_id=first&client_id=second",
                StatusCode::BAD_REQUEST,
            ),
            (Method::POST, "/logout", StatusCode::BAD_REQUEST),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri(uri)
                .body(Bytes::new())
                .unwrap();
            let body = async { panic!("logout must not poll this body") };
            assert_eq!(
                oidc_logout(&endpoint, &request, body).await.status(),
                status
            );
        }
    });
}

#[test]
fn logout_confirmation_posts_to_the_unmodified_mounted_path() {
    futures_executor::block_on(async {
        let app = endpoint(operations(Err(OidcLogoutError::ConfirmationRequired)));
        let request = http::Request::builder()
            .uri("/tenant/auth/logout?state=a%2Fb")
            .header(header::COOKIE, "session=sid; csrf=csrf-value")
            .body(Bytes::new())
            .unwrap();
        let response = oidc_logout(&app, &request, std::future::ready(Ok(Bytes::new()))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = std::str::from_utf8(response.body()).unwrap();
        assert!(body.contains("action=\"/tenant/auth/logout\""));
        assert!(body.contains("id=\"nazo-logout-cancel\" href=\"/\""));
        assert!(body.contains("name=\"state\" value=\"a/b\""));
        assert_eq!(request.uri(), "/tenant/auth/logout?state=a%2Fb");
    });
}
