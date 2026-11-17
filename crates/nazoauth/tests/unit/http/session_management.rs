use bytes::Bytes;
use cookie::Cookie;
use http::{Method, StatusCode, header};

use nazo_oauth_server::contracts::session_management::{
    SessionManagementFuture, SessionManagementOriginFuture,
};

use super::*;

#[derive(Clone)]
struct TestOperations {
    availability: SessionManagementAvailability,
    origin_allowed: bool,
    op_browser_state: Result<Option<String>, SessionManagementError>,
}

impl SessionManagementOperations for TestOperations {
    fn acquire_request(&self) -> Option<nazo_runtime_modules::RequestLease> {
        use nazo_runtime_modules::{
            ActiveModuleSnapshot, CapabilityAdmission, ModuleId, ModuleRevision, SnapshotStore,
        };
        SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting: if matches!(self.availability, SessionManagementAvailability::Enabled) {
                [ModuleId::SessionManagement].into()
            } else {
                Default::default()
            },
            draining: if matches!(self.availability, SessionManagementAvailability::Draining) {
                [ModuleId::SessionManagement].into()
            } else {
                Default::default()
            },
        })
        .lease(
            ModuleId::SessionManagement,
            CapabilityAdmission::ExistingTransaction,
        )
    }

    fn is_origin_allowed<'a>(
        &'a self,
        _client_id: &'a str,
        _origin: &'a str,
    ) -> SessionManagementOriginFuture<'a> {
        let allowed = self.origin_allowed;
        Box::pin(async move { Ok(allowed) })
    }

    fn op_browser_state<'a>(&'a self, _session_id: &'a str) -> SessionManagementFuture<'a> {
        let result = self.op_browser_state.clone();
        Box::pin(async move { result })
    }
}

fn endpoint(availability: SessionManagementAvailability) -> SessionManagementEndpoint {
    SessionManagementEndpoint::new(
        Arc::new(TestOperations {
            availability,
            origin_allowed: true,
            op_browser_state: Ok(Some("opbs-1".to_owned())),
        }),
        SessionManagementConfig::new("https://issuer.example", "sid"),
    )
}

#[test]
fn iframe_document_escapes_executable_string_context() {
    let html = session_management_iframe_document(
        "https://issuer.example/check?x=1&y='z'\u{2028}</script>",
    );
    assert!(html.contains("x=1\\u0026y=\\'z\\'\\u2028\\u003c/script\\u003e"));
    assert!(!html.contains("</script></script>"));
    assert!(html.contains("new XMLHttpRequest()"));
    assert!(!html.contains("fetch("));
}

#[test]
fn disabled_enabled_and_draining_route_contracts_are_stable() {
    futures_executor::block_on(async {
        for (availability, enabled) in [
            (SessionManagementAvailability::Disabled, false),
            (SessionManagementAvailability::Enabled, true),
            (SessionManagementAvailability::Draining, true),
        ] {
            let app = endpoint(availability);

            for (uri, iframe) in [
                ("/check_session", true),
                (
                    "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state=invalid.salt",
                    false,
                ),
            ] {
                for method in [Method::GET, Method::POST, Method::OPTIONS] {
                    let mut request = http::Request::builder()
                        .method(method.clone())
                        .uri(uri)
                        .header(header::ORIGIN, "https://client.example");
                    if !iframe {
                        request = request.header(
                            header::COOKIE,
                            (Cookie::new("sid", "session-1")).to_string(),
                        );
                    }
                    let response = {
                        let request = request.body(Bytes::new()).unwrap();
                        let mut response = if request.method() != Method::GET {
                            crate::routes::resolve(request.method(), request.uri().path())
                                .unwrap_err()
                        } else if iframe {
                            check_session_iframe(&app).await
                        } else {
                            check_session_status(
                                &app,
                                &request,
                                crate::http::parse_query(&request).unwrap(),
                            )
                            .await
                        };
                        crate::http::apply_security_headers(response.headers_mut(), iframe);
                        response
                    };
                    let served = method == Method::GET && enabled;
                    assert_eq!(
                        response.status(),
                        if served {
                            StatusCode::OK
                        } else if method != Method::GET {
                            StatusCode::METHOD_NOT_ALLOWED
                        } else {
                            StatusCode::NOT_FOUND
                        },
                        "{availability:?} {method} {uri}"
                    );
                    if method != Method::GET {
                        assert_eq!(response.headers().get(header::ALLOW).unwrap(), "GET");
                    }
                    assert!(
                        response
                            .headers()
                            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                            .is_none()
                    );
                    assert_eq!(
                        response
                            .headers()
                            .get(header::X_CONTENT_TYPE_OPTIONS)
                            .unwrap(),
                        "nosniff"
                    );
                    assert_eq!(
                        response.headers().get("Referrer-Policy").unwrap(),
                        "no-referrer"
                    );
                    if served {
                        assert_eq!(
                            response.headers().get(header::CACHE_CONTROL).unwrap(),
                            "no-store"
                        );
                        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
                    } else {
                        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
                        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
                    }
                    if iframe {
                        assert!(response.headers().get(header::X_FRAME_OPTIONS).is_none());
                    } else {
                        assert_eq!(
                            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                            "DENY"
                        );
                    }
                }
            }
        }
    });
}

#[test]
fn status_is_unchanged_only_for_the_bound_live_session() {
    futures_executor::block_on(async {
        let state = nazo_auth::issue_oidc_session_state(
            "client-1",
            "https://client.example/callback",
            "opbs-1",
        )
        .expect("HTTPS callback has a browser origin");
        let uri = format!(
            "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state={state}"
        );
        let app = endpoint(SessionManagementAvailability::Enabled);
        let response = {
            let request = http::Request::builder()
                .uri(&uri)
                .header(
                    header::COOKIE,
                    (Cookie::new("sid", "session-1")).to_string(),
                )
                .body(Bytes::new())
                .unwrap();
            check_session_status(&app, &request, crate::http::parse_query(&request).unwrap()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body(), r#"{"status":"unchanged"}"#.as_bytes());
    });
}

#[test]
fn status_rejects_an_origin_not_registered_for_the_client() {
    futures_executor::block_on(async {
        let state = nazo_auth::issue_oidc_session_state(
            "client-1",
            "https://client.example/callback",
            "opbs-1",
        )
        .expect("HTTPS callback has a browser origin");
        let operations = Arc::new(TestOperations {
            availability: SessionManagementAvailability::Enabled,
            origin_allowed: false,
            op_browser_state: Ok(Some("opbs-1".to_owned())),
        });
        let endpoint = SessionManagementEndpoint::new(
            operations,
            SessionManagementConfig::new("https://issuer.example", "sid"),
        );
        let app = endpoint;
        let uri = format!(
            "/check_session/status?client_id=client-1&origin=https%3A%2F%2Fclient.example&session_state={state}"
        );
        let response = {
            let request = http::Request::builder()
                .uri(&uri)
                .header(
                    header::COOKIE,
                    (Cookie::new("sid", "session-1")).to_string(),
                )
                .body(Bytes::new())
                .unwrap();
            check_session_status(&app, &request, crate::http::parse_query(&request).unwrap()).await
        };
        assert_eq!(response.into_body(), r#"{"status":"error"}"#.as_bytes());
    });
}

#[derive(Clone, Copy, Debug)]
enum SessionManagementAvailability {
    Disabled,
    Enabled,
    Draining,
}

struct PendingOperations {
    runtime: Arc<nazo_runtime_modules::SnapshotStore>,
    ready: std::sync::atomic::AtomicBool,
}

impl SessionManagementOperations for PendingOperations {
    fn acquire_request(&self) -> Option<nazo_runtime_modules::RequestLease> {
        self.runtime.lease(
            nazo_runtime_modules::ModuleId::SessionManagement,
            nazo_runtime_modules::CapabilityAdmission::ExistingTransaction,
        )
    }

    fn is_origin_allowed<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> SessionManagementOriginFuture<'a> {
        Box::pin(std::future::poll_fn(|_| {
            if self.ready.load(std::sync::atomic::Ordering::SeqCst) {
                std::task::Poll::Ready(Ok(true))
            } else {
                std::task::Poll::Pending
            }
        }))
    }

    fn op_browser_state<'a>(&'a self, _: &'a str) -> SessionManagementFuture<'a> {
        Box::pin(async { Ok(Some("opbs-1".into())) })
    }
}

#[test]
fn http_request_holds_its_lease_across_await_and_releases_on_completion_or_cancellation() {
    use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision, SnapshotStore};
    use std::{
        future::Future,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll, Waker},
    };

    for cancel in [false, true] {
        let runtime = Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting: [ModuleId::SessionManagement].into(),
            draining: Default::default(),
        }));
        let operations = Arc::new(PendingOperations {
            runtime: runtime.clone(),
            ready: AtomicBool::new(false),
        });
        let endpoint = SessionManagementEndpoint::new(
            operations.clone(),
            SessionManagementConfig::new("https://issuer.example", "sid"),
        );
        let http_request = http::Request::builder()
            .header(header::COOKIE, Cookie::new("sid", "session-1").to_string())
            .body(Bytes::new())
            .unwrap();
        let request = || {
            check_session_status(
                &endpoint,
                &http_request,
                CheckSessionStatusQuery {
                    client_id: "client-1".into(),
                    origin: "https://client.example".into(),
                    session_state: nazo_auth::issue_oidc_session_state(
                        "client-1",
                        "https://client.example/callback",
                        "opbs-1",
                    )
                    .unwrap(),
                },
            )
        };
        let mut context = Context::from_waker(Waker::noop());
        let mut admitted = Box::pin(request());
        assert!(admitted.as_mut().poll(&mut context).is_pending());
        runtime
            .compare_and_publish(
                ModuleRevision::new(1),
                ActiveModuleSnapshot {
                    revision: ModuleRevision::new(2),
                    accepting: Default::default(),
                    draining: Default::default(),
                },
            )
            .unwrap();
        let mut rejected = Box::pin(request());
        let Poll::Ready(response) = rejected.as_mut().poll(&mut context) else {
            panic!("closed admission must reject without reaching the pending lookup");
        };
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let mut drain = Box::pin(runtime.wait_until_idle(ModuleId::SessionManagement));
        assert!(drain.as_mut().poll(&mut context).is_pending());
        if !cancel {
            operations.ready.store(true, Ordering::SeqCst);
            let Poll::Ready(response) = admitted.as_mut().poll(&mut context) else {
                panic!("the admitted request must finish after admission closes");
            };
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            drop(admitted);
        }
        assert!(drain.as_mut().poll(&mut context).is_ready());
    }
}
