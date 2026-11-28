use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use axum::{body::Body, extract::ConnectInfo};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use nazoauth::{ConnectionFacts, NazoAuth, integration::conformance};
use tower::{Service, ServiceExt};

async fn application(prefix: &str, optional: bool) -> Arc<NazoAuth> {
    let state = super::infrastructure(optional).await;
    let mut configuration = state.settings.application_configuration();
    let suffix = prefix.trim_end_matches('/');
    configuration.endpoint.issuer = format!("https://issuer.example{suffix}");
    configuration.endpoint.mtls_endpoint_base_url = format!("https://mtls.example{suffix}");
    configuration.protocol.protected_resource_identifier =
        "https://issuer.example/business/resource%2Fone".to_owned();
    configuration.endpoint.cors_allowed_origins = vec!["https://browser.example".to_owned()];
    let capabilities =
        crate::test_support::facade::capabilities(&state, Default::default()).unwrap();
    Arc::new(
        nazoauth::NazoAuthBuilder::new(
            configuration,
            capabilities,
            format!("axum-{}", uuid::Uuid::now_v7()),
        )
        .mount_path(prefix)
        .build()
        .await
        .unwrap(),
    )
}

pub(super) async fn standard_response(response: Response<Body>) -> Response<Bytes> {
    let (head, body) = response.into_parts();
    Response::from_parts(head, body.collect().await.unwrap().to_bytes())
}

#[tokio::test]
async fn independent_axum_host_mounts_once_and_passes_shared_conformance() {
    for prefix in ["/", "/tenant/auth-v2.1_~"] {
        for optional in [false, true] {
            let auth = application(prefix, optional).await;
            let suffix = prefix.trim_end_matches('/');
            let app = nazoauth_axum_embedding::application(auth.clone()).unwrap();
            conformance::assert_adapter(&auth, |mut request| {
                // A prepared, authenticated ingress fact takes precedence over
                // the underlying connection's independently supplied address.
                request.extensions_mut().insert(ConnectInfo(
                    "198.51.100.21:54123".parse::<SocketAddr>().unwrap(),
                ));
                let app = app.clone();
                async move {
                    standard_response(app.oneshot(request.map(Body::from)).await.unwrap()).await
                }
            })
            .await;

            for (method, path, status, body) in [
                (
                    Method::GET,
                    "/api/health".to_owned(),
                    StatusCode::OK,
                    "existing-api",
                ),
                (
                    Method::GET,
                    "/users/me".to_owned(),
                    StatusCode::OK,
                    "existing-user",
                ),
                (
                    Method::GET,
                    format!("{suffix}/ui"),
                    StatusCode::OK,
                    "host-owned-ui",
                ),
                (
                    Method::GET,
                    "/api/missing".to_owned(),
                    StatusCode::NOT_FOUND,
                    "host-fallback",
                ),
                (
                    Method::POST,
                    "/api/health".to_owned(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "host-method-not-allowed",
                ),
            ] {
                let response = standard_response(
                    app.clone()
                        .oneshot(
                            Request::builder()
                                .method(method)
                                .uri(&path)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap(),
                )
                .await;
                assert_eq!(response.status(), status, "{path}");
                assert_eq!(response.body(), body, "{path}");
            }

            if prefix != "/" {
                for path in [
                    "/host-missing".to_owned(),
                    format!("{prefix}2/token"),
                    "/.well-known/oauth-protected-resource/business/resource/one".to_owned(),
                    "/.well-known/oauth-protected-resource/business/resource%2fone".to_owned(),
                ] {
                    let response = standard_response(
                        app.clone()
                            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                            .await
                            .unwrap(),
                    )
                    .await;
                    assert_eq!(response.status(), StatusCode::NOT_FOUND);
                    assert_eq!(response.body(), "host-fallback");
                }
            }

            for path in auth.mount().discovery_paths() {
                let request = Request::builder().uri(path).body(Bytes::new()).unwrap();
                let expected = auth.handle(request.clone()).await;
                let actual =
                    standard_response(app.clone().oneshot(request.map(Body::from)).await.unwrap())
                        .await;
                assert_eq!(actual.status(), StatusCode::OK, "{path}");
                conformance::assert_response(&expected, &actual);
                assert!(
                    nazo_http_tower::axum::mount(axum::Router::new(), auth.clone(), &[path])
                        .is_err(),
                    "accepted discovery collision {path}"
                );
            }
            let conflict = format!("{suffix}/token");
            assert!(
                nazo_http_tower::axum::mount(axum::Router::new(), auth.clone(), &[&conflict])
                    .is_err()
            );

            // Escaped letters affect routing only; repeated query values and
            // Content-Encoding remain part of the original external request.
            const GZIP: &[u8] = &[
                31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 75, 47, 74, 204, 43, 137, 47, 169, 44, 72, 181,
                77, 206, 79, 73, 85, 75, 71, 240, 139, 82, 211, 138, 82, 139, 51, 226, 75, 242,
                179, 83, 243, 0, 10, 63, 124, 67, 40, 0, 0, 0,
            ];
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(format!("{suffix}/%74oken?state=%2F&state=two"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::CONTENT_ENCODING, "gzip")
                .body(Bytes::from_static(
                    b"grant_type=code&grant_type=refresh_token",
                ))
                .unwrap();
            request.extensions_mut().insert(ConnectionFacts {
                peer_addr: Some("192.0.2.20:43125".parse().unwrap()),
                ..ConnectionFacts::default()
            });
            let expected = auth.handle(request.clone()).await;
            let actual = standard_response(
                app.clone()
                    .oneshot(request.map(|_| Body::from(Bytes::from_static(GZIP))))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(actual.status(), StatusCode::BAD_REQUEST);
            conformance::assert_response(&expected, &actual);

            for (method, path, status) in [
                (Method::GET, "/token", StatusCode::METHOD_NOT_ALLOWED),
                (
                    Method::POST,
                    "/openid4vci/credential",
                    StatusCode::NOT_FOUND,
                ),
            ] {
                let body = futures_util::stream::poll_fn(
                    |_: &mut Context<'_>| -> Poll<Option<Result<Bytes, io::Error>>> {
                        panic!("rejected Axum request must not poll its payload")
                    },
                );
                let request = Request::builder()
                    .method(method)
                    .uri(format!("{suffix}{path}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from_stream(body))
                    .unwrap();
                assert_eq!(app.clone().oneshot(request).await.unwrap().status(), status);
            }

            let request = Request::builder()
                .uri(format!("{suffix}/.well-known/openid-configuration"))
                .body(Body::empty())
                .unwrap();
            let response = tokio::spawn(async move { app.oneshot(request).await.unwrap() })
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}

struct ReadyHost {
    poll: usize,
    ready: bool,
    fail: bool,
    expected: Request<Bytes>,
}

impl Clone for ReadyHost {
    fn clone(&self) -> Self {
        Self {
            poll: 0,
            ready: false,
            fail: self.fail,
            expected: self.expected.clone(),
        }
    }
}

impl Service<Request<Full<Bytes>>> for ReadyHost {
    type Response = Response<Full<Bytes>>;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.fail {
            return Poll::Ready(Err(io::Error::other("host unavailable")));
        }
        self.poll += 1;
        match self.poll {
            1 => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            _ => {
                self.ready = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
        assert!(self.ready, "mount called an unready or cloned host service");
        self.ready = false;
        let expected = self.expected.clone();
        Box::pin(async move {
            let (head, body) = request.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            assert_eq!(bytes.as_ptr(), expected.body().as_ptr());
            conformance::assert_request(&expected, &Request::from_parts(head, bytes.clone()));
            Ok(Response::new(Full::new(bytes)))
        })
    }
}

#[tokio::test]
async fn tower_mount_delegates_host_readiness_and_preserves_the_ready_instance() {
    let auth = application("/identity", false).await;
    let mut request = conformance::transport_requests().remove(0);
    *request.uri_mut() = "https://issuer.example/api/%65cho?state=%2F&state=two"
        .parse()
        .unwrap();
    let mut app = nazo_http_tower::mount(
        ReadyHost {
            poll: 0,
            ready: false,
            fail: false,
            expected: request.clone(),
        },
        auth.clone(),
        &["/api"],
    )
    .unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(app.poll_ready(&mut cx).is_pending());
    assert!(matches!(app.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    let mut unavailable = nazo_http_tower::mount(
        ReadyHost {
            poll: 0,
            ready: false,
            fail: true,
            expected: request.clone(),
        },
        auth,
        &["/api"],
    )
    .unwrap();
    match unavailable.poll_ready(&mut cx) {
        Poll::Ready(Err(error)) => assert_eq!(error.to_string(), "host unavailable"),
        actual => panic!("mount lost the host readiness error: {actual:?}"),
    }
    drop(unavailable);
    let pointer = request.body().as_ptr();
    let response = app.call(request.map(Full::new)).await.unwrap();
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ptr(),
        pointer
    );
}
