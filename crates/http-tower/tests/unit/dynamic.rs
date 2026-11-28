use super::*;
use http::Version;
use http_body_util::Full;
use std::{
    convert::Infallible,
    future::{Ready, ready},
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct Host {
    calls: Arc<AtomicUsize>,
}

impl Service<Request<Full<Bytes>>> for Host {
    type Response = Response<Bytes>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::Relaxed);
        ready(Ok(Response::new(Bytes::copy_from_slice(
            request.uri().path().as_bytes(),
        ))))
    }
}

#[tokio::test]
async fn business_namespaces_bypass_selection_and_unknown_authorities_fail_closed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut mounted = mount_dynamic(
        Host {
            calls: calls.clone(),
        },
        TenantRuntimeRegistry::empty(),
        &["/api"],
    )
    .unwrap();
    for path in ["/api", "/api/missing"] {
        let request = Request::builder()
            .uri(path)
            .header("host", "unknown.example")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = mounted.call(request).await.unwrap();
        assert_eq!(response.body(), path);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    for path in ["/api-extra", "/token", "/.well-known/openid-configuration"] {
        let request = Request::builder()
            .uri(path)
            .header("host", "unknown.example")
            .header("forwarded", "host=trusted.example;proto=https")
            .header("x-forwarded-host", "trusted.example")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = mounted.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().contains_key("x-content-type-options"));
        assert!(response.body().is_empty());
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    for target in ["/token", "https://unknown.example/token"] {
        for host in [None, Some("unknown.example:abc")] {
            let mut request = Request::builder().uri(target);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let response = mounted
                .call(request.body(Full::new(Bytes::new())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.headers().contains_key("x-content-type-options"));
        }
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[test]
fn authority_uses_the_original_transport_authority() {
    let http1 = Request::builder()
        .uri("https://absolute.example/token")
        .header("host", "header.example:8443")
        .header("x-forwarded-host", "untrusted.example")
        .body(())
        .unwrap();
    assert_eq!(request_authority(&http1), Some("absolute.example"));
    let origin = Request::builder()
        .uri("/token")
        .header("host", "header.example:8443")
        .body(())
        .unwrap();
    assert_eq!(request_authority(&origin), Some("header.example:8443"));
    let http2 = Request::builder()
        .uri("https://absolute.example/token")
        .version(Version::HTTP_2)
        .header("host", "header.example")
        .body(())
        .unwrap();
    assert_eq!(request_authority(&http2), None);
    let duplicated = Request::builder()
        .uri("/token")
        .header("host", "first.example")
        .header("host", "second.example")
        .body(())
        .unwrap();
    assert_eq!(request_authority(&duplicated), None);
    let absolute_duplicate = Request::builder()
        .uri("https://absolute.example/token")
        .header("host", "first.example")
        .header("host", "second.example")
        .body(())
        .unwrap();
    assert_eq!(request_authority(&absolute_duplicate), None);
}
