use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::service::Service;
use nazoauth::integration::conformance;
use tower::service_fn;

#[tokio::test]
async fn independent_hyper_host_builds_mounts_and_passes_shared_conformance() {
    for prefix in ["/", "/testauth", "/nested/testauth"] {
        for optional in [false, true] {
            let state = super::infrastructure(optional).await;
            let mut configuration = state.settings.application_configuration();
            let suffix = prefix.trim_end_matches('/');
            configuration.endpoint.issuer = format!("https://issuer.example{suffix}");
            configuration.endpoint.mtls_endpoint_base_url = format!("https://mtls.example{suffix}");
            configuration.protocol.protected_resource_identifier =
                format!("https://issuer.example{suffix}/fapi/resource");
            configuration.endpoint.cors_allowed_origins =
                vec!["https://browser.example".to_owned()];
            let capabilities =
                crate::test_support::facade::capabilities(&state, Default::default()).unwrap();
            let application = nazoauth_hyper_embedding::build(
                configuration,
                capabilities,
                format!("hyper-{}", uuid::Uuid::now_v7()),
                prefix,
            )
            .await
            .unwrap();
            let existing = service_fn(|request: Request<Full<Bytes>>| async move {
                Ok::<_, Infallible>(if request.uri().path() == "/api/health" {
                    Response::new(Full::new(Bytes::from_static(b"existing-api")))
                } else {
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                })
            });
            let conflict = format!("{suffix}/token");
            assert!(
                nazoauth_hyper_embedding::mount(
                    application.clone(),
                    existing,
                    &[conflict.as_str()],
                )
                .is_err()
            );
            let service =
                nazoauth_hyper_embedding::mount(application.clone(), existing, &["/api/"]).unwrap();
            conformance::assert_adapter(&application, |request| {
                let service = &service;
                async move {
                    let response = service.call(request.map(Full::new)).await.unwrap();
                    let (head, body) = response.into_parts();
                    Response::from_parts(head, body.collect().await.unwrap().to_bytes())
                }
            })
            .await;
            let response = service
                .call(
                    Request::builder()
                        .uri("/api/health")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "existing-api"
            );

            let target = format!("{suffix}/.well-known/openid-configuration");
            let request = Request::builder()
                .uri(target)
                .body(Full::new(Bytes::new()))
                .unwrap();
            // Exercise the same service on Tokio's native Send task boundary.
            let response = tokio::spawn(async move { service.call(request).await.unwrap() })
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}
