use crate::http::Request;
use crate::http::mtls::MtlsThumbprintExtractor;
use crate::http::{UserinfoEndpoint, userinfo};
use bytes::Bytes;
use http::{StatusCode, header};
use nazo_oauth_server::contracts::userinfo::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct RejectingOperations {
    error: UserinfoError,
    prepares: Arc<AtomicUsize>,
}
impl UserinfoOperations for RejectingOperations {
    fn prepare<'a>(
        &'a self,
        _scheme: AccessTokenAuthScheme,
        _token: String,
    ) -> UserinfoPreparationFuture<'a> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        let error = self.error.clone();
        Box::pin(async move { Err(error) })
    }
    fn userinfo<'a>(
        &'a self,
        _prepared: PreparedUserinfo,
        _facts: UserinfoRequestFacts<'a>,
    ) -> UserinfoFuture<'a> {
        panic!("failed preparation must not continue to binding")
    }
}
struct ForbiddenCertificateExtraction;
impl MtlsThumbprintExtractor for ForbiddenCertificateExtraction {
    fn resolve(&self, _request: &Request) -> Option<String> {
        panic!("failed or absent token must not extract a certificate")
    }
}
fn endpoint(error: UserinfoError) -> UserinfoEndpoint {
    UserinfoEndpoint::new(
        Arc::new(RejectingOperations {
            error,
            prepares: Arc::new(AtomicUsize::new(0)),
        }),
        Arc::new(ForbiddenCertificateExtraction),
    )
}

#[test]
fn missing_and_conflicting_token_transport_keep_exact_bearer_contract() {
    futures_executor::block_on(async {
        let service = endpoint(UserinfoError::InvalidAccessToken);

        let missing = {
            let request = http::Request::builder()
                .uri("/userinfo")
                .body(Bytes::new())
                .unwrap();
            userinfo(&service, &request, request.body()).await
        };
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Bearer error="invalid_token", error_description="Request failed.""#
        );
        assert_eq!(
            missing.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let conflicting = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/userinfo")
                .header(header::AUTHORIZATION, "Bearer header-token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Bytes::from("access_token=body-token"))
                .unwrap();
            userinfo(&service, &request, request.body()).await
        };
        assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            conflicting.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
        );
    });
}

#[test]
fn invalid_token_precedes_malformed_dpop_and_certificate_extraction() {
    futures_executor::block_on(async {
        let prepares = Arc::new(AtomicUsize::new(0));
        let endpoint = UserinfoEndpoint::new(
            Arc::new(RejectingOperations {
                error: UserinfoError::InvalidAccessToken,
                prepares: prepares.clone(),
            }),
            Arc::new(ForbiddenCertificateExtraction),
        );
        let service = endpoint;
        let response = {
            let request = http::Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, "Bearer invalid-token")
                .header("dpop", "first")
                .header("dpop", "second")
                .body(Bytes::new())
                .unwrap();
            userinfo(&service, &request, request.body()).await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(body["error"], "invalid_token");
        assert_eq!(prepares.load(Ordering::SeqCst), 1);
    });
}
