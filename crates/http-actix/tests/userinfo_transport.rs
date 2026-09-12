use actix_web::{
    App, HttpRequest,
    http::{StatusCode, header},
    test,
    web::{self, Data},
};
use nazo_http_actix::mtls::MtlsThumbprintExtractor;
use nazo_http_actix::{UserinfoEndpoint, userinfo};
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
    fn resolve(&self, _request: &HttpRequest) -> Option<String> {
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

#[actix_web::test]
async fn missing_and_conflicting_token_transport_keep_exact_bearer_contract() {
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint(UserinfoError::InvalidAccessToken)))
            .route("/userinfo", web::get().to(userinfo))
            .route("/userinfo", web::post().to(userinfo)),
    )
    .await;

    let missing = test::call_service(
        &service,
        test::TestRequest::get().uri("/userinfo").to_request(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_token", error_description="Request failed.""#
    );
    assert_eq!(
        missing.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let conflicting = test::call_service(
        &service,
        test::TestRequest::post()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("access_token=body-token")
            .to_request(),
    )
    .await;
    assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        conflicting.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
    );
}

#[actix_web::test]
async fn invalid_token_precedes_malformed_dpop_and_certificate_extraction() {
    let prepares = Arc::new(AtomicUsize::new(0));
    let endpoint = UserinfoEndpoint::new(
        Arc::new(RejectingOperations {
            error: UserinfoError::InvalidAccessToken,
            prepares: prepares.clone(),
        }),
        Arc::new(ForbiddenCertificateExtraction),
    );
    let service = test::init_service(
        App::new()
            .app_data(Data::new(endpoint))
            .route("/userinfo", web::get().to(userinfo)),
    )
    .await;
    let response = test::call_service(
        &service,
        test::TestRequest::get()
            .uri("/userinfo")
            .insert_header((header::AUTHORIZATION, "Bearer invalid-token"))
            .append_header(("dpop", "first"))
            .append_header(("dpop", "second"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(prepares.load(Ordering::SeqCst), 1);
}
