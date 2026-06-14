use super::fixtures::*;
use super::*;
use futures_util::future::{Ready, ready};
use serde_json::json;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[test]
fn http_request_authorizer_inserts_verified_claims_for_tower_and_axum() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let mut request = http::Request::builder()
        .uri("https://api.example/orders")
        .header(http::header::AUTHORIZATION, token)
        .body(())
        .unwrap();

    let verified = authorize_http_request(&fixture.verifier, &mut request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}

#[actix_web::test]
async fn actix_request_authorizer_inserts_verified_claims() {
    use actix_web::HttpMessage;

    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let request = actix_web::test::TestRequest::get()
        .uri("/orders")
        .insert_header((actix_web::http::header::AUTHORIZATION, token))
        .to_http_request();

    let verified = authorize_actix_request(&fixture.verifier, &request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}

#[tokio::test]
async fn tower_layer_inserts_verified_claims_before_inner_service() {
    #[derive(Clone)]
    struct ExtensionCheckService;

    impl Service<http::Request<()>> for ExtensionCheckService {
        type Response = bool;
        type Error = ();
        type Future = Ready<Result<bool, ()>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<()>) -> Self::Future {
            ready(Ok(request
                .extensions()
                .get::<VerifiedAccessToken>()
                .is_some()))
        }
    }

    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let request = http::Request::builder()
        .uri("https://api.example/orders")
        .header(http::header::AUTHORIZATION, token)
        .body(())
        .unwrap();
    let mut service = TowerResourceServerLayer::new(fixture.verifier).layer(ExtensionCheckService);

    let saw_claims = service.call(request).await.unwrap();

    assert!(saw_claims);
}

#[test]
fn tonic_request_authorizer_inserts_verified_claims() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", token.parse().unwrap());

    let verified = authorize_tonic_request(&fixture.verifier, &mut request).unwrap();

    assert_eq!(verified.subject, "subject-1");
    assert_eq!(
        request
            .extensions()
            .get::<VerifiedAccessToken>()
            .unwrap()
            .client_id,
        "client-1"
    );
}
