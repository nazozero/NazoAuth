use super::fixtures::*;
use super::*;
use actix_web::{FromRequest, http::StatusCode};
use futures_util::{
    future::{Ready, ready},
    task::noop_waker_ref,
};
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

#[actix_web::test]
async fn actix_request_authorizer_includes_query_token_transport_in_validation() {
    let fixture = fixture();
    let token = bearer(&token(&fixture, json!({}), None));
    let request = actix_web::test::TestRequest::get()
        .uri("/orders?access_token=query-token")
        .insert_header((actix_web::http::header::AUTHORIZATION, token))
        .to_http_request();

    let error = authorize_actix_request(&fixture.verifier, &request).unwrap_err();

    assert!(matches!(error, ResourceServerRequestError::InvalidRequest));
}

#[actix_web::test]
async fn actix_extractor_maps_authorization_failure_to_bearer_response() {
    let fixture = fixture();
    let request = actix_web::test::TestRequest::get()
        .uri("/orders")
        .app_data(actix_web::web::Data::new(fixture.verifier))
        .to_http_request();
    let mut payload = actix_web::dev::Payload::None;

    let error = ActixVerifiedAccessToken::from_request(&request, &mut payload)
        .await
        .unwrap_err();
    let response = error.as_response_error().error_response();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .unwrap(),
        r#"Bearer error="invalid_token", error_description="Missing bearer access token.""#
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
fn tower_layer_poll_ready_propagates_inner_service_errors() {
    #[derive(Clone)]
    struct NotReadyService;

    impl Service<http::Request<()>> for NotReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err("not ready"))
        }

        fn call(&mut self, _request: http::Request<()>) -> Self::Future {
            ready(Ok(()))
        }
    }

    let fixture = fixture();
    let mut service = TowerResourceServerLayer::new(fixture.verifier).layer(NotReadyService);
    let mut cx = Context::from_waker(noop_waker_ref());

    let Poll::Ready(Err(error)) = service.poll_ready(&mut cx) else {
        panic!("inner readiness failure should be returned immediately");
    };

    assert!(matches!(
        error,
        TowerResourceServerError::Inner("not ready")
    ));
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

#[actix_web::test]
async fn actix_extractor_fails_closed_when_verifier_is_not_configured() {
    let request = actix_web::test::TestRequest::get()
        .uri("/orders")
        .to_http_request();
    let mut payload = actix_web::dev::Payload::None;

    let error = ActixVerifiedAccessToken::from_request(&request, &mut payload)
        .await
        .unwrap_err();
    let response = error.as_response_error().error_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .unwrap(),
        r#"Bearer error="invalid_request", error_description="The request used an invalid access token transport.""#
    );
}

#[test]
fn bearer_error_mappers_hide_internal_reasons_but_preserve_protocol_category() {
    let invalid_request = http_bearer_error_response(&ResourceServerRequestError::InvalidRequest);
    assert_eq!(invalid_request.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_request
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap(),
        r#"Bearer error="invalid_request", error_description="The request used an invalid access token transport.""#
    );

    let dpop_mismatch =
        http_bearer_error_response(&ResourceServerRequestError::DpopBindingMismatch);
    assert_eq!(dpop_mismatch.status(), http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        dpop_mismatch.body(),
        r#"{"error":"invalid_token","error_description":"DPoP proof does not match access token."}"#
    );

    let missing_token = http_bearer_error_response(&ResourceServerRequestError::MissingToken);
    assert_eq!(
        missing_token.body(),
        r#"{"error":"invalid_token","error_description":"Missing bearer access token."}"#
    );

    let missing_sender_constraint =
        http_bearer_error_response(&ResourceServerRequestError::MissingSenderConstraint);
    assert_eq!(
        missing_sender_constraint.body(),
        r#"{"error":"invalid_token","error_description":"Sender-constrained access token requires verified proof."}"#
    );

    let mtls_mismatch =
        http_bearer_error_response(&ResourceServerRequestError::MtlsBindingMismatch);
    assert_eq!(
        mtls_mismatch.body(),
        r#"{"error":"invalid_token","error_description":"Client certificate does not match access token."}"#
    );

    let invalid_token = http_bearer_error_response(&ResourceServerRequestError::InvalidToken(
        ResourceServerVerifierError::InvalidToken,
    ));
    assert_eq!(
        invalid_token.body(),
        r#"{"error":"invalid_token","error_description":"Access token is invalid."}"#
    );
    assert!(!invalid_token.body().contains("signature details"));

    let invalid_dpop = http_bearer_error_response(&ResourceServerRequestError::InvalidDpopProof(
        DpopProofVerifierError::InvalidSignature,
    ));
    assert_eq!(invalid_dpop.status(), http::StatusCode::UNAUTHORIZED);
    assert!(!invalid_dpop.body().contains("InvalidSignature"));
    assert_eq!(
        invalid_dpop.body(),
        r#"{"error":"invalid_token","error_description":"DPoP proof is invalid."}"#
    );
}

#[test]
fn tonic_authorizer_maps_invalid_request_to_argument_and_auth_failures_to_unauthenticated() {
    let fixture = fixture();
    let mut invalid_request = tonic::Request::new(());
    invalid_request
        .metadata_mut()
        .insert("authorization", "Bearer token extra".parse().unwrap());

    let invalid_request_status =
        authorize_tonic_request(&fixture.verifier, &mut invalid_request).unwrap_err();
    assert_eq!(invalid_request_status.code(), tonic::Code::InvalidArgument);
    assert_eq!(invalid_request_status.message(), "invalid_request");

    let mut missing_token = tonic::Request::new(());
    let missing_token_status =
        authorize_tonic_request(&fixture.verifier, &mut missing_token).unwrap_err();
    assert_eq!(missing_token_status.code(), tonic::Code::Unauthenticated);
    assert_eq!(missing_token_status.message(), "invalid_token");
}

#[tokio::test]
async fn tower_layer_returns_unauthorized_without_calling_inner_service() {
    #[derive(Clone)]
    struct PanicIfCalled;

    impl Service<http::Request<()>> for PanicIfCalled {
        type Response = ();
        type Error = ();
        type Future = Ready<Result<(), ()>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: http::Request<()>) -> Self::Future {
            panic!("inner service must not be called after failed authorization")
        }
    }

    let fixture = fixture();
    let request = http::Request::builder()
        .uri("https://api.example/orders")
        .body(())
        .unwrap();
    let mut service = TowerResourceServerLayer::new(fixture.verifier).layer(PanicIfCalled);

    let error = service.call(request).await.unwrap_err();

    assert!(matches!(
        error,
        TowerResourceServerError::Unauthorized(ResourceServerRequestError::MissingToken)
    ));
}
