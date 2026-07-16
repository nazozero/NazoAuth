use std::sync::{Arc, Mutex};

use actix_web::{App, http::StatusCode, test, web};
use nazo_openid4vc_http_actix::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CreatePresentationRequest, CreatePresentationResponse, CredentialHttpError,
    CredentialIssuerEndpoint, CredentialIssuerFuture, CredentialIssuerOperations,
    CredentialRequestBody, CredentialRequestContext, CredentialResponseBody,
    PreAuthorizedTokenRequest, PreAuthorizedTokenResponse, PresentationEndpoint,
    PresentationFuture, PresentationHttpError, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput, create_credential_offer, create_presentation, credential,
    notification, presentation_response,
};
use nazo_openid4vci::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, DeferredCredentialRequest,
    NotificationRequest,
};
use nazo_openid4vp::{PresentationResult, PresentationTransaction};
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
struct Issuer {
    credential_contexts: Mutex<Vec<CredentialRequestContext>>,
}

impl CredentialIssuerOperations for Issuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        context: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        self.credential_contexts.lock().unwrap().push(context);
        Box::pin(async {
            Err(CredentialHttpError {
                status: 409,
                error: "captured",
                description: "captured",
                dpop_nonce: None,
            })
        })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<(), CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

struct Verifier;

impl PresentationOperations for Verifier {
    fn create<'a>(
        &'a self,
        _: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn request<'a>(
        &'a self,
        _: Uuid,
        _: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn respond<'a>(
        &'a self,
        _: Uuid,
        _: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>> {
        Box::pin(async { Ok(None) })
    }
    fn result<'a>(
        &'a self,
        _: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
}

struct DpopNonceIssuer;

impl CredentialIssuerOperations for DpopNonceIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        Box::pin(async {
            Err(CredentialHttpError {
                status: 401,
                error: "use_dpop_nonce",
                description: "Credential issuer requires nonce in DPoP proof.",
                dpop_nonce: Some("resource-nonce".to_owned()),
            })
        })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<(), CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

#[derive(Default)]
struct NotificationIssuer {
    notifications: Mutex<Vec<NotificationRequest>>,
}

impl CredentialIssuerOperations for NotificationIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<'a, Result<CredentialResponseBody, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<(), CredentialHttpError>> {
        self.notifications.lock().unwrap().push(request);
        Box::pin(async { Ok(()) })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

#[actix_web::test]
async fn management_endpoints_fail_closed_without_exact_bearer_token() {
    let issuer = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(Issuer::default()),
        b"management-token".to_vec(),
    ));
    let verifier = web::Data::new(PresentationEndpoint::new(
        Arc::new(Verifier),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(issuer)
            .app_data(verifier)
            .route("/offers", web::post().to(create_credential_offer))
            .route("/presentations", web::post().to(create_presentation)),
    )
    .await;

    for (path, body) in [
        (
            "/offers",
            serde_json::json!({"subject_id":Uuid::now_v7(),"credential_configuration_ids":["pid"],"grant_types":["authorization_code"]}),
        ),
        (
            "/presentations",
            serde_json::json!({"wallet_authorization_endpoint":"https://wallet.example/authorize","dcql_query":{"credentials":[]}}),
        ),
    ] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(path)
                .set_json(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            "Bearer"
        );
    }
}

#[actix_web::test]
async fn credential_endpoint_preserves_dpop_nonce_challenge_error() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(DpopNonceIssuer),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("DPoP", "proof.jwt"))
            .set_json(json!({"credential_configuration_id":"pid","proof":{"proof_type":"jwt","jwt":"proof"}}))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        "resource-nonce"
    );
}

#[actix_web::test]
async fn notification_endpoint_accepts_extension_members_without_relaxing_authentication() {
    let issuer = Arc::new(NotificationIssuer::default());
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        issuer.clone(),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/notification", web::post().to(notification)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/notification")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .set_json(json!({
                "notification_id": "notification-1",
                "event": "credential_accepted",
                "suite_extension": "ignored"
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let notifications = issuer.notifications.lock().unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].notification_id, "notification-1");
}

#[actix_web::test]
async fn credential_endpoint_rejects_query_tokens_and_non_json_or_jwt_bodies() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(Issuer::default()),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let query_token = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential?access_token=leak")
            .insert_header(("content-type", "application/json"))
            .set_payload("{}")
            .to_request(),
    )
    .await;
    assert_eq!(query_token.status(), StatusCode::UNAUTHORIZED);

    let unsupported = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer token"))
            .insert_header(("content-type", "text/plain"))
            .set_payload("{}")
            .to_request(),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[actix_web::test]
async fn credential_endpoint_preserves_dpop_authorization_scheme_and_proof() {
    let issuer = Arc::new(Issuer::default());
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        issuer.clone(),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .set_json(json!({
                "credential_configuration_id": "pid",
                "proofs": {"jwt": ["proof.jwt"]}
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let contexts = issuer.credential_contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].bearer_token, "access-token");
    assert_eq!(contexts[0].access_token_scheme, AccessTokenScheme::Dpop);
    assert_eq!(contexts[0].dpop_proof.as_deref(), Some("proof.jwt"));
}

#[actix_web::test]
async fn direct_post_rejects_duplicate_and_mixed_response_parameters() {
    let endpoint = web::Data::new(PresentationEndpoint::new(
        Arc::new(Verifier),
        b"management-token".to_vec(),
    ));
    let id = Uuid::now_v7();
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/response/{id}", web::post().to(presentation_response)),
    )
    .await;

    for body in ["state=one&state=two", "response=jwt&state=unexpected"] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/response/{id}"))
                .insert_header(("content-type", "application/x-www-form-urlencoded"))
                .set_payload(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}

fn _assert_transaction_type(_: &PresentationTransaction) {}
