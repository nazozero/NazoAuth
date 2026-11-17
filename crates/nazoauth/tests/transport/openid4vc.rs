use bytes::Bytes;
use http::{StatusCode, header};
use std::sync::{Arc, Mutex};

use crate::openid4vc::{
    CredentialIssuerEndpoint, PresentationEndpoint, create_credential_offer, create_presentation,
    credential, credential_issuer_metadata, deferred_credential, notification,
    presentation_complete, presentation_response,
};
use nazo_openid4vci::application::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CredentialEndpointResponse, CredentialHttpError, CredentialIssuerFuture,
    CredentialIssuerOperations, CredentialRequestBody, CredentialRequestContext,
    CredentialResponseBody, PreAuthorizedTokenRequest, PreAuthorizedTokenResponse,
};
use nazo_openid4vci::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, NotificationRequest,
};
use nazo_openid4vp::PresentationResult;
use nazo_openid4vp::application::{
    CreatePresentationRequest, CreatePresentationResponse, PresentationFuture,
    PresentationHttpError, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn presentation_request_accepts_only_the_generic_trust_policy_fence() {
    futures_executor::block_on(async {
        let request_json = || {
            json!({
                "create_request_jti": Uuid::now_v7().to_string(),
                "wallet_authorization_endpoint": "https://wallet.example/authorize",
                "dcql_query": {"credentials": []},
                "openid4vc_trust_policy_resource_id": "trust:run-1",
                "openid4vc_trust_policy_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            })
        };
        let request: CreatePresentationRequest =
            serde_json::from_value(request_json()).expect("ordinary trust policy request");
        assert_eq!(
            request.openid4vc_trust_policy_resource_id.as_deref(),
            Some("trust:run-1")
        );
        assert_eq!(
            request.openid4vc_trust_policy_digest.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        let mut missing_jti = request_json();
        missing_jti
            .as_object_mut()
            .unwrap()
            .remove("create_request_jti");
        assert!(serde_json::from_value::<CreatePresentationRequest>(missing_jti).is_err());
        let mut malformed_jti = request_json();
        malformed_jti["create_request_jti"] = json!("NOT-A-CANONICAL-UUID");
        let malformed: CreatePresentationRequest = serde_json::from_value(malformed_jti)
            .expect("shape parsing is separate from policy validation");
        assert!(
            nazo_operator_protocol::validate_openid4vp_create_request_jti(
                &malformed.create_request_jti
            )
            .is_err()
        );

        let mut unknown = request_json();
        unknown["unexpected"] = json!({});
        assert!(
            serde_json::from_value::<CreatePresentationRequest>(unknown).is_err(),
            "unknown request members must be rejected"
        );
    });
}

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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        self.credential_contexts.lock().unwrap().push(context);
        Box::pin(async move {
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
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
        request: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>> {
        Box::pin(async move {
            Ok(CreatePresentationResponse {
                idempotency: nazo_operator_protocol::Openid4vpCreateIdempotencyBinding {
                    create_request_jti: request.create_request_jti,
                    create_request_sha256: "a".repeat(64),
                },
                transaction_id: Uuid::now_v7(),
                authorization_url: "https://wallet.example/authorize".to_owned(),
                expires_in: 60,
            })
        })
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
        transaction_id: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>> {
        Box::pin(async move {
            if transaction_id.is_nil() {
                return Err(PresentationHttpError {
                    status: 404,
                    error: "not_found",
                    description: "Presentation transaction was not found.",
                });
            }
            Ok(PresentationResult {
                transaction_id,
                credentials: Vec::new(),
                completed_at: jiff::Timestamp::now(),
            })
        })
    }
}

#[test]
fn presentation_completion_page_reflects_a_verified_transaction() {
    futures_executor::block_on(async {
        let endpoint = PresentationEndpoint::new(Arc::new(Verifier), "secret");
        let app = endpoint;
        let response = {
            let request = http::Request::builder()
                .uri(format!("/openid4vp/complete/{}", Uuid::now_v7()))
                .body(Bytes::new())
                .unwrap();
            presentation_complete(
                &app,
                crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap()).unwrap(),
            )
            .await
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body();
        let body = std::str::from_utf8(&body).expect("completion page is UTF-8");
        assert!(body.contains("data-testid=\"vp-verification-result\""));
        assert!(body.contains("data-status=\"verified\""));
        assert!(body.contains("Presentation verified"));
    });
}

#[test]
fn presentation_completion_page_does_not_claim_an_unknown_transaction_succeeded() {
    futures_executor::block_on(async {
        let endpoint = PresentationEndpoint::new(Arc::new(Verifier), "secret");
        let app = endpoint;
        let response = {
            let request = http::Request::builder()
                .uri(format!("/openid4vp/complete/{}", Uuid::nil()))
                .body(Bytes::new())
                .unwrap();
            presentation_complete(
                &app,
                crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap()).unwrap(),
            )
            .await
        };

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body();
        let body = std::str::from_utf8(&body).expect("error response is UTF-8");
        assert!(!body.contains("data-status=\"verified\""));
    });
}
struct CapturingVerifier {
    responses: Mutex<Vec<PresentationResponseInput>>,
}

impl PresentationOperations for CapturingVerifier {
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
        response: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>> {
        self.responses.lock().unwrap().push(response);
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
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

struct MetadataIssuer;

impl CredentialIssuerOperations for MetadataIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async {
            Ok(CredentialIssuerMetadata {
                credential_issuer: "https://issuer.example".to_owned(),
                authorization_servers: Vec::new(),
                credential_endpoint: "https://issuer.example/credential".to_owned(),
                nonce_endpoint: None,
                deferred_credential_endpoint: None,
                notification_endpoint: None,
                credential_request_encryption: None,
                credential_response_encryption: None,
                batch_credential_issuance: None,
                display: Vec::new(),
                credential_configurations_supported: Default::default(),
                signed_metadata: Some("signed.metadata.jwt".to_owned()),
            })
        })
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
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

struct SuccessfulIssuer {
    response: CredentialResponseBody,
    status: nazo_openid4vci::application::CredentialResponseStatus,
    dpop_nonce: Option<String>,
}

impl SuccessfulIssuer {
    fn response(&self) -> CredentialEndpointResponse<CredentialResponseBody> {
        CredentialEndpointResponse {
            body: self.response.clone(),
            status: self.status,
            dpop_nonce: self.dpop_nonce.clone(),
        }
    }
}

impl CredentialIssuerOperations for SuccessfulIssuer {
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        let response = self.response();
        Box::pin(async move { Ok(response) })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        let response = self.response();
        Box::pin(async move { Ok(response) })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        let dpop_nonce = self.dpop_nonce.clone();
        Box::pin(async move {
            Ok(CredentialEndpointResponse {
                body: (),
                status: nazo_openid4vci::application::CredentialResponseStatus::Issued,
                dpop_nonce,
            })
        })
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

fn immediate_response() -> CredentialResponseBody {
    CredentialResponseBody::Json(
        serde_json::to_vec(&CredentialResponse {
            credentials: Some(Vec::new()),
            transaction_id: None,
            notification_id: None,
            interval: None,
        })
        .unwrap()
        .into(),
    )
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
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        self.notifications.lock().unwrap().push(request);
        Box::pin(async {
            Ok(CredentialEndpointResponse {
                body: (),
                status: nazo_openid4vci::application::CredentialResponseStatus::Issued,
                dpop_nonce: None,
            })
        })
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

#[test]
fn metadata_endpoint_returns_signed_jwt_when_requested() {
    futures_executor::block_on(async {
        let endpoint =
            CredentialIssuerEndpoint::new(Arc::new(MetadataIssuer), b"management-token".to_vec());
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .uri("/metadata")
                .header("accept", "application/jwt")
                .body(Bytes::new())
                .unwrap();
            credential_issuer_metadata(&app, &request).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/jwt"
        );
        let body = response.into_body();
        assert_eq!(body, "signed.metadata.jwt");
    });
}

#[test]
fn management_endpoints_fail_closed_without_exact_bearer_token() {
    futures_executor::block_on(async {
        let issuer = CredentialIssuerEndpoint::new(
            Arc::new(Issuer::default()),
            b"management-token".to_vec(),
        );
        let verifier = PresentationEndpoint::new(Arc::new(Verifier), b"management-token".to_vec());
        let app = (issuer, verifier);

        for (path, body) in [
            (
                "/offers",
                serde_json::json!({"subject_id":Uuid::now_v7(),"credential_configuration_ids":["pid"],"grant_types":["authorization_code"]}),
            ),
            (
                "/presentations",
                serde_json::json!({"create_request_jti":Uuid::now_v7(),"wallet_authorization_endpoint":"https://wallet.example/authorize","dcql_query":{"credentials":[]}}),
            ),
        ] {
            let response = {
                let request = http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Bytes::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap();
                if path == "/offers" {
                    create_credential_offer(
                        &app.0,
                        &request,
                        crate::http::parse_json(&request).unwrap(),
                    )
                    .await
                } else {
                    create_presentation(
                        &app.1,
                        &request,
                        crate::http::parse_json(&request).unwrap(),
                    )
                    .await
                }
            };
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
            assert_eq!(
                response.headers().get("www-authenticate").unwrap(),
                "Bearer"
            );
        }
    });
}

#[test]
fn presentation_create_echoes_the_typed_idempotency_binding() {
    futures_executor::block_on(async {
        let endpoint = PresentationEndpoint::new(Arc::new(Verifier), b"management-token".to_vec());
        let app = endpoint;
        let create_request_jti = Uuid::now_v7().to_string();
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/presentations")
                .header("authorization", "Bearer management-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "create_request_jti": create_request_jti,
                        "wallet_authorization_endpoint": "https://wallet.example/authorize",
                        "dcql_query": {"credentials": []}
                    }))
                    .unwrap(),
                ))
                .unwrap();
            create_presentation(&app, &request, crate::http::parse_json(&request).unwrap()).await
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(body["create_request_jti"], create_request_jti);
        assert_eq!(body["create_request_sha256"], "a".repeat(64));
    });
}

#[test]
fn presentation_management_requires_nonempty_exact_bearer_token() {
    futures_executor::block_on(async {
        let cases = [
            (Vec::<u8>::new(), Some("Bearer "), StatusCode::UNAUTHORIZED),
            (
                b"management-token".to_vec(),
                Some("Bearer "),
                StatusCode::UNAUTHORIZED,
            ),
            (
                b"management-token".to_vec(),
                Some("Bearer  management-token"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                b"management-token".to_vec(),
                Some(" Bearer management-token"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                b"management-token".to_vec(),
                Some("Bearer management-token "),
                StatusCode::UNAUTHORIZED,
            ),
            (
                b"management-token".to_vec(),
                Some("Basic management-token"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                b"management-token".to_vec(),
                Some("bearer management-token"),
                StatusCode::OK,
            ),
            (b"management-token".to_vec(), None, StatusCode::UNAUTHORIZED),
            (
                b"management-token".to_vec(),
                Some("Bearer management-token"),
                StatusCode::OK,
            ),
        ];

        for (configured_token, authorization, expected_status) in cases {
            let endpoint = PresentationEndpoint::new(Arc::new(Verifier), configured_token);
            let app = endpoint;

            let request = http::Request::builder()
                .method("POST")
                .uri("/presentations")
                .header(header::CONTENT_TYPE, "application/json");
            let request = if let Some(authorization) = authorization {
                request.header("authorization", authorization)
            } else {
                request
            };
            let response = {
                let request = request.body(Bytes::from(serde_json::to_vec(&json!({"create_request_jti": Uuid::now_v7(), "wallet_authorization_endpoint": "https://wallet.example/authorize", "dcql_query": {"credentials": []}})).unwrap())).unwrap();
                create_presentation(&app, &request, crate::http::parse_json(&request).unwrap())
                    .await
            };

            assert_eq!(response.status(), expected_status);
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        }
    });
}

#[test]
fn credential_endpoint_preserves_dpop_nonce_challenge_error() {
    futures_executor::block_on(async {
        let endpoint =
            CredentialIssuerEndpoint::new(Arc::new(DpopNonceIssuer), b"management-token".to_vec());
        let app = endpoint;

        let response = {
            let request = http::Request::builder().method("POST").uri("/credential").header("authorization", "DPoP access-token").header("DPoP", "proof.jwt").header(header::CONTENT_TYPE, "application/json").body(Bytes::from(serde_json::to_vec(&json!({"credential_configuration_id":"pid","proof":{"proof_type":"jwt","jwt":"proof"}})).unwrap())).unwrap();
            credential(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            r#"DPoP error="use_dpop_nonce""#
        );
        assert_eq!(
            response.headers().get("dpop-nonce").unwrap(),
            "resource-nonce"
        );
    });
}

#[test]
fn credential_success_returns_next_dpop_nonce_for_json_and_jwt_responses() {
    futures_executor::block_on(async {
        use nazo_openid4vci::application::CredentialResponseStatus::{Deferred, Issued};
        for (response_body, content_type, status) in [
            (immediate_response(), "application/json", Issued),
            (
                CredentialResponseBody::Jwt("encrypted.credential.response".into()),
                "application/jwt",
                Issued,
            ),
            (
                CredentialResponseBody::Json(
                    serde_json::to_vec(&nazo_openid4vci::CredentialResponse {
                        credentials: None,
                        transaction_id: Some("pending".to_owned()),
                        notification_id: None,
                        interval: Some(5),
                    })
                    .unwrap()
                    .into(),
                ),
                "application/json",
                Deferred,
            ),
            (
                CredentialResponseBody::Jwt("opaque.encrypted.deferred.response".into()),
                "application/jwt",
                Deferred,
            ),
        ] {
            let endpoint = CredentialIssuerEndpoint::new(
                Arc::new(SuccessfulIssuer {
                    response: response_body,
                    status,
                    dpop_nonce: Some("next-resource-nonce".to_owned()),
                }),
                b"management-token".to_vec(),
            );
            let app = endpoint;

            let response = {
                let request = http::Request::builder()
                    .method("POST")
                    .uri("/credential")
                    .header("authorization", "DPoP access-token")
                    .header("dpop", "proof.jwt")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Bytes::from(
                        serde_json::to_vec(&json!({"credential_configuration_id":"pid"})).unwrap(),
                    ))
                    .unwrap();
                credential(&app, &request, request.body()).await
            };

            assert_eq!(response.status().as_u16(), status.http_status());
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                content_type
            );
            assert_eq!(
                response.headers().get("dpop-nonce").unwrap(),
                "next-resource-nonce"
            );
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        }
    });
}

#[test]
fn deferred_and_notification_success_return_next_dpop_nonce() {
    futures_executor::block_on(async {
        let endpoint = CredentialIssuerEndpoint::new(
            Arc::new(SuccessfulIssuer {
                response: immediate_response(),
                status: nazo_openid4vci::application::CredentialResponseStatus::Issued,
                dpop_nonce: Some("next-resource-nonce".to_owned()),
            }),
            b"management-token".to_vec(),
        );
        let app = endpoint;

        let deferred = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/deferred")
                .header("authorization", "DPoP access-token")
                .header("dpop", "proof.jwt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({"transaction_id":"transaction-1"})).unwrap(),
                ))
                .unwrap();
            deferred_credential(&app, &request, request.body()).await
        };
        assert_eq!(deferred.status(), StatusCode::OK);
        assert_eq!(
            deferred.headers().get("dpop-nonce").unwrap(),
            "next-resource-nonce"
        );

        let notification_response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/notification")
                .header("authorization", "DPoP access-token")
                .header("dpop", "proof.jwt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "notification_id":"notification-1",
                        "event":"credential_accepted"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            notification(&app, &request, crate::http::parse_json(&request).unwrap()).await
        };
        assert_eq!(notification_response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            notification_response.headers().get("dpop-nonce").unwrap(),
            "next-resource-nonce"
        );
        assert_eq!(
            notification_response
                .headers()
                .get("cache-control")
                .unwrap(),
            "no-store"
        );
    });
}

#[test]
fn bearer_success_does_not_emit_a_dpop_nonce() {
    futures_executor::block_on(async {
        let endpoint = CredentialIssuerEndpoint::new(
            Arc::new(SuccessfulIssuer {
                response: immediate_response(),
                status: nazo_openid4vci::application::CredentialResponseStatus::Issued,
                dpop_nonce: None,
            }),
            b"management-token".to_vec(),
        );
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential")
                .header("authorization", "Bearer access-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({"credential_configuration_id":"pid"})).unwrap(),
                ))
                .unwrap();
            credential(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("dpop-nonce").is_none());
    });
}

#[test]
fn notification_endpoint_accepts_extension_members_without_relaxing_authentication() {
    futures_executor::block_on(async {
        let issuer = Arc::new(NotificationIssuer::default());
        let endpoint = CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec());
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/notification")
                .header("authorization", "DPoP access-token")
                .header("dpop", "proof.jwt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "notification_id": "notification-1",
                        "event": "credential_accepted",
                        "unknown_extension": "ignored"
                    }))
                    .unwrap(),
                ))
                .unwrap();
            notification(&app, &request, crate::http::parse_json(&request).unwrap()).await
        };

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let notifications = issuer.notifications.lock().unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].notification_id, "notification-1");
    });
}

#[test]
fn credential_endpoint_authenticates_only_headers_and_rejects_unsupported_bodies() {
    futures_executor::block_on(async {
        let issuer = Arc::new(Issuer::default());
        let endpoint = CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec());
        let app = endpoint;

        let query_token = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential?access_token=leak")
                .header("content-type", "application/json")
                .body(Bytes::from("{}"))
                .unwrap();
            credential(&app, &request, request.body()).await
        };
        assert_eq!(query_token.status(), StatusCode::UNAUTHORIZED);

        assert!(issuer.credential_contexts.lock().unwrap().is_empty());
        let header_token = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential?access_token=ignored")
                .header("authorization", "Bearer header-token")
                .header("content-type", "application/json")
                .body(Bytes::from("{}"))
                .unwrap();
            credential(&app, &request, request.body()).await
        };
        assert_eq!(header_token.status(), StatusCode::CONFLICT);
        assert_eq!(
            issuer.credential_contexts.lock().unwrap()[0].bearer_token,
            "header-token"
        );

        let unsupported = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential")
                .header("authorization", "Bearer token")
                .header("content-type", "text/plain")
                .body(Bytes::from("{}"))
                .unwrap();
            credential(&app, &request, request.body()).await
        };
        assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    });
}

#[test]
fn credential_endpoint_rejects_multiple_dpop_proof_headers() {
    futures_executor::block_on(async {
        let issuer = Arc::new(Issuer::default());
        let endpoint = CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec());
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential")
                .header("authorization", "DPoP access-token")
                .header("dpop", "proof-one.jwt")
                .header("dpop", "proof-two.jwt")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "credential_configuration_id": "pid",
                        "proofs": {"jwt": ["proof.jwt"]}
                    }))
                    .unwrap(),
                ))
                .unwrap();
            credential(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let contexts = issuer.credential_contexts.lock().unwrap();
        assert!(
            contexts.is_empty(),
            "duplicate DPoP proofs must be rejected before credential issuance"
        );
    });
}

#[test]
fn credential_endpoint_preserves_dpop_authorization_scheme_and_proof() {
    futures_executor::block_on(async {
        let issuer = Arc::new(Issuer::default());
        let endpoint = CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec());
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential")
                .header("authorization", "DPoP access-token")
                .header("dpop", "proof.jwt")
                .header("x-forwarded-tls-client-cert-sha256", "attacker-header")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "credential_configuration_id": "pid",
                        "proofs": {"jwt": ["proof.jwt"]}
                    }))
                    .unwrap(),
                ))
                .unwrap();
            credential(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let contexts = issuer.credential_contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].bearer_token, "access-token");
        assert_eq!(contexts[0].access_token_scheme, AccessTokenScheme::Dpop);
        assert_eq!(contexts[0].dpop_proof.as_deref(), Some("proof.jwt"));
        assert_eq!(contexts[0].mtls_x5t_s256, None);
    });
}

#[test]
fn credential_endpoint_passes_injected_verified_certificate_thumbprint() {
    futures_executor::block_on(async {
        let issuer = Arc::new(Issuer::default());
        let endpoint = CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec())
            .with_client_certificate_extractor(|_| Some("verified-thumbprint".to_owned()));
        let app = endpoint;

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/credential")
                .header("authorization", "Bearer access-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "credential_configuration_id": "pid",
                        "proofs": {"jwt": ["proof.jwt"]}
                    }))
                    .unwrap(),
                ))
                .unwrap();
            credential(&app, &request, request.body()).await
        };

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let contexts = issuer.credential_contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(
            contexts[0].mtls_x5t_s256.as_deref(),
            Some("verified-thumbprint")
        );
    });
}

#[test]
fn direct_post_rejects_duplicate_and_mixed_response_parameters() {
    futures_executor::block_on(async {
        let endpoint = PresentationEndpoint::new(Arc::new(Verifier), b"management-token".to_vec());
        let id = Uuid::now_v7();
        let app = endpoint;

        for body in ["state=one&state=two", "response=jwt&state=unexpected"] {
            let response = {
                let request = http::Request::builder()
                    .method("POST")
                    .uri(format!("/response/{id}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Bytes::from(body))
                    .unwrap();
                presentation_response(
                    &app,
                    crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap())
                        .unwrap(),
                    &request,
                    request.body(),
                )
                .await
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        }
    });
}

#[test]
fn direct_post_preserves_json_vp_token_and_jwt_response_shapes() {
    futures_executor::block_on(async {
        let verifier = Arc::new(CapturingVerifier {
            responses: Mutex::new(Vec::new()),
        });
        let endpoint = PresentationEndpoint::new(verifier.clone(), b"management-token".to_vec());
        let id = Uuid::now_v7();
        let app = endpoint;

        let response = {
            let request = http::Request::builder().method("POST").uri(format!("/response/{id}")).header("content-type", "application/x-www-form-urlencoded").body(Bytes::from("vp_token=%7B%22credential%22%3A%5B%22encoded%22%5D%7D&state=state&future=one&future=two")).unwrap();
            presentation_response(
                &app,
                crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap()).unwrap(),
                &request,
                request.body(),
            )
            .await
        };
        assert_eq!(response.status(), StatusCode::OK);

        for payload in [
            "vp_token=not-json&state=state",
            "vp_token=%7Bbroken&state=state",
        ] {
            let response = {
                let request = http::Request::builder()
                    .method("POST")
                    .uri(format!("/response/{id}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Bytes::from(payload))
                    .unwrap();
                presentation_response(
                    &app,
                    crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap())
                        .unwrap(),
                    &request,
                    request.body(),
                )
                .await
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                verifier.responses.lock().unwrap().len(),
                1,
                "malformed JSON must not reach transaction or trust-policy lookup"
            );
        }

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri(format!("/response/{id}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Bytes::from("response=signed.jwt"))
                .unwrap();
            presentation_response(
                &app,
                crate::http::parse_path(request.uri().path().rsplit("/").next().unwrap()).unwrap(),
                &request,
                request.body(),
            )
            .await
        };
        assert_eq!(response.status(), StatusCode::OK);

        let responses = verifier.responses.lock().unwrap();
        assert!(matches!(
            &responses[0],
            PresentationResponseInput::DirectPost(response)
                if response.vp_token == Some(json!({"credential": ["encoded"]}))
                    && response.state.as_deref() == Some("state")
        ));
        assert_eq!(
            responses[1],
            PresentationResponseInput::DirectPostJwt("signed.jwt".to_owned())
        );
    });
}
