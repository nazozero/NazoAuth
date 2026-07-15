use std::{collections::BTreeMap, sync::Arc};

use actix_web::{
    App, HttpRequest,
    http::{StatusCode, header},
    test as actix_test, web,
};
use nazo_http_actix::{
    ScimAuthorizationError, ScimAuthorizedRequest, ScimBootstrapPasswordProvider,
    ScimCursorProtector, ScimDependencyError, ScimEndpoint, ScimFuture, ScimRequestAuthorizer,
    scim_poll_security_events, scim_service_provider_config,
};
use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{
        NewScimUser, PasswordHashInput, RepositoryError, RepositoryFuture, ScimCredentialAuditPort,
        ScimCredentialUse, ScimListQuery, ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimCursorSubject, ScimPatch, ScimRequiredScope, ScimService},
};
use nazo_scim_events::{EventPollerPort, EventReceiver, MutationContext, ValidatedPollRequest};
use serde_json::{Value, json};

struct UnusedRepository;

impl ScimRepositoryPort for UnusedRepository {
    fn list<'a>(&'a self, _query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn get<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn create<'a>(&'a self, _user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn replace<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _replacement: NormalizedScimUser,
        _mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn patch<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _patch: ScimPatch,
        _mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn deactivate<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _mutation: MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

struct UnusedAudit;

impl ScimCredentialAuditPort for UnusedAudit {
    fn active_credential<'a>(
        &'a self,
        _token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::scim::ScimTokenCredential>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn record_use<'a>(&'a self, _usage: ScimCredentialUse) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

struct AllowRequests;

impl ScimRequestAuthorizer for AllowRequests {
    fn authorize<'a>(
        &'a self,
        _request: &'a HttpRequest,
        _required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        Box::pin(async {
            let tenant = TenantContext::default_system();
            Ok(ScimAuthorizedRequest {
                tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: tenant.tenant_id.as_uuid(),
                    actor: "test".to_owned(),
                },
                event_receiver: None,
            })
        })
    }
}

struct DenyRequests(ScimAuthorizationError);

impl ScimRequestAuthorizer for DenyRequests {
    fn authorize<'a>(
        &'a self,
        _request: &'a HttpRequest,
        _required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

struct EventRequests {
    receiver: EventReceiver,
}

impl ScimRequestAuthorizer for EventRequests {
    fn authorize<'a>(
        &'a self,
        _request: &'a HttpRequest,
        _required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        let receiver = self.receiver.clone();
        Box::pin(async move {
            let tenant = TenantContext::default_system();
            Ok(ScimAuthorizedRequest {
                tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: tenant.tenant_id.as_uuid(),
                    actor: "event-test".to_owned(),
                },
                event_receiver: Some(receiver),
            })
        })
    }

    fn security_events_enabled(&self) -> bool {
        true
    }
}

struct FixedPoller;

impl EventPollerPort for FixedPoller {
    fn poll<'a>(
        &'a self,
        _receiver: &'a EventReceiver,
        _request: &'a ValidatedPollRequest,
    ) -> nazo_scim_events::EventFuture<
        'a,
        Result<nazo_scim_events::PollResponse, nazo_scim_events::PollError>,
    > {
        Box::pin(async {
            Ok(nazo_scim_events::PollResponse {
                sets: BTreeMap::from([("event-id".to_owned(), "signed-set".to_owned())]),
                more_available: false,
            })
        })
    }
}

struct UnusedCursor;

impl ScimCursorProtector for UnusedCursor {
    fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
        Err(ScimDependencyError::Unavailable)
    }

    fn unprotect(&self, _protected: &[u8]) -> Result<Vec<u8>, ScimDependencyError> {
        Err(ScimDependencyError::Unavailable)
    }
}

struct UnusedPassword;

impl ScimBootstrapPasswordProvider for UnusedPassword {
    fn password_hash(&self) -> ScimFuture<'_, Result<PasswordHashInput, ScimDependencyError>> {
        Box::pin(async { Err(ScimDependencyError::Unavailable) })
    }
}

fn endpoint(authorizer: Arc<dyn ScimRequestAuthorizer>) -> web::Data<ScimEndpoint> {
    web::Data::new(ScimEndpoint::new(
        ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedAudit)),
        authorizer,
        Arc::new(UnusedCursor),
        Arc::new(UnusedPassword),
    ))
}

fn event_endpoint() -> web::Data<ScimEndpoint> {
    let tenant = TenantContext::default_system();
    web::Data::new(
        ScimEndpoint::new(
            ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedAudit)),
            Arc::new(EventRequests {
                receiver: EventReceiver {
                    token_id: uuid::Uuid::now_v7(),
                    tenant_id: tenant.tenant_id.as_uuid(),
                    audience: "https://receiver.example/events".to_owned(),
                },
            }),
            Arc::new(UnusedCursor),
            Arc::new(UnusedPassword),
        )
        .with_security_events(Arc::new(FixedPoller)),
    )
}

#[actix_web::test]
async fn authorization_errors_preserve_scim_documents_and_bearer_challenge() {
    let app = actix_test::init_service(
        App::new()
            .app_data(endpoint(Arc::new(DenyRequests(
                ScimAuthorizationError::MissingBearer,
            ))))
            .route(
                "/scim/v2/ServiceProviderConfig",
                web::get().to(scim_service_provider_config),
            ),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/scim/v2/ServiceProviderConfig")
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let document = actix_test::read_body_json::<Value, _>(response).await;
    assert_eq!(document["status"], "401");
}

#[actix_web::test]
async fn provider_config_handler_preserves_http_contract() {
    let app = actix_test::init_service(
        App::new()
            .app_data(endpoint(Arc::new(AllowRequests)))
            .route(
                "/scim/v2/ServiceProviderConfig",
                web::get().to(scim_service_provider_config),
            ),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/scim/v2/ServiceProviderConfig")
            .insert_header((header::AUTHORIZATION, "Bearer test"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let document = actix_test::read_body_json::<Value, _>(response).await;
    assert_eq!(document["id"], "nazo-oauth-scim");
    assert_eq!(document["patch"], json!({"supported": true}));
    assert_eq!(
        document["pagination"]["cursorTimeout"],
        nazo_identity::scim::SCIM_CURSOR_TIMEOUT_SECONDS
    );
    assert_eq!(
        document["securityEvents"],
        json!({"asyncRequest": "none", "eventUris": []})
    );
}

#[actix_web::test]
async fn event_poll_returns_rfc8936_shape_and_advertises_only_when_deliverable() {
    let app = actix_test::init_service(
        App::new()
            .app_data(event_endpoint())
            .route(
                "/scim/v2/ServiceProviderConfig",
                web::get().to(scim_service_provider_config),
            )
            .route(
                "/scim/v2/SecurityEvents",
                web::post().to(scim_poll_security_events),
            ),
    )
    .await;
    let config_response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/scim/v2/ServiceProviderConfig")
            .insert_header((header::AUTHORIZATION, "Bearer test"))
            .to_request(),
    )
    .await;
    let config = actix_test::read_body_json::<Value, _>(config_response).await;
    assert_eq!(
        config["securityEvents"]["eventUris"],
        serde_json::to_value(nazo_scim_events::SUPPORTED_EVENT_URIS).unwrap()
    );

    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/scim/v2/SecurityEvents")
            .insert_header((header::AUTHORIZATION, "Bearer test"))
            .set_json(json!({"maxEvents": 1, "returnImmediately": true}))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_test::read_body_json::<Value, _>(response).await;
    assert_eq!(body["sets"]["event-id"], "signed-set");
    assert_eq!(body["moreAvailable"], false);
}

#[actix_web::test]
async fn event_poll_requires_content_language_for_set_error_descriptions() {
    let app = actix_test::init_service(App::new().app_data(event_endpoint()).route(
        "/scim/v2/SecurityEvents",
        web::post().to(scim_poll_security_events),
    ))
    .await;
    let event_id = uuid::Uuid::now_v7().to_string();
    let response = actix_test::call_service(
        &app,
        actix_test::TestRequest::post()
            .uri("/scim/v2/SecurityEvents")
            .insert_header((header::AUTHORIZATION, "Bearer test"))
            .set_json(json!({
                "returnImmediately": true,
                "setErrs": {
                    (event_id): {
                        "err": "jwtClaims",
                        "description": "invalid claims"
                    }
                }
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
