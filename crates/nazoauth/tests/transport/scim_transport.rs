use bytes::Bytes;
use http::{StatusCode, header};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use crate::http::{
    ClientIpConfig, ClientIpHeaderMode, IpCidr, ScimEndpoint, scim_poll_security_events,
    scim_resource_types, scim_schemas, scim_service_provider_config,
};
use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{
        NewScimUser, PasswordHashInput, RepositoryError, RepositoryFuture, ScimCredentialPort,
        ScimListQuery, ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimCursorSubject, ScimPatch, ScimRequiredScope, ScimService},
};
use nazo_oauth_server::contracts::scim::{
    ScimAuthenticationFacts, ScimAuthorizationError, ScimAuthorizedRequest,
    ScimBootstrapPasswordProvider, ScimCursorProtector, ScimDependencyError, ScimFuture,
    ScimRequestAuthorizer,
};
use nazo_scim_events::{EventPollerPort, EventReceiver, MutationContext, ValidatedPollRequest};
use serde_json::json;

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

    fn delete<'a>(
        &'a self,
        _tenant: TenantContext,
        _user_id: UserId,
        _mutation: MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

struct UnusedCredentials;

impl ScimCredentialPort for UnusedCredentials {
    fn active_credential<'a>(
        &'a self,
        _token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::scim::ScimTokenCredential>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
}

struct AllowRequests;

impl ScimRequestAuthorizer for AllowRequests {
    fn authorize<'a>(
        &'a self,
        _facts: ScimAuthenticationFacts<'a>,
        _required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        Box::pin(async {
            let tenant = TenantContext::default_system();
            Ok(ScimAuthorizedRequest {
                modules: test_modules(false),
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

type CapturedAuthenticationFact = (Option<String>, String, Option<String>);

#[derive(Default)]
struct CapturedAuthenticationFacts {
    values: std::sync::Mutex<Vec<CapturedAuthenticationFact>>,
}

impl ScimRequestAuthorizer for CapturedAuthenticationFacts {
    fn authorize<'a>(
        &'a self,
        facts: ScimAuthenticationFacts<'a>,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        assert_eq!(required_scope, ScimRequiredScope::Read);
        self.values.lock().unwrap().push((
            facts.bearer_token.map(ToOwned::to_owned),
            facts.source_ip,
            facts.user_agent.map(ToOwned::to_owned),
        ));
        Box::pin(async { Err(ScimAuthorizationError::MissingBearer) })
    }
}

impl ScimRequestAuthorizer for DenyRequests {
    fn authorize<'a>(
        &'a self,
        _facts: ScimAuthenticationFacts<'a>,
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
        _facts: ScimAuthenticationFacts<'a>,
        _required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        let receiver = self.receiver.clone();
        Box::pin(async move {
            let tenant = TenantContext::default_system();
            Ok(ScimAuthorizedRequest {
                modules: test_modules(true),
                tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: tenant.tenant_id.as_uuid(),
                    actor: "event-test".to_owned(),
                },
                event_receiver: Some(receiver),
            })
        })
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

    fn unprotect<'a>(&self, _protected: &'a mut [u8]) -> Result<&'a [u8], ScimDependencyError> {
        Err(ScimDependencyError::Unavailable)
    }
}

struct UnusedPassword;

impl ScimBootstrapPasswordProvider for UnusedPassword {
    fn password_hash(&self) -> ScimFuture<'_, Result<PasswordHashInput, ScimDependencyError>> {
        Box::pin(async { Err(ScimDependencyError::Unavailable) })
    }
}

fn endpoint(authorizer: Arc<dyn ScimRequestAuthorizer>) -> ScimEndpoint {
    ScimEndpoint::new(
        ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedCredentials)),
        authorizer,
        Arc::new(UnusedCursor),
        Arc::new(UnusedPassword),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        "https://issuer.example",
    )
}

fn event_endpoint() -> ScimEndpoint {
    let tenant = TenantContext::default_system();

    ScimEndpoint::new(
        ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedCredentials)),
        Arc::new(EventRequests {
            receiver: EventReceiver {
                token_id: uuid::Uuid::now_v7(),
                tenant_id: tenant.tenant_id.as_uuid(),
                audience: "https://receiver.example/events".to_owned(),
            },
        }),
        Arc::new(UnusedCursor),
        Arc::new(UnusedPassword),
        ClientIpConfig::new(&[], ClientIpHeaderMode::None),
        "https://issuer.example",
    )
    .with_security_events(Arc::new(FixedPoller))
}

#[test]
fn authorization_extracts_only_bearer_source_ip_and_user_agent() {
    futures_executor::block_on(async {
        let captured = Arc::new(CapturedAuthenticationFacts::default());
        let app = ScimEndpoint::new(
            ScimService::new(Arc::new(UnusedRepository), Arc::new(UnusedCredentials)),
            captured.clone(),
            Arc::new(UnusedCursor),
            Arc::new(UnusedPassword),
            ClientIpConfig::new(
                &[IpCidr::parse("192.0.2.0/24").unwrap()],
                ClientIpHeaderMode::XForwardedFor,
            ),
            "https://issuer.example",
        );
        for (authorization, token) in [
            ("Bearer scim-token", Some("scim-token")),
            ("bearer\tscim-token", Some("scim-token")),
            ("  Bearer scim-token  ", Some("scim-token")),
            ("Basic scim-token", None),
            ("Bearer", None),
            ("Bearer ", None),
            ("Bearer scim-token extra", None),
        ] {
            let response = {
                let request = http::Request::builder()
                    .uri("/scim/v2/ServiceProviderConfig")
                    .extension(crate::integration::ConnectionFacts {
                        peer_addr: Some("192.0.2.10:1234".parse().unwrap()),
                        ..Default::default()
                    })
                    .header(header::AUTHORIZATION, authorization)
                    .header(header::USER_AGENT, "  scim-agent  ")
                    .header("x-forwarded-for", "203.0.113.7")
                    .body(Bytes::new())
                    .unwrap();
                scim_service_provider_config(&app, &request).await
            };
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                captured.values.lock().unwrap().pop().unwrap(),
                (
                    token.map(ToOwned::to_owned),
                    "203.0.113.7".to_owned(),
                    Some("  scim-agent  ".to_owned()),
                )
            );
        }
        let response = {
            let request = http::Request::builder()
                .uri("/scim/v2/ServiceProviderConfig")
                .extension(crate::integration::ConnectionFacts {
                    peer_addr: Some("198.51.100.10:1234".parse().unwrap()),
                    ..Default::default()
                })
                .header(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_bytes(b"Bearer \xff").unwrap(),
                )
                .header(
                    header::USER_AGENT,
                    header::HeaderValue::from_bytes(b"\xff").unwrap(),
                )
                .header("x-forwarded-for", "203.0.113.7")
                .body(Bytes::new())
                .unwrap();
            scim_service_provider_config(&app, &request).await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            captured.values.lock().unwrap().pop().unwrap(),
            (None, "198.51.100.10".to_owned(), None)
        );
        let response = {
            let request = http::Request::builder()
                .uri("/scim/v2/ServiceProviderConfig")
                .extension(crate::integration::ConnectionFacts {
                    peer_addr: Some("198.51.100.10:1234".parse().unwrap()),
                    ..Default::default()
                })
                .body(Bytes::new())
                .unwrap();
            scim_service_provider_config(&app, &request).await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            captured.values.lock().unwrap().pop().unwrap(),
            (None, "198.51.100.10".to_owned(), None)
        );
    });
}

#[test]
fn authorization_errors_preserve_scim_documents_and_bearer_challenge() {
    futures_executor::block_on(async {
        let app = endpoint(Arc::new(DenyRequests(
            ScimAuthorizationError::MissingBearer,
        )));
        let response = {
            let request = http::Request::builder()
                .uri("/scim/v2/ServiceProviderConfig")
                .body(Bytes::new())
                .unwrap();
            scim_service_provider_config(&app, &request).await
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/scim+json"
        );
        let document = serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(document["status"], "401");
    });
}

#[test]
fn provider_config_handler_preserves_http_contract() {
    futures_executor::block_on(async {
        let app = endpoint(Arc::new(AllowRequests));
        let response = {
            let request = http::Request::builder()
                .uri("/scim/v2/ServiceProviderConfig")
                .header(header::AUTHORIZATION, "Bearer test")
                .body(Bytes::new())
                .unwrap();
            scim_service_provider_config(&app, &request).await
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/scim+json"
        );
        let document = serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(document["id"], "nazo-oauth-scim");
        assert_eq!(document["patch"], json!({"supported": false}));
        assert_eq!(document["filter"]["supported"], false);
        assert_eq!(
            document["pagination"]["cursorTimeout"],
            nazo_identity::scim::SCIM_CURSOR_TIMEOUT_SECONDS
        );
        assert_eq!(
            document["securityEvents"],
            json!({"asyncRequest": "none", "eventUris": []})
        );
    });
}

#[test]
fn event_poll_returns_rfc8936_shape_and_advertises_only_when_deliverable() {
    futures_executor::block_on(async {
        let app = event_endpoint();
        let config_response = {
            let request = http::Request::builder()
                .uri("/scim/v2/ServiceProviderConfig")
                .header(header::AUTHORIZATION, "Bearer test")
                .body(Bytes::new())
                .unwrap();
            scim_service_provider_config(&app, &request).await
        };
        let config = serde_json::from_slice::<serde_json::Value>(config_response.body()).unwrap();
        assert_eq!(
            config["securityEvents"]["eventUris"],
            serde_json::to_value(nazo_scim_events::SUPPORTED_EVENT_URIS).unwrap()
        );

        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/scim/v2/SecurityEvents")
                .header(header::AUTHORIZATION, "Bearer test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({"maxEvents": 1, "returnImmediately": true}))
                        .unwrap(),
                ))
                .unwrap();
            scim_poll_security_events(&app, &request, crate::http::parse_json(&request).unwrap())
                .await
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
        assert_eq!(body["sets"]["event-id"], "signed-set");
        assert_eq!(body["moreAvailable"], false);
    });
}

#[test]
fn event_poll_requires_content_language_for_set_error_descriptions() {
    futures_executor::block_on(async {
        let app = event_endpoint();
        let event_id = uuid::Uuid::now_v7().to_string();
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/scim/v2/SecurityEvents")
                .header(header::AUTHORIZATION, "Bearer test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({
                        "returnImmediately": true,
                        "setErrs": {
                            (event_id): {
                                "err": "jwtClaims",
                                "description": "invalid claims"
                            }
                        }
                    }))
                    .unwrap(),
                ))
                .unwrap();
            scim_poll_security_events(&app, &request, crate::http::parse_json(&request).unwrap())
                .await
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    });
}

struct DiscoveryAuthority {
    calls: AtomicUsize,
    events_enabled: AtomicBool,
    denial: Mutex<Option<ScimAuthorizationError>>,
}

impl ScimRequestAuthorizer for DiscoveryAuthority {
    fn authorize<'a>(
        &'a self,
        facts: ScimAuthenticationFacts<'a>,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        assert_eq!(facts.bearer_token, Some("discovery-token"));
        assert_eq!(required_scope, ScimRequiredScope::Read);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let denial = *self.denial.lock().unwrap();
        Box::pin(async move {
            if let Some(error) = denial {
                return Err(error);
            }
            let tenant = TenantContext::default_system();
            Ok(ScimAuthorizedRequest {
                modules: test_modules(self.events_enabled.load(Ordering::SeqCst)),
                tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: tenant.tenant_id.as_uuid(),
                    actor: "discovery".into(),
                },
                event_receiver: None,
            })
        })
    }
}

fn endpoint_with_poller(
    authorizer: Arc<dyn ScimRequestAuthorizer>,
    poller: Arc<dyn EventPollerPort>,
) -> ScimEndpoint {
    endpoint(authorizer).clone().with_security_events(poller)
}

#[test]
fn discovery_cached_bodies_keep_per_request_authority_and_current_variants() {
    futures_executor::block_on(async {
        let authority = Arc::new(DiscoveryAuthority {
            calls: AtomicUsize::new(0),
            events_enabled: AtomicBool::new(false),
            denial: Mutex::new(None),
        });
        let app = endpoint_with_poller(authority.clone(), Arc::new(FixedPoller));
        for enabled in [false, true, false] {
            authority.events_enabled.store(enabled, Ordering::SeqCst);
            for uri in ["/config", "/schemas", "/resources"] {
                let response = {
                    let request = http::Request::builder()
                        .uri(uri)
                        .header(header::ACCEPT, "application/scim+json")
                        .header(header::AUTHORIZATION, "Bearer discovery-token")
                        .body(Bytes::new())
                        .unwrap();
                    match uri {
                        "/config" => scim_service_provider_config(&app, &request).await,
                        "/schemas" => scim_schemas(&app, &request).await,
                        "/resources" => scim_resource_types(&app, &request).await,
                        _ => unreachable!(),
                    }
                };
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.headers().get(header::CONTENT_TYPE).unwrap(),
                    "application/scim+json"
                );
                let body = response.into_body();
                let expected = match uri {
                    "/config" => {
                        nazo_identity::scim::scim_service_provider_config_document_with_events(
                            enabled,
                        )
                    }
                    "/schemas" => nazo_identity::scim::scim_schemas_document(),
                    _ => nazo_identity::scim::scim_resource_types_document(),
                };
                assert_eq!(
                    body.as_ref(),
                    serde_json::to_vec(&expected).unwrap().as_slice()
                );
            }
        }
        // Cached documents must not reuse previous successful admission.
        *authority.denial.lock().unwrap() = Some(ScimAuthorizationError::InvalidBearer);
        for uri in ["/config", "/schemas", "/resources"] {
            let response = {
                let request = http::Request::builder()
                    .uri(uri)
                    .header(header::AUTHORIZATION, "Bearer discovery-token")
                    .body(Bytes::new())
                    .unwrap();
                match uri {
                    "/config" => scim_service_provider_config(&app, &request).await,
                    "/schemas" => scim_schemas(&app, &request).await,
                    "/resources" => scim_resource_types(&app, &request).await,
                    _ => unreachable!(),
                }
            };
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(authority.calls.load(Ordering::SeqCst), 12);
    });
}

#[derive(Clone, Copy, Debug)]
enum PollBoundaryChange {
    None,
    RevokedOrExpired,
    ScopeRemoved,
    ScimDisabled,
    BackendUnavailable,
    DeliveryDisabled,
    ReceiverMissing,
    ReceiverChanged,
    ReceiverIdentityChanged,
    TenantChanged,
}

struct PollBoundaryAuthority {
    receiver: EventReceiver,
    released_poll: Arc<AtomicBool>,
    calls: AtomicUsize,
    change: PollBoundaryChange,
}

impl ScimRequestAuthorizer for PollBoundaryAuthority {
    fn authorize<'a>(
        &'a self,
        facts: ScimAuthenticationFacts<'a>,
        required_scope: ScimRequiredScope,
    ) -> ScimFuture<'a, Result<ScimAuthorizedRequest, ScimAuthorizationError>> {
        assert_eq!(facts.bearer_token, Some("poll-token"));
        assert_eq!(required_scope, ScimRequiredScope::Events);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let final_check = self.released_poll.load(Ordering::SeqCst);
            let mut tenant = TenantContext::default_system();
            let mut receiver = Some(self.receiver.clone());
            if final_check {
                match self.change {
                    PollBoundaryChange::RevokedOrExpired => {
                        return Err(ScimAuthorizationError::InvalidBearer);
                    }
                    PollBoundaryChange::ScopeRemoved => {
                        return Err(ScimAuthorizationError::InsufficientScope);
                    }
                    PollBoundaryChange::ScimDisabled => {
                        return Err(ScimAuthorizationError::Disabled);
                    }
                    PollBoundaryChange::BackendUnavailable => {
                        return Err(ScimAuthorizationError::BackendUnavailable);
                    }
                    PollBoundaryChange::ReceiverMissing => receiver = None,
                    PollBoundaryChange::ReceiverChanged => {
                        receiver.as_mut().unwrap().audience =
                            "https://changed.example/events".into()
                    }
                    PollBoundaryChange::ReceiverIdentityChanged => {
                        receiver.as_mut().unwrap().token_id = uuid::Uuid::now_v7()
                    }
                    PollBoundaryChange::TenantChanged => {
                        tenant.tenant_id =
                            nazo_identity::TenantId::new(uuid::Uuid::from_u128(999)).unwrap()
                    }
                    _ => {}
                }
            }
            Ok(ScimAuthorizedRequest {
                modules: test_modules(
                    !(self.released_poll.load(Ordering::SeqCst)
                        && matches!(self.change, PollBoundaryChange::DeliveryDisabled)),
                ),
                tenant,
                cursor_subject: ScimCursorSubject {
                    tenant_id: tenant.tenant_id.as_uuid(),
                    actor: "poll".into(),
                },
                event_receiver: receiver,
            })
        })
    }
}

struct PollBoundaryPoller {
    receiver: EventReceiver,
    released_poll: Arc<AtomicBool>,
    requests: Mutex<Vec<(Vec<uuid::Uuid>, usize)>>,
    empty_response: bool,
}

impl EventPollerPort for PollBoundaryPoller {
    fn poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> nazo_scim_events::EventFuture<
        'a,
        Result<nazo_scim_events::PollResponse, nazo_scim_events::PollError>,
    > {
        assert_eq!(receiver, &self.receiver);
        self.requests
            .lock()
            .unwrap()
            .push((request.ack.clone(), request.set_errors.len()));
        Box::pin(async move {
            let mut pending = true;
            std::future::poll_fn(|cx| {
                if std::mem::take(&mut pending) {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(())
                }
            })
            .await;
            self.released_poll.store(true, Ordering::SeqCst);
            Ok(nazo_scim_events::PollResponse {
                sets: if self.empty_response {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([("new-event".into(), "signed-set".into())])
                },
                more_available: false,
            })
        })
    }
}

#[test]
fn event_poll_rechecks_authority_after_wait_and_passes_dispositions_once() {
    futures_executor::block_on(async {
        use PollBoundaryChange::*;
        for (change, expected) in [
            (None, StatusCode::OK),
            (RevokedOrExpired, StatusCode::UNAUTHORIZED),
            (ScopeRemoved, StatusCode::FORBIDDEN),
            (ScimDisabled, StatusCode::NOT_FOUND),
            (BackendUnavailable, StatusCode::SERVICE_UNAVAILABLE),
            (DeliveryDisabled, StatusCode::NOT_FOUND),
            (ReceiverMissing, StatusCode::FORBIDDEN),
            (ReceiverChanged, StatusCode::UNAUTHORIZED),
            (ReceiverIdentityChanged, StatusCode::UNAUTHORIZED),
            (TenantChanged, StatusCode::FORBIDDEN),
        ] {
            let receiver = EventReceiver {
                token_id: uuid::Uuid::now_v7(),
                tenant_id: TenantContext::default_system().tenant_id.as_uuid(),
                audience: "https://receiver.example/events".into(),
            };
            let released_poll = Arc::new(AtomicBool::new(false));
            let authority = Arc::new(PollBoundaryAuthority {
                receiver: receiver.clone(),
                released_poll: released_poll.clone(),
                calls: AtomicUsize::new(0),
                change,
            });
            let poller = Arc::new(PollBoundaryPoller {
                receiver,
                released_poll,
                requests: Mutex::new(Vec::new()),
                empty_response: false,
            });
            let app = endpoint_with_poller(authority.clone(), poller.clone());
            let acknowledged = uuid::Uuid::now_v7();
            let errored = uuid::Uuid::now_v7();
            let response = {
                let request = http::Request::builder().method("POST").uri("/events").header(header::AUTHORIZATION, "Bearer poll-token").header(header::CONTENT_LANGUAGE, "en").header(header::CONTENT_TYPE, "application/json").body(Bytes::from(serde_json::to_vec(&json!({"returnImmediately": false, "ack": [acknowledged.to_string()],
                "setErrs": {(errored.to_string()): {"err": "jwtClaims", "description": "invalid claims"}}})).unwrap())).unwrap();
                scim_poll_security_events(
                    &app,
                    &request,
                    crate::http::parse_json(&request).unwrap(),
                )
                .await
            };
            assert_eq!(response.status(), expected, "{change:?}");
            let body = serde_json::from_slice::<serde_json::Value>(response.body()).unwrap();
            if expected == StatusCode::OK {
                assert_eq!(body["sets"]["new-event"], "signed-set");
            } else {
                assert!(body.get("sets").is_none(), "{change:?}: {body}");
            }
            assert_eq!(authority.calls.load(Ordering::SeqCst), 2, "{change:?}");
            assert_eq!(
                *poller.requests.lock().unwrap(),
                vec![(vec![acknowledged], 1)]
            );
        }
    });
}

#[test]
fn empty_immediate_poll_also_rechecks_current_authority() {
    futures_executor::block_on(async {
        let receiver = EventReceiver {
            token_id: uuid::Uuid::now_v7(),
            tenant_id: TenantContext::default_system().tenant_id.as_uuid(),
            audience: "https://receiver.example/events".into(),
        };
        let released_poll = Arc::new(AtomicBool::new(false));
        let authority = Arc::new(PollBoundaryAuthority {
            receiver: receiver.clone(),
            released_poll: released_poll.clone(),
            calls: AtomicUsize::new(0),
            change: PollBoundaryChange::RevokedOrExpired,
        });
        let poller = Arc::new(PollBoundaryPoller {
            receiver,
            released_poll,
            requests: Mutex::new(Vec::new()),
            empty_response: true,
        });
        let app = endpoint_with_poller(authority.clone(), poller.clone());
        let response = {
            let request = http::Request::builder()
                .method("POST")
                .uri("/events")
                .header(header::AUTHORIZATION, "Bearer poll-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Bytes::from(
                    serde_json::to_vec(&json!({"returnImmediately": true})).unwrap(),
                ))
                .unwrap();
            scim_poll_security_events(&app, &request, crate::http::parse_json(&request).unwrap())
                .await
        };
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
        assert_eq!(poller.requests.lock().unwrap().len(), 1);
    });
}

fn test_modules(events_enabled: bool) -> Arc<nazo_runtime_modules::RequestSnapshot> {
    use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision, SnapshotStore};
    let mut accepting = std::collections::BTreeSet::from([ModuleId::Scim]);
    if events_enabled {
        accepting.insert(ModuleId::ScimSecurityEvents);
    }
    Arc::new(
        SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting,
            draining: Default::default(),
        })
        .request(),
    )
}
