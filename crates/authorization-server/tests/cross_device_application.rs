use nazo_oauth_server as app;
#[path = "support/authorization.rs"]
mod authorization_fixture;
use app::{
    contracts::{
        ciba::BackchannelAuthenticationForm,
        device::{DeviceAuthorizationForm, prepare_device_authorization},
        oauth_error::{OAuthEndpointError, OAuthErrorFields},
        token_client_auth::{BasicAuthorizationCredentials, TokenClientAuthTransportFacts},
    },
    ports::audit::{AuditFuture, SecurityAudit},
    services::ServerCibaService,
    sessions::CurrentSession,
    token::ciba::{CibaApplication, CibaConfig, CibaTokenHandles, prepare_ciba_creation},
};
use futures_executor::block_on;
use http::StatusCode;
use nazo_auth::{
    CibaAtomicResult, CibaRequestState, CibaStateFuture, CibaStateStorePort, CibaStateVersion,
    CibaStatus, CibaStoredRequest,
};
use nazo_identity::{PublicAccount, TenantId, UserId, ports::RepositoryError};
use serde_json::{Map, Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum AuditFailure {
    None,
    Preflight,
    Intent,
    Create,
}
struct Ports {
    account: Mutex<Option<Result<Option<PublicAccount>, RepositoryError>>>,
    allow_create: bool,
    state: Mutex<CibaRequestState>,
    calls: Mutex<Vec<&'static str>>,
    intents: Mutex<Vec<Map<String, Value>>>,
    failure: AuditFailure,
}
impl Ports {
    fn record_call(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}
impl CibaStateStorePort for Ports {
    type Version = CibaStateVersion;
    fn load<'a>(
        &'a self,
        _: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        self.record_call("load");
        Box::pin(async {
            let state = self.state.lock().unwrap().clone();
            let version = CibaStateVersion::new("1".into(), state.retention_expires_at);
            Ok(Some(CibaStoredRequest::new(state, version)))
        })
    }
    fn create<'a>(
        &'a self,
        _: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        assert!(self.allow_create);
        self.record_call("create");
        Box::pin(async move {
            if matches!(self.failure, AuditFailure::Create) {
                return Ok(CibaAtomicResult::Conflict);
            }
            *self.state.lock().unwrap() = state.clone();
            Ok(CibaAtomicResult::Applied)
        })
    }
    fn replace<'a>(
        &'a self,
        _: &'a str,
        _: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.record_call("decide");
        Box::pin(async move {
            *self.state.lock().unwrap() = state.clone();
            Ok(CibaAtomicResult::Applied)
        })
    }
    fn delete<'a>(
        &'a self,
        _: &'a str,
        _: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        panic!("unexpired request must not be deleted")
    }
}
impl SecurityAudit for Ports {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        self.record_call("audit_preflight");
        Box::pin(async {
            if matches!(self.failure, AuditFailure::Preflight) {
                anyhow::bail!("audit storage unavailable");
            }
            Ok(())
        })
    }
    fn record(&self, event: &str, _: Map<String, Value>) {
        assert!(matches!(
            event,
            "ciba_authorization_approved"
                | "ciba_authorization_denied"
                | "ciba_authorization_started"
        ));
        self.record_call("audit_result");
    }
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: Map<String, Value>,
    ) -> AuditFuture<'a> {
        assert!(matches!(
            event,
            "ciba_decision_intent" | "ciba_authorization_intent"
        ));
        self.record_call("audit_intent");
        self.intents.lock().unwrap().push(fields);
        Box::pin(async {
            if matches!(self.failure, AuditFailure::Intent) {
                anyhow::bail!("audit intent unavailable");
            }
            Ok(())
        })
    }
}
impl nazo_persistence::CibaAccountStore for Ports {
    fn by_email<'a>(
        &'a self,
        _: TenantId,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PublicAccount>, RepositoryError>> + Send + 'a>>
    {
        self.record_call("account");
        Box::pin(async {
            self.account
                .lock()
                .unwrap()
                .as_ref()
                .expect("account lookup must be configured")
                .clone()
        })
    }
    fn by_id(
        &self,
        _: TenantId,
        _: UserId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PublicAccount>, RepositoryError>> + Send + '_>>
    {
        panic!("unexpected account lookup")
    }
}
fn fixture(
    failure: AuditFailure,
) -> (
    CibaApplication,
    Arc<Ports>,
    CurrentSession,
    authorization_fixture::Fixture,
) {
    fixture_with_client(failure, authorization_fixture::client(true), false)
}
fn fixture_with_client(
    failure: AuditFailure,
    client: nazo_auth::OAuthClient,
    allow_create: bool,
) -> (
    CibaApplication,
    Arc<Ports>,
    CurrentSession,
    authorization_fixture::Fixture,
) {
    let user = authorization_fixture::account();
    let now = chrono::Utc::now().timestamp();
    let state = CibaRequestState {
        client_id: "client-1".into(),
        user_id: user.id(),
        scopes: vec!["openid".into()],
        audiences: vec!["resource://default".into()],
        acr: None,
        authentication_context: None,
        binding_message: Some("1234".into()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: None,
    };
    let ports = Arc::new(Ports {
        account: Mutex::new(None),
        allow_create,
        state: Mutex::new(state),
        calls: Mutex::new(vec![]),
        intents: Mutex::new(vec![]),
        failure,
    });
    let mut authorization = authorization_fixture::Fixture::new(Ok(Some(client)), Ok(None));
    authorization.config.client_secret_pepper = app::crypto::random_urlsafe_token().into();
    let config = CibaConfig {
        issuer: "https://issuer.example".into(),
        mtls_endpoint_base_url: "".into(),
        frontend_base_url: "https://frontend.example".into(),
        client_secret_pepper: authorization.config.client_secret_pepper.clone(),
        default_audience: "resource://default".into(),
        tenant_id: authorization.tenant_id,
        auth_req_id_ttl_seconds: 60,
        poll_interval_seconds: 5,
        ciba_fapi_profile: false,
        ciba_fapi2_hardening: false,
    };
    let application = CibaApplication::new(
        authorization.service.clone(),
        Arc::new(CibaTokenHandles::new(
            Arc::new(ServerCibaService::new(ports.clone())),
            ports.clone(),
            Arc::new(config),
        )),
        authorization.remote_client_documents.clone(),
        authorization.snapshots.clone(),
        ports.clone(),
    );
    let session = CurrentSession {
        user,
        auth_time: now - 10,
        amr: vec!["pwd".into(), "otp".into()],
        oidc_sid: "session-1".into(),
        logged_in_client_ids: vec![],
    };
    (application, ports, session, authorization)
}
fn fields(error: &OAuthEndpointError) -> &OAuthErrorFields {
    match error {
        OAuthEndpointError::Json(fields)
        | OAuthEndpointError::Authorization(fields)
        | OAuthEndpointError::Token { fields, .. } => fields,
        _ => panic!("expected OAuth fields"),
    }
}
#[test]
fn ciba_prepared_authentication_conflicts_fail_before_client_or_state_access() {
    let (_, ports, _, authorization) = fixture(AuditFailure::None);
    for (form, has_basic) in [
        (
            BackchannelAuthenticationForm {
                client_id: Some("client-1".into()),
                ..Default::default()
            },
            true,
        ),
        (
            BackchannelAuthenticationForm {
                client_secret: Some("secret".into()),
                client_assertion: Some("assertion".into()),
                ..Default::default()
            },
            false,
        ),
        (
            BackchannelAuthenticationForm {
                client_assertion_type: Some("assertion-type".into()),
                ..Default::default()
            },
            true,
        ),
    ] {
        let error = match prepare_ciba_creation(form, has_basic) {
            Err(error) => error,
            Ok(_) => panic!("mixed authentication must fail"),
        };
        assert_eq!(fields(&error).status, StatusCode::BAD_REQUEST);
        assert_eq!(fields(&error).error, "invalid_request");
    }
    assert!(authorization.ports.calls().is_empty());
    assert!(ports.calls().is_empty());
}
#[test]
fn ciba_missing_credentials_fail_before_client_or_state_access() {
    block_on(async {
        let (application, ports, _, authorization) = fixture(AuditFailure::None);
        let prepared =
            prepare_ciba_creation(BackchannelAuthenticationForm::default(), false).unwrap();
        let transport = TokenClientAuthTransportFacts::from_parts(
            BasicAuthorizationCredentials::Absent,
            None,
            None,
            None,
            None,
        );
        let error = match application
            .prepare_client(prepared, &transport, false)
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing credentials must fail"),
        };
        assert_eq!(fields(&error).error, "invalid_client");
        assert!(authorization.ports.calls().is_empty());
        assert!(ports.calls().is_empty());
    });
}
#[test]
fn device_prepared_authentication_conflicts_and_missing_client_fail_before_io() {
    for (client_id, secret, assertion, basic) in [
        (None, None, None, false),
        (Some("client-1"), Some("secret"), None, true),
        (Some("client-1"), Some("secret"), Some("assertion"), false),
    ] {
        let result = prepare_device_authorization(
            DeviceAuthorizationForm {
                client_id: client_id.map(str::to_owned),
                scope: None,
                resources: vec![],
                client_secret: secret.map(str::to_owned),
                client_assertion: assertion.map(str::to_owned),
                client_assertion_type: None,
            },
            basic,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid preflight must fail"),
        };
        assert_eq!(fields(&error).status, StatusCode::BAD_REQUEST);
        assert_eq!(fields(&error).error, "invalid_request");
    }
    let prepared = prepare_device_authorization(
        DeviceAuthorizationForm {
            client_id: Some("client-1".into()),
            scope: Some("openid".into()),
            resources: vec![],
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        },
        true,
    )
    .unwrap();
    assert_eq!(prepared.form().client_id.as_deref(), Some("client-1"));
}
#[test]
fn ciba_decision_persists_audit_intent_before_state_transition_and_result_audit() {
    block_on(async {
        let (application, ports, session, _) = fixture(AuditFailure::None);
        application
            .decide("auth-request".into(), "approve", &session, "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(
            ports.calls(),
            [
                "load",
                "audit_preflight",
                "audit_intent",
                "load",
                "decide",
                "audit_result"
            ]
        );
        let state = ports.state.lock().unwrap();
        assert_eq!(state.status, CibaStatus::Approved);
        let context = state.authentication_context.as_ref().unwrap();
        assert_eq!(context.auth_time, session.auth_time);
        assert_eq!(context.amr, session.amr);
        assert_eq!(context.oidc_sid.as_deref(), Some(session.oidc_sid.as_str()));
        let intents = ports.intents.lock().unwrap();
        assert_eq!(intents[0]["expected_user_id"], json!(session.user.id()));
        assert_eq!(
            intents[0]["source_ip_hash"],
            json!(app::crypto::blake3_hex("127.0.0.1"))
        );
    });
}
#[test]
fn ciba_decision_audit_failure_never_mutates_request_state() {
    block_on(async {
        for failure in [AuditFailure::Preflight, AuditFailure::Intent] {
            let (application, ports, session, _) = fixture(failure);
            let error = application
                .decide("auth-request".into(), "approve", &session, "127.0.0.1")
                .await
                .unwrap_err();
            assert_eq!(fields(&error).status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(fields(&error).error, "server_error");
            assert_eq!(ports.state.lock().unwrap().status, CibaStatus::Pending);
            let expected = if matches!(failure, AuditFailure::Preflight) {
                vec!["load", "audit_preflight"]
            } else {
                vec!["load", "audit_preflight", "audit_intent"]
            };
            assert_eq!(ports.calls(), expected);
        }
    });
}
#[test]
fn ciba_decision_binds_expected_user_to_current_session() {
    block_on(async {
        let (application, ports, mut session, _) = fixture(AuditFailure::None);
        session.user.principal.user_id = UserId::new(Uuid::from_u128(999)).unwrap();
        let error = application
            .decide("auth-request".into(), "deny", &session, "127.0.0.1")
            .await
            .unwrap_err();
        assert_eq!(fields(&error).status, StatusCode::FORBIDDEN);
        assert_eq!(fields(&error).error, "access_denied");
        assert_eq!(ports.state.lock().unwrap().status, CibaStatus::Pending);
        assert_eq!(
            ports.calls(),
            ["load", "audit_preflight", "audit_intent", "load"]
        );
        assert_eq!(
            ports.intents.lock().unwrap()[0]["expected_user_id"],
            json!(session.user.id())
        );
    });
}
#[test]
fn ciba_invalid_decision_does_not_read_store_or_emit_audit() {
    block_on(async {
        let (application, ports, session, _) = fixture(AuditFailure::None);
        let error = application
            .decide("auth-request".into(), "invalid", &session, "127.0.0.1")
            .await
            .unwrap_err();
        assert_eq!(fields(&error).error, "invalid_request");
        assert!(ports.calls().is_empty());
    });
}

#[path = "support/ciba_creation_application.rs"]
mod ciba_creation;
