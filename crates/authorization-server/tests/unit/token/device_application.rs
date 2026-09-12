use super::*;
use crate::contracts::device::prepare_device_authorization;
use crate::rate_limit::TokenManagementRequestLimiter;
use crate::services::ServerDeviceGrantService;
use crate::sessions::CurrentSession;
use crate::token::device::DeviceDecisionHandles;
use nazo_auth::{
    AuthorizationPortError, DeviceAtomicResult, DeviceCreateResult, DeviceGrantFuture,
    DeviceGrantRepositoryPort, DeviceGrantWrite, DeviceStateFuture, DeviceStateStorePort,
    DeviceStateVersion, RequestRateLimitBucket, RequestRateLimitFuture, RequestRateLimitPort,
    StoredDeviceAuthorization,
};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision, SnapshotStore};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    None,
    State,
    Create,
    Complete,
    Grant,
    AuditPreflight,
    AuditIntent,
}

struct Ports {
    state: Mutex<Option<DeviceAuthorizationState>>,
    failure: Mutex<Failure>,
    calls: Mutex<Vec<&'static str>>,
    client: ClientRow,
}
impl Ports {
    fn fail(&self, failure: Failure) -> bool {
        *self.failure.lock().unwrap() == failure
    }
    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
    fn load(&self) -> DeviceStateFuture<'_, Option<StoredDeviceAuthorization<DeviceStateVersion>>> {
        self.record("load");
        Box::pin(async {
            if self.fail(Failure::State) {
                return Err(nazo_auth::DeviceStatePortError::Unavailable);
            }
            Ok(self.state.lock().unwrap().clone().map(|state| {
                StoredDeviceAuthorization::new(state, DeviceStateVersion::new("1".into()))
            }))
        })
    }
    fn replace<'a>(
        &'a self,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            *self.state.lock().unwrap() = Some(replacement.clone());
            Ok(DeviceAtomicResult::Applied)
        })
    }
}
impl DeviceStateStorePort for Ports {
    type Version = DeviceStateVersion;
    fn create<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl: u64,
    ) -> DeviceStateFuture<'a, DeviceCreateResult> {
        self.record("create");
        Box::pin(async move {
            assert_eq!(ttl, 600);
            if self.fail(Failure::Create) {
                return Err(nazo_auth::DeviceStatePortError::Unavailable);
            }
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(DeviceCreateResult::Applied)
        })
    }
    fn load_by_device_code<'a>(
        &'a self,
        _: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        self.load()
    }
    fn load_by_device_hash<'a>(
        &'a self,
        _: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        self.load()
    }
    fn resolve_user_code<'a>(&'a self, _: &'a str) -> DeviceStateFuture<'a, Option<String>> {
        Box::pin(async {
            if self.fail(Failure::State) {
                return Err(nazo_auth::DeviceStatePortError::Unavailable);
            }
            Ok(self.state.lock().unwrap().as_ref().map(|_| "hash".into()))
        })
    }
    fn replace_by_device_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a Self::Version,
        state: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        self.replace(state)
    }
    fn replace_by_device_hash<'a>(
        &'a self,
        _: &'a str,
        _: &'a Self::Version,
        state: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        self.replace(state)
    }
    fn complete_decision<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a Self::Version,
        state: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        self.record("complete");
        Box::pin(async move {
            if self.fail(Failure::Complete) {
                return Err(nazo_auth::DeviceStatePortError::Unavailable);
            }
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(DeviceAtomicResult::Applied)
        })
    }
    fn consume_by_device_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a Self::Version,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        panic!("decision must not consume a token")
    }
    fn delete_user_code_if_matches<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async { Ok(DeviceAtomicResult::Applied) })
    }
}
impl DeviceGrantRepositoryPort for Ports {
    fn client_by_id<'a>(&'a self, id: &'a str) -> DeviceGrantFuture<'a, Option<ClientRow>> {
        Box::pin(async move {
            assert_eq!(id, self.client.client_id);
            Ok(Some(self.client.clone()))
        })
    }
    fn upsert_grant<'a>(&'a self, write: DeviceGrantWrite<'a>) -> DeviceGrantFuture<'a, ()> {
        self.record("grant");
        Box::pin(async move {
            assert_eq!(write.client_id, self.client.id);
            assert_eq!(write.scopes, ["openid"]);
            if self.fail(Failure::Grant) {
                return Err(nazo_auth::DeviceGrantPortError::Unavailable);
            }
            Ok(())
        })
    }
}
impl RequestRateLimitPort for Ports {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        _: &'a str,
        ttl: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            assert_eq!(bucket, RequestRateLimitBucket::TokenManagement);
            assert_eq!(ttl, 60);
            Ok(1)
        })
    }
}
impl SecurityAudit for Ports {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        self.record("audit_preflight");
        Box::pin(async {
            if self.fail(Failure::AuditPreflight) {
                anyhow::bail!("audit unavailable");
            }
            Ok(())
        })
    }
    fn record(&self, event: &str, fields: serde_json::Map<String, serde_json::Value>) {
        assert!(event.starts_with("device_"));
        assert_eq!(
            fields["source_ip_hash"],
            json!(crate::crypto::blake3_hex("127.0.0.1"))
        );
        self.record("outcome");
    }
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuditFuture<'a> {
        self.record("audit_intent");
        Box::pin(async move {
            assert_eq!(event, "device_decision_intent");
            assert_eq!(fields["client_id"], json!("device-client"));
            if self.fail(Failure::AuditIntent) {
                anyhow::bail!("audit intent unavailable");
            }
            Ok(())
        })
    }
}
fn handles(
    client: Result<Option<ClientRow>, AuthorizationPortError>,
) -> (DeviceDecisionHandles, Arc<Ports>) {
    let stored_client = client
        .as_ref()
        .ok()
        .and_then(|value| value.clone())
        .unwrap_or_else(device_client);
    let ports = Arc::new(Ports {
        state: Mutex::new(None),
        failure: Mutex::new(Failure::None),
        calls: Mutex::new(Vec::new()),
        client: stored_client,
    });
    let (_, authorization) = token_ports::services(Ok(None), client);
    let application = DeviceDecisionHandles::new(
        Arc::new(authorization),
        Arc::new(ServerDeviceGrantService::new(ports.clone())),
        ports.clone(),
        Arc::new(device_config()),
        Arc::new(SnapshotStore::new(ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting: [ModuleId::DeviceAuthorization].into(),
            draining: Default::default(),
        })),
        Arc::new(Dependencies),
        Arc::new(TokenManagementRequestLimiter::new(ports.clone(), 60, 10)),
        ports.clone(),
    );
    (application, ports)
}
fn pending(ports: &Ports) {
    let now = Utc::now();
    *ports.state.lock().unwrap() = Some(DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            client_id: "device-client".into(),
            client_name: "Device Client".into(),
            scopes: vec!["openid".into()],
            resource_indicators: vec!["resource://default".into()],
            authorization_details: json!([]),
            interval_seconds: 5,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
        },
        last_poll_at: None,
        slow_down_count: 0,
    });
}
fn session() -> CurrentSession {
    CurrentSession {
        user: crate::test_support::authorization::account(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".into()],
        oidc_sid: "device-session".into(),
        logged_in_client_ids: vec![],
    }
}
fn form() -> DeviceAuthorizationForm {
    DeviceAuthorizationForm {
        client_id: Some("device-client".into()),
        scope: Some("openid".into()),
        resources: vec![],
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    }
}
fn credentials() -> ClientCredentials {
    ClientCredentials {
        client_id: Some("device-client".into()),
        method: "none".into(),
        ..Default::default()
    }
}
fn assert_error(error: OAuthEndpointError, status: StatusCode, code: &str) {
    let OAuthEndpointError::Json(fields) = error else {
        panic!("device errors must be JSON")
    };
    assert_eq!(fields.status, status);
    assert_eq!(fields.error, code);
}

#[test]
fn create_and_verify_preserve_authorization_payload() {
    futures_executor::block_on(async {
        let (app, ports) = handles(Ok(Some(device_client())));
        app.check_admission(nazo_auth::CapabilityAdmission::NewRequest)
            .unwrap();
        app.enforce_creation_rate_limit("127.0.0.1").await.unwrap();
        let response = app
            .create(
                prepare_device_authorization(form(), false).unwrap(),
                credentials(),
                ClientAuthRequestFacts::new("/device_authorization", None),
                "127.0.0.1",
            )
            .await
            .unwrap();
        assert!(!response.device_code.is_empty());
        assert_eq!(response.expires_in, 600);
        assert_eq!(response.interval, 5);
        assert!(
            response
                .verification_uri_complete
                .contains(&response.user_code)
        );
        let view = app.verification(&response.user_code).await;
        assert_eq!(view.request.unwrap().scopes, ["openid"]);
        assert!(app.verification(" ").await.request.is_none());
        *ports.failure.lock().unwrap() = Failure::State;
        assert!(
            app.verification(&response.user_code)
                .await
                .request
                .is_none()
        );
    });
}
#[test]
fn create_rejects_client_and_storage_failures_before_issuing_codes() {
    futures_executor::block_on(async {
        let mut inactive = device_client();
        inactive.is_active = false;
        let mut forbidden = device_client();
        forbidden.security_policy.allow_cross_device_flows = false;
        for (client, status, code) in [
            (Ok(None), StatusCode::UNAUTHORIZED, "invalid_client"),
            (
                Ok(Some(inactive)),
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            ),
            (
                Err(AuthorizationPortError::Unavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
            (
                Ok(Some(forbidden)),
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
            ),
        ] {
            let (app, ports) = handles(client);
            assert_error(
                app.create(
                    prepare_device_authorization(form(), false).unwrap(),
                    credentials(),
                    ClientAuthRequestFacts::new("/", None),
                    "127.0.0.1",
                )
                .await
                .err()
                .unwrap(),
                status,
                code,
            );
            assert!(ports.state.lock().unwrap().is_none());
        }
        let (app, ports) = handles(Ok(Some(device_client())));
        *ports.failure.lock().unwrap() = Failure::Create;
        assert_error(
            app.create(
                prepare_device_authorization(form(), false).unwrap(),
                credentials(),
                ClientAuthRequestFacts::new("/", None),
                "127.0.0.1",
            )
            .await
            .err()
            .unwrap(),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        );
        let mut invalid_scope = form();
        invalid_scope.scope = Some("unregistered".into());
        assert_error(
            app.create(
                prepare_device_authorization(invalid_scope, false).unwrap(),
                credentials(),
                ClientAuthRequestFacts::new("/", None),
                "127.0.0.1",
            )
            .await
            .err()
            .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_scope",
        );
    });
}
#[test]
fn approval_and_denial_require_audit_before_mutation() {
    futures_executor::block_on(async {
        for decision in ["approve", "deny"] {
            let (app, ports) = handles(Ok(Some(device_client())));
            pending(&ports);
            app.decide("AB-CD", decision, session(), "127.0.0.1")
                .await
                .unwrap();
            let calls = ports.calls.lock().unwrap();
            assert!(
                calls.iter().position(|c| *c == "audit_intent").unwrap()
                    < calls.iter().position(|c| *c == "complete").unwrap()
            );
            assert_eq!(calls.last(), Some(&"outcome"));
            let state = ports.state.lock().unwrap();
            if decision == "approve" {
                assert!(matches!(
                    state.as_ref().unwrap(),
                    DeviceAuthorizationState::Approved { .. }
                ));
            } else {
                assert!(matches!(
                    state.as_ref().unwrap(),
                    DeviceAuthorizationState::Denied { .. }
                ));
            }
        }
        for failure in [Failure::AuditPreflight, Failure::AuditIntent] {
            let (app, ports) = handles(Ok(Some(device_client())));
            pending(&ports);
            *ports.failure.lock().unwrap() = failure;
            assert_error(
                app.decide("ABCD", "approve", session(), "127.0.0.1")
                    .await
                    .unwrap_err(),
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            );
            assert!(matches!(
                ports.state.lock().unwrap().as_ref().unwrap(),
                DeviceAuthorizationState::Pending { .. }
            ));
            assert!(!ports.calls.lock().unwrap().contains(&"grant"));
        }
    });
}
#[test]
fn decision_rejects_invalid_requests_and_maps_dependency_failures() {
    futures_executor::block_on(async {
        for (code, decision, has_pending, failure, status) in [
            (
                " ",
                "approve",
                false,
                Failure::None,
                StatusCode::BAD_REQUEST,
            ),
            (
                "ABCD",
                "approve",
                false,
                Failure::None,
                StatusCode::BAD_REQUEST,
            ),
            (
                "ABCD",
                "unexpected",
                true,
                Failure::None,
                StatusCode::BAD_REQUEST,
            ),
            (
                "ABCD",
                "approve",
                true,
                Failure::State,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                "ABCD",
                "deny",
                true,
                Failure::Complete,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                "ABCD",
                "approve",
                true,
                Failure::Grant,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (app, ports) = handles(Ok(Some(device_client())));
            if has_pending {
                pending(&ports);
            }
            *ports.failure.lock().unwrap() = failure;
            assert_error(
                app.decide(code, decision, session(), "127.0.0.1")
                    .await
                    .unwrap_err(),
                status,
                if status == StatusCode::BAD_REQUEST {
                    "invalid_request"
                } else {
                    "server_error"
                },
            );
            assert!(!ports.calls.lock().unwrap().contains(&"outcome"));
        }
        for client in [Ok(None), Err(AuthorizationPortError::Unavailable)] {
            let unavailable = client.is_err();
            let (app, ports) = handles(client);
            pending(&ports);
            assert_error(
                app.decide("ABCD", "approve", session(), "127.0.0.1")
                    .await
                    .unwrap_err(),
                if unavailable {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::BAD_REQUEST
                },
                if unavailable {
                    "server_error"
                } else {
                    "invalid_request"
                },
            );
        }
        let mut client = device_client();
        client.subject_type = "pairwise".into();
        client.sector_identifier_host = Some("client.example".into());
        let (app, ports) = handles(Ok(Some(client)));
        pending(&ports);
        assert_error(
            app.decide("ABCD", "approve", session(), "127.0.0.1")
                .await
                .unwrap_err(),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        );
    });
}
