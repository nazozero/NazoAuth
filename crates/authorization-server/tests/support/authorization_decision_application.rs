use super::*;
use app::{
    contracts::authorization_decision::{
        AuthorizationDecisionCommand, AuthorizationDecisionError, AuthorizationDecisionOperations,
    },
    domain::authorization_decision::ServerAuthorizationDecisionOperations,
    ports::audit::{AuditFuture, SecurityAudit},
};
use nazo_auth::{ConsentPayload, UserAuthorizationDecision};
use serde_json::{Map, Value, json};
use std::sync::Mutex;

#[derive(Clone, Copy)]
enum Failure {
    None,
    DynamicReadiness,
    RequiredAppend,
}

struct Audit {
    failure: Failure,
    ports: Arc<Ports>,
    calls: Mutex<Vec<&'static str>>,
}

impl SecurityAudit for Audit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        panic!("the required intent owns the writer check")
    }

    fn ensure_transactional_ready(&self) -> AuditFuture<'_> {
        Box::pin(async {
            self.calls.lock().unwrap().push("dynamic_readiness");
            if matches!(self.failure, Failure::DynamicReadiness) {
                anyhow::bail!("audit anchor unavailable");
            }
            Ok(())
        })
    }

    fn record_required<'a>(&'a self, event: &'a str, _: Map<String, Value>) -> AuditFuture<'a> {
        Box::pin(async move {
            assert_eq!(event, "authorization_decision_intent");
            assert!(self.ports.consent.lock().unwrap().is_some());
            assert!(!self.ports.calls().contains(&"consume_consent"));
            self.calls.lock().unwrap().push("required_append");
            if matches!(self.failure, Failure::RequiredAppend) {
                anyhow::bail!("audit append unavailable");
            }
            Ok(())
        })
    }

    fn record(&self, event: &str, _: Map<String, Value>) {
        assert_eq!(event, "authorization_denied");
        assert!(self.ports.consent.lock().unwrap().is_none());
        self.calls.lock().unwrap().push("outcome");
    }
}

fn consent() -> ConsentPayload {
    let now = chrono::Utc::now();
    ConsentPayload {
        request_id: "request".into(),
        user_id: authorization_fixture::account().id(),
        client_id: "client-1".into(),
        client_name: "Client".into(),
        redirect_uri: "https://client.example/callback".into(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".into()],
        resource_indicators: vec![],
        authorization_details: json!([]),
        state: None,
        response_mode: Some("query".into()),
        nonce: None,
        auth_time: now.timestamp(),
        amr: vec!["pwd".into()],
        oidc_sid: Some("oidc-session".into()),
        acr: None,
        userinfo_claims: vec![],
        userinfo_claim_requests: vec![],
        id_token_claims: vec![],
        id_token_claim_requests: vec![],
        code_challenge: Some("challenge".into()),
        code_challenge_method: Some("S256".into()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        signed_authorization_response_required: None,
        session_management_allowed: None,
        authorization_code_ttl_seconds: None,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(5),
    }
}

#[test]
fn decision_requires_dynamic_readiness_and_durable_intent_before_consuming_consent() {
    block_on(async {
        for failure in [
            Failure::None,
            Failure::DynamicReadiness,
            Failure::RequiredAppend,
        ] {
            let fixture = Fixture::new(Ok(Some(client(true))), Ok(Some(session())));
            *fixture.ports.consent.lock().unwrap() = Some(consent());
            let audit = Arc::new(Audit {
                failure,
                ports: fixture.ports.clone(),
                calls: Mutex::new(vec![]),
            });
            let tenant = nazo_identity::TenantId::new(fixture.tenant_id).unwrap();
            let application = ServerAuthorizationDecisionOperations::new(
                fixture.service,
                nazo_identity::SessionService::new(
                    fixture.ports.clone(),
                    fixture.ports.clone(),
                    tenant,
                ),
                tenant,
                Arc::new(fixture.config),
                fixture.snapshots,
                fixture.remote_client_documents,
                audit.clone(),
            );
            let result = application
                .decide(AuthorizationDecisionCommand {
                    request_id: "request".into(),
                    decision: UserAuthorizationDecision::Deny,
                    session_id: SessionId::new("active"),
                    source_ip: "192.0.2.1".into(),
                })
                .await;
            let expected = match failure {
                Failure::None => {
                    assert!(result.is_ok(), "{result:?}");
                    assert!(fixture.ports.consent.lock().unwrap().is_none());
                    vec!["dynamic_readiness", "required_append", "outcome"]
                }
                Failure::DynamicReadiness | Failure::RequiredAppend => {
                    assert_eq!(
                        result.unwrap_err(),
                        AuthorizationDecisionError::AuditUnavailable
                    );
                    assert!(fixture.ports.consent.lock().unwrap().is_some());
                    assert!(!fixture.ports.calls().contains(&"consume_consent"));
                    if matches!(failure, Failure::DynamicReadiness) {
                        vec!["dynamic_readiness"]
                    } else {
                        vec!["dynamic_readiness", "required_append"]
                    }
                }
            };
            assert_eq!(*audit.calls.lock().unwrap(), expected);
        }
    });
}
