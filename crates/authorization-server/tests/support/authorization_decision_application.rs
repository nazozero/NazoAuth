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
    DecisionCommit,
}

struct Audit {
    failure: Failure,
    calls: Mutex<Vec<&'static str>>,
}

impl SecurityAudit for Audit {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        panic!("decision preflight owns the writer readiness check")
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

    fn record_required<'a>(&'a self, _: &'a str, _: Map<String, Value>) -> AuditFuture<'a> {
        panic!("the repository commit owns the immutable decision fact")
    }

    fn record(&self, _: &str, _: Map<String, Value>) {
        panic!("committed decisions must not emit a second success telemetry fact")
    }

}

fn consent() -> ConsentPayload {
    let now = chrono::Utc::now();
    ConsentPayload {
        request_id: "payload-display-id".into(),
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
fn decision_commits_durable_denial_before_discarding_preparation() {
    block_on(async {
        for failure in [Failure::None, Failure::DynamicReadiness, Failure::DecisionCommit] {
            let fixture = Fixture::new(Ok(Some(client(true))), Ok(Some(session())));
            let mut payload = consent();
            let valid_until = payload.expires_at;
            let retain_until = payload.expires_at + chrono::Duration::minutes(5);
            let par = nazo_auth::PushedAuthorizationRequest {
                client_id: payload.client_id.clone(),
                params: HashMap::new(),
                dpop_jkt: None,
                mtls_x5t_s256: None,
                issued_at: payload.issued_at,
                expires_at: retain_until,
            };
            payload.pushed_request_uri = Some("par".into());
            payload.pushed_request_digest =
                Some(nazo_auth::pushed_authorization_request_digest(&par).unwrap());
            fixture.ports.stored_par.lock().unwrap().push(("par".into(), par, 600));
            *fixture.ports.consent.lock().unwrap() = Some(payload);
            fixture.ports.decisions.lock().unwrap().outcome = Some(
                if matches!(failure, Failure::DecisionCommit) {
                    Err(AuthorizationPortError::Unavailable)
                } else {
                    Ok(nazo_auth::AuthorizationDecisionCommitResult::Committed)
                },
            );
            let audit = Arc::new(Audit {
                failure,
                calls: Mutex::new(vec![]),
            });
            let tenant = nazo_identity::TenantId::new(fixture.tenant_id).unwrap();
            let application = ServerAuthorizationDecisionOperations::new(
                fixture.service,
                nazo_identity::SessionService::new(fixture.ports.clone(), fixture.ports.clone(), tenant),
                tenant,
                Arc::new(fixture.config),
                fixture.snapshots,
                fixture.remote_client_documents,
                audit.clone(),
            );
            let result = application.decide(AuthorizationDecisionCommand {
                request_id: "request".into(),
                decision: UserAuthorizationDecision::Deny,
                session_id: SessionId::new("active"),
                source_ip: "192.0.2.1".into(),
            }).await;
            let calls = fixture.ports.calls();
            match failure {
                Failure::None => {
                    assert!(result.is_ok(), "{result:?}");
                    assert!(fixture.ports.consent.lock().unwrap().is_none());
                    assert!(calls.iter().position(|call| *call == "commit_decision").unwrap()
                        < calls.iter().position(|call| *call == "consume_consent").unwrap());
                    let decisions = fixture.ports.decisions.lock().unwrap();
                    assert_eq!(decisions.facts.len(), 1);
                    assert_eq!(decisions.facts[0].request_id, "request",
                        "the storage/command identity owns the consumption fence");
                    assert_eq!(decisions.facts[0].decision, nazo_auth::AuthorizationDecisionKind::Deny);
                    assert_eq!(decisions.facts[0].valid_until, valid_until);
                    assert_eq!(decisions.facts[0].retain_until, retain_until,
                        "a shorter consent must not free a still-live PAR fence");
                    assert!(decisions.facts[0].audit_fields.get("code_hash").is_none());
                    assert_eq!(decisions.explicit_grant_writes, 0);
                }
                Failure::DynamicReadiness | Failure::DecisionCommit => {
                    assert_eq!(result.unwrap_err(), if matches!(failure, Failure::DynamicReadiness) {
                        AuthorizationDecisionError::AuditUnavailable
                    } else {
                        AuthorizationDecisionError::ApprovalUnavailable
                    });
                    assert!(fixture.ports.consent.lock().unwrap().is_some());
                    assert!(!calls.contains(&"consume_consent"));
                    assert!(fixture.ports.decisions.lock().unwrap().facts.is_empty());
                }
            }
            assert!(fixture.ports.stored_codes.lock().unwrap().is_empty());
            assert_eq!(*audit.calls.lock().unwrap(), ["dynamic_readiness"]);
        }
    });
}
