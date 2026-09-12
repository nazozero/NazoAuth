//! An external consumer exercises public application boundaries using semantic ports.
use futures_executor::block_on;
use nazo_oauth_server as app;
#[path = "support/authorization.rs"]
mod authorization_fixture;
use app::{
    authorization::AuthorizationRequestFacts,
    contracts::{oauth_error::OAuthEndpointError, request_facts::DpopRequestFacts},
    ports::transient_state::{
        CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
        TransientStateFuture,
    },
    security::dpop::validate_dpop_proof,
    workers::ciba_ping::{CibaPingDeliveryWorker, CibaPingSender},
};
use authorization_fixture::{Fixture, client};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{
    DPOP_REPLAY_TTL_SECONDS, DpopError, DpopNoncePolicy, DpopStateFuture, DpopStateStorePort,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[test]
fn authorize_rejects_unregistered_redirect_before_session_access() {
    let fixture = Fixture::new(Ok(Some(client(true))), Ok(None));
    let application = fixture.make_application();
    let mut parameters = HashMap::from([
        ("client_id".into(), "client-1".into()),
        (
            "redirect_uri".into(),
            "https://attacker.example/callback".into(),
        ),
        ("response_type".into(), "code".into()),
    ]);
    let facts = AuthorizationRequestFacts {
        source_ip: "192.0.2.4",
        session_id: None,
        user_agent: Some("external-consumer"),
    };
    let Err(OAuthEndpointError::Authorization(fields)) =
        block_on(application.authorize(&facts, &mut parameters))
    else {
        panic!("unregistered redirect must fail without navigation")
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(
        fields.description,
        "redirect_uri is not registered for this client."
    );
    assert_eq!(fixture.ports.calls(), ["client"]);
}

#[derive(Default)]
struct ProofStore(Mutex<Vec<(String, String, u64)>>);
impl DpopStateStorePort for ProofStore {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            let mut calls = self.0.lock().unwrap();
            let fresh = calls.is_empty();
            calls.push((jkt.to_owned(), jti.to_owned(), ttl));
            Ok(fresh)
        })
    }
    fn issue_nonce<'a>(&'a self, _: &'a str, _: u64) -> DpopStateFuture<'a, ()> {
        panic!("optional nonce does not issue a challenge")
    }
    fn validate_nonce<'a>(&'a self, _: &'a str) -> DpopStateFuture<'a, bool> {
        panic!("proof has no nonce")
    }
}

#[test]
fn security_facts_validate_signature_target_and_replay_without_host_state() {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let header = serde_json::json!({"typ":"dpop+jwt", "alg":"EdDSA", "jwk": {
        "kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.public_key().as_ref())
    }});
    let claims = serde_json::json!({"jti":"external-proof", "htm":"POST", "htu":"https://issuer.example/token", "iat":chrono::Utc::now().timestamp()});
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let proof = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).as_ref())
    );
    let store = ProofStore::default();
    let fixture = Fixture::new(Ok(None), Ok(None));
    let facts = DpopRequestFacts {
        method: http::Method::POST,
        path: "/token",
        proof: Ok(Some(&proof)),
        proof_present: true,
    };
    let validate = |facts| {
        block_on(validate_dpop_proof(
            &store,
            fixture.audit.as_ref(),
            "https://issuer.example/",
            "https://mtls.example/",
            DpopNoncePolicy::Optional,
            facts,
            None,
            None,
        ))
    };
    let thumbprint = validate(facts.clone())
        .unwrap()
        .expect("verified key binding");
    assert!(!thumbprint.is_empty());
    assert_eq!(
        *store.0.lock().unwrap(),
        [(thumbprint, "external-proof".into(), DPOP_REPLAY_TTL_SECONDS)]
    );
    assert!(matches!(
        validate(facts.clone()),
        Err(DpopError::ReplayDetected(_))
    ));
    let mut wrong_target = facts.clone();
    wrong_target.path = "/different";
    assert_eq!(validate(wrong_target), Err(DpopError::InvalidProof));
    let mut malformed = facts;
    malformed.proof = Err(DpopError::MalformedProof);
    assert_eq!(validate(malformed), Err(DpopError::MalformedProof));
    assert_eq!(
        store.0.lock().unwrap().len(),
        2,
        "rejected facts never consume replay state"
    );
}

struct DeliveryPorts {
    pending: Mutex<Option<CibaPingDelivery>>,
    sent: Mutex<Vec<String>>,
    finished: Mutex<Vec<(String, CibaPingFinishOutcome)>>,
    claims: Mutex<Vec<(i64, i64, usize)>>,
}
impl CibaPingDeliveryPort for DeliveryPorts {
    fn claim_due(
        &self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'_, Vec<CibaPingDelivery>> {
        Box::pin(async move {
            self.claims.lock().unwrap().push((now, lock_until, limit));
            Ok(self.pending.lock().unwrap().take().into_iter().collect())
        })
    }
    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            self.finished
                .lock()
                .unwrap()
                .push((delivery.auth_req_id_hash.clone(), outcome));
            Ok(CibaPingFinishResult::Applied)
        })
    }
}
impl CibaPingSender for DeliveryPorts {
    fn send<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    > {
        Box::pin(async move {
            assert_eq!(delivery.endpoint, "https://client.example/notify");
            assert_eq!(delivery.client_notification_token, "notification-token");
            assert_eq!(delivery.auth_req_id, "opaque-request");
            self.sent
                .lock()
                .unwrap()
                .push(delivery.auth_req_id_hash.clone());
            Ok(http::StatusCode::NO_CONTENT)
        })
    }
}

#[test]
fn oneshot_batch_delivers_records_result_and_returns_to_external_caller() {
    let ports = Arc::new(DeliveryPorts {
        pending: Mutex::new(Some(CibaPingDelivery {
            auth_req_id_hash: "request-hash".into(),
            auth_req_id: "opaque-request".into(),
            endpoint: "https://client.example/notify".into(),
            client_notification_token: "notification-token".into(),
            attempts: 1,
            expires_at: chrono::Utc::now().timestamp() + 60,
        })),
        sent: Mutex::new(vec![]),
        finished: Mutex::new(vec![]),
        claims: Mutex::new(vec![]),
    });
    let worker = CibaPingDeliveryWorker::new(ports.clone(), ports.clone());
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 1);
    assert_eq!(*ports.sent.lock().unwrap(), ["request-hash"]);
    assert_eq!(
        *ports.finished.lock().unwrap(),
        [("request-hash".into(), CibaPingFinishOutcome::Delivered)]
    );
    {
        let claims = ports.claims.lock().unwrap();
        assert_eq!(claims.len(), 1, "a batch must not schedule itself again");
        let (now, lock_until, limit) = claims[0];
        assert_eq!(lock_until - now, 15);
        assert_eq!(limit, 8);
    }
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 0);
    assert_eq!(ports.claims.lock().unwrap().len(), 2);
    assert_eq!(ports.finished.lock().unwrap().len(), 1);
}
