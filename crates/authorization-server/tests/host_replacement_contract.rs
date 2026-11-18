//! An external consumer exercises public application boundaries using semantic ports.
use futures_executor::block_on;
use nazo_oauth_server as app;
#[path = "support/authorization.rs"]
mod authorization_fixture;
#[path = "support/token_ports.rs"]
mod token_ports;
use app::{
    authorization::AuthorizationRequestFacts,
    contracts::{oauth_error::OAuthEndpointError, request_facts::DpopRequestFacts},
    ports::transient_state::{
        CibaPingClaimBatch, CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome,
        CibaPingFinishResult, TransientStateFuture,
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

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
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

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn security_facts_validate_signature_target_and_replay_without_host_state() {
    let key = nazo_crypto::ed25519::SigningKey::from_bytes(&[7; 32]);
    let header = serde_json::json!({"typ":"dpop+jwt", "alg":"EdDSA", "jwk": {
        "kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
    }});
    let claims = serde_json::json!({"jti":"external-proof", "htm":"POST", "htu":"https://issuer.example/token", "iat":jiff::Timestamp::now().as_second()});
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let proof = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()))
    );
    let store = ProofStore::default();
    let fixture = Fixture::new(Ok(None), Ok(None));
    let facts = DpopRequestFacts {
        method: http::Method::POST,
        path: "/token",
        authority: Some("issuer.example"),
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
    let mut other_endpoint = facts.clone();
    other_endpoint.authority = Some("mtls.example");
    assert_eq!(validate(other_endpoint), Err(DpopError::InvalidProof));
    assert!(
        store.0.lock().unwrap().is_empty(),
        "wrong alias must not consume proof"
    );
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
    ) -> TransientStateFuture<'_, CibaPingClaimBatch> {
        Box::pin(async move {
            self.claims.lock().unwrap().push((now, lock_until, limit));
            let deliveries: Vec<_> = self.pending.lock().unwrap().take().into_iter().collect();
            Ok(CibaPingClaimBatch {
                scanned: deliveries.len(),
                deliveries,
            })
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

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn oneshot_batch_delivers_records_result_and_returns_to_external_caller() {
    let ports = Arc::new(DeliveryPorts {
        pending: Mutex::new(Some(CibaPingDelivery {
            auth_req_id_hash: "request-hash".into(),
            auth_req_id: "opaque-request".into(),
            endpoint: "https://client.example/notify".into(),
            client_notification_token: "notification-token".into(),
            attempts: 1,
            expires_at: jiff::Timestamp::now().as_second() + 60,
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

#[cfg_attr(
    all(target_arch = "wasm32", target_os = "unknown"),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn token_signing_and_userinfo_execute_through_semantic_ports() {
    use app::{
        contracts::userinfo::{
            AccessTokenAuthScheme, UserinfoError, UserinfoOperations, UserinfoRepresentation,
            UserinfoRequestFacts,
        },
        domain::userinfo::{ServerUserinfoOperations, UserinfoConfig, UserinfoHandles},
    };
    use nazo_auth::{AccessTokenSignInput, AppliedSenderConstraint};

    block_on(async {
        let registered = client(true);
        let tenant = registered.tenant_id;
        let user_id = uuid::Uuid::from_u128(10);
        let subject = user_id.to_string();
        let fixture = Fixture::new(Ok(Some(registered.clone())), Ok(None));
        let claims = serde_json::from_value::<nazo_identity::SubjectClaims>(serde_json::json!({
            "subject": user_id,
            "preferred_username": "alice",
            "email": "alice@example.test",
            "email_verified": true,
            "phone_number_verified": false,
            "updated_at": jiff::Timestamp::now().as_second(),
        }))
        .unwrap();
        let service = Arc::new(token_ports::userinfo_service(
            fixture.keys.clone(),
            registered.clone(),
            claims.clone(),
            false,
        ));
        let issued = service
            .sign_access_token(AccessTokenSignInput {
                signing_algorithm: Some("EdDSA"),
                authorization_id: Some(uuid::Uuid::now_v7()),
                client_epoch: Some(0),
                user_epoch: Some(0),
                issuer: "https://issuer.example",
                tenant_id: tenant,
                subject: &subject,
                user_id: Some(user_id),
                subject_type: "user",
                client_id: &registered.client_id,
                audiences: &["https://issuer.example/userinfo".into()],
                scopes: &["openid".into(), "email".into()],
                authorization_details: &serde_json::json!([]),
                userinfo_claim_requests: &[],
                ttl_seconds: 300,
                sender_constraint: AppliedSenderConstraint::Bearer,
                actor: None,
            })
            .await
            .unwrap();
        let decoded = service
            .decode_access_token("https://issuer.example", &issued.token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded.sub, subject);
        assert_eq!(decoded.jti, issued.jti);
        assert_eq!(decoded.exp, issued.expires_at);
        assert_eq!(decoded.tenant_id, tenant.to_string());

        let handles = UserinfoHandles::new(
            Arc::new(ProofStore::default()),
            fixture.audit.clone(),
            fixture.keys.clone(),
            UserinfoConfig::new(
                "https://issuer.example",
                "https://resource.example",
                "https://mtls.example",
                DpopNoncePolicy::Optional,
                false,
            ),
            fixture.remote_client_documents.clone(),
        );
        let operation = ServerUserinfoOperations::new(service.clone(), handles.clone());
        let prepared = operation
            .prepare(AccessTokenAuthScheme::Bearer, issued.token.clone())
            .await
            .unwrap();
        let result = operation
            .userinfo(
                prepared,
                UserinfoRequestFacts {
                    dpop: DpopRequestFacts {
                        method: http::Method::GET,
                        path: "/userinfo",
                        authority: Some("issuer.example"),
                        proof: Ok(None),
                        proof_present: false,
                    },
                    mtls_thumbprint: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.dpop_nonce, None);
        assert_eq!(
            result.representation,
            UserinfoRepresentation::Claims(serde_json::json!({
                "sub": subject,
                "email": "alice@example.test",
                "email_verified": true,
            })),
        );

        let mut parts = issued.token.split('.');
        let header = parts.next().unwrap();
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap())
                .unwrap();
        tampered["sub"] = serde_json::json!("another-subject");
        let signature = parts.next().unwrap();
        let tampered = format!(
            "{header}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap()),
        );
        assert!(matches!(
            operation
                .prepare(AccessTokenAuthScheme::Bearer, tampered)
                .await,
            Err(UserinfoError::InvalidAccessToken),
        ));

        let revoked_service = Arc::new(token_ports::userinfo_service(
            fixture.keys,
            registered,
            claims,
            true,
        ));
        let revoked = ServerUserinfoOperations::new(revoked_service, handles);
        assert!(matches!(
            revoked
                .prepare(AccessTokenAuthScheme::Bearer, issued.token)
                .await,
            Err(UserinfoError::RevokedAccessToken),
        ));
    });
}
