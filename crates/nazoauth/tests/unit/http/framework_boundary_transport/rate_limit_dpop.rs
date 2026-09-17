use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use actix_web::{
    http::{StatusCode, header},
    test::TestRequest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use nazo_auth::{
    DpopError, DpopNoncePolicy, DpopStateFuture, DpopStateStorePort, RequestRateLimitBucket,
    RequestRateLimitError, RequestRateLimitFuture, RequestRateLimitPort,
};
use nazo_http_actix::{ClientIpConfig, ClientIpHeaderMode};
use serde_json::json;

use super::ready_body_bytes;
use crate::http;

#[derive(Clone)]
struct RecordingRateLimiter {
    outcome: Result<u64, RequestRateLimitError>,
    calls: Arc<Mutex<Vec<(RequestRateLimitBucket, String, u64)>>>,
}

impl RequestRateLimitPort for RecordingRateLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((bucket, subject.to_owned(), window_seconds));
            self.outcome
        })
    }
}

#[actix_web::test]
async fn framework_boundary_transport_rate_limit_exact_wire_and_store_order() {
    let store = Arc::new(RecordingRateLimiter {
        outcome: Ok(3),
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let req = TestRequest::default()
        .peer_addr("203.0.113.77:443".parse().unwrap())
        .to_http_request();
    let response = http::rate_limit::enforce_auth_request_limit(
        &nazo_oauth_server::rate_limit::AuthRequestLimiter::new(store.clone(), 41, 2),
        &req,
        &ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
    .await
    .expect_err("third request must be rate limited");
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::Authentication,
            "203.0.113.77".to_owned(),
            41
        )]
    );
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "41");
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"temporarily_unavailable","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_rate_limit_store_failure_exact_wire_and_order() {
    let store = Arc::new(RecordingRateLimiter {
        outcome: Err(RequestRateLimitError),
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let req = TestRequest::default()
        .peer_addr("198.51.100.9:443".parse().unwrap())
        .to_http_request();
    let response = http::rate_limit::enforce_auth_request_limit(
        &nazo_oauth_server::rate_limit::AuthRequestLimiter::new(store.clone(), 60, 10),
        &req,
        &ClientIpConfig::new(&[], ClientIpHeaderMode::None),
    )
    .await
    .expect_err("store failure must fail closed");
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[(
            RequestRateLimitBucket::Authentication,
            "198.51.100.9".to_owned(),
            60
        )]
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get(header::RETRY_AFTER).is_none());
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"server_error","error_description":"Request failed."}"#
    );
}

#[actix_web::test]
async fn framework_boundary_transport_duplicate_dpop_header_has_exact_error_wire() {
    let req = TestRequest::default()
        .insert_header(("dpop", "first-proof"))
        .append_header(("dpop", "second-proof"))
        .to_http_request();
    let error = nazo_http_actix::dpop_proof_header(req.headers())
        .expect_err("duplicate DPoP proof headers must be rejected");
    let response = nazo_http_actix::dpop_error_response(
        error,
        nazo_oauth_server::contracts::request_facts::DpopErrorContext::TokenEndpoint,
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "DPoP error=\"invalid_dpop_proof\""
    );
    assert_eq!(
        ready_body_bytes(response).await,
        br#"{"error":"invalid_dpop_proof","error_description":"DPoP proof is malformed."}"#
    );
}

#[test]
fn framework_boundary_transport_empty_dpop_header_is_present_but_has_no_proof() {
    let req = TestRequest::default()
        .insert_header(("dpop", "   "))
        .to_http_request();
    assert!(nazo_http_actix::dpop_proof_present(req.headers()));
    assert_eq!(
        nazo_http_actix::dpop_proof_header(req.headers()).unwrap(),
        None
    );
}

fn signed_boundary_dpop_proof(
    htu: &str,
    nonce: Option<&str>,
    ath: Option<&str>,
    jti: &str,
) -> String {
    let key = SigningKey::from_bytes(&[7; 32]);
    let jwk = json!({"kty":"OKP", "crv":"Ed25519", "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())});
    let header = json!({"typ":"dpop+jwt", "alg":"EdDSA", "jwk":jwk});
    let mut claims =
        json!({"htm":"POST", "htu":htu, "iat":chrono::Utc::now().timestamp(), "jti":jti});
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[derive(Default)]
struct RecordingDpopState {
    calls: Mutex<Vec<String>>,
    nonces: Mutex<HashSet<String>>,
    replay: Mutex<HashSet<String>>,
}

impl DpopStateStorePort for RecordingDpopState {
    fn consume_replay<'a>(
        &'a self,
        jkt: &'a str,
        jti: &'a str,
        ttl_seconds: u64,
    ) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("replay:{jkt}:{jti}:{ttl_seconds}"));
            Ok(self.replay.lock().unwrap().insert(format!("{jkt}:{jti}")))
        })
    }
    fn issue_nonce<'a>(&'a self, nonce: &'a str, ttl_seconds: u64) -> DpopStateFuture<'a, ()> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("issue_nonce:{ttl_seconds}"));
            self.nonces.lock().unwrap().insert(nonce.to_owned());
            Ok(())
        })
    }
    fn validate_nonce<'a>(&'a self, nonce: &'a str) -> DpopStateFuture<'a, bool> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push(format!("validate_nonce:{nonce}"));
            Ok(self.nonces.lock().unwrap().contains(nonce))
        })
    }
}

#[actix_web::test]
async fn framework_boundary_transport_dpop_nonce_then_replay_store_order() {
    let store = RecordingDpopState::default();
    let proof_without_nonce =
        signed_boundary_dpop_proof("https://issuer.example/token", None, None, "stable-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", proof_without_nonce))
        .to_http_request();
    let first = nazo_oauth_server::security::dpop::validate_dpop_proof(
        &store,
        crate::http::authorization::test_support::test_security_audit(),
        "https://issuer.example",
        "https://mtls.example",
        DpopNoncePolicy::Required,
        http::dpop::dpop_request_facts(&req),
        None,
        None,
    )
    .await;
    let nonce = match first {
        Err(DpopError::UseNonce(nonce)) => nonce,
        other => panic!("expected nonce challenge, got {other:?}"),
    };
    assert_eq!(store.calls.lock().unwrap().len(), 1);
    assert!(store.calls.lock().unwrap()[0].starts_with("issue_nonce:"));
    let proof = signed_boundary_dpop_proof(
        "https://issuer.example/token",
        Some(&nonce),
        None,
        "stable-jti",
    );
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", proof))
        .to_http_request();
    assert!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Required,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await
        .unwrap()
        .is_some()
    );
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Required,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await,
        Err(DpopError::ReplayDetected(_))
    ));
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[1], format!("validate_nonce:{nonce}"));
    assert!(calls[2].contains(":stable-jti:"));
    assert_eq!(calls[3], format!("validate_nonce:{nonce}"));
    assert_eq!(calls[4], calls[2]);
}

#[actix_web::test]
async fn framework_boundary_transport_dpop_ath_and_htu_fail_before_state_port() {
    let store = RecordingDpopState::default();
    let wrong_htu =
        signed_boundary_dpop_proof("https://attacker.example/token", None, None, "htu-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", wrong_htu))
        .to_http_request();
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Optional,
            http::dpop::dpop_request_facts(&req),
            None,
            None
        )
        .await,
        Err(DpopError::InvalidProof)
    ));
    let missing_ath =
        signed_boundary_dpop_proof("https://issuer.example/token", None, None, "ath-jti");
    let req = TestRequest::post()
        .uri("/token")
        .insert_header(("dpop", missing_ath))
        .to_http_request();
    assert!(matches!(
        nazo_oauth_server::security::dpop::validate_dpop_proof(
            &store,
            crate::http::authorization::test_support::test_security_audit(),
            "https://issuer.example",
            "https://mtls.example",
            DpopNoncePolicy::Optional,
            http::dpop::dpop_request_facts(&req),
            Some("access-token"),
            None
        )
        .await,
        Err(DpopError::InvalidProof)
    ));
    assert!(store.calls.lock().unwrap().is_empty());
}
