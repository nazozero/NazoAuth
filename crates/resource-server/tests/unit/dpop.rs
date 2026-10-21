use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use jsonwebtoken::Algorithm;
use serde_json::json;

fn signed_proof(iat: i64, critical: Option<Value>) -> String {
    let key = SigningKey::from_bytes(&[42; 32]);
    let mut header = json!({
        "typ": "dpop+jwt", "alg": "EdDSA",
        "jwk": {"kty": "OKP", "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())}
    });
    if let Some(critical) = critical {
        header["crit"] = critical;
        header["unknown"] = json!(true);
    }
    let claims = json!({
        "htm": "GET", "htu": "https://resource.example/userinfo",
        "iat": iat, "jti": "replay", "ath": access_token_hash("token")
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

#[test]
fn future_dated_proof_stays_reserved_through_its_last_valid_second() {
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig {
        max_age_seconds: 10,
        clock_skew_seconds: 5,
        ..DpopProofVerifierConfig::default()
    });
    let proof = signed_proof(105, None);
    let verify = |now| {
        verifier.verify_at(
            &proof,
            "GET",
            "https://resource.example/userinfo",
            "token",
            now,
        )
    };
    assert!(verify(100).is_ok());
    for now in [100, 115, 120] {
        assert_eq!(verify(now), Err(DpopProofVerifierError::ReplayDetected));
    }
    assert_eq!(verify(121), Err(DpopProofVerifierError::Expired));
}

#[test]
fn signed_dpop_rejects_critical_headers_even_when_empty_or_null() {
    for critical in [json!(["unknown"]), json!([]), Value::Null] {
        let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
        assert_eq!(
            verifier.verify_at(
                &signed_proof(100, Some(critical)),
                "GET",
                "https://resource.example/userinfo",
                "token",
                100
            ),
            Err(DpopProofVerifierError::MalformedProof)
        );
    }
}

#[test]
fn supported_dpop_algorithm_rejects_unsupported_algs() {
    assert!(supported_dpop_algorithm(Algorithm::HS256).is_none());
    assert!(supported_dpop_algorithm(Algorithm::ES384).is_none());
    assert!(supported_dpop_algorithm(Algorithm::RS384).is_none());
}

#[test]
fn replay_cache_expires_only_due_entries_after_clock_rollback() {
    let verifier = DpopProofVerifier::new_with_replay_cache_limit(
        DpopProofVerifierConfig {
            max_age_seconds: 10,
            clock_skew_seconds: 0,
            ..DpopProofVerifierConfig::default()
        },
        2,
    );

    verifier.check_replay("key", "later", 100, 110).unwrap();
    verifier.check_replay("key", "earlier", 90, 100).unwrap();
    assert_eq!(
        verifier.check_replay("key", "earlier", 99, 109),
        Err(DpopProofVerifierError::ReplayDetected)
    );
    assert_eq!(
        verifier.check_replay("key", "third", 99, 109),
        Err(DpopProofVerifierError::ReplayCacheFull)
    );

    // The second insertion expires first, at the exact old retain boundary.
    verifier.check_replay("key", "third", 100, 110).unwrap();
    assert_eq!(
        verifier.check_replay("key", "later", 100, 110),
        Err(DpopProofVerifierError::ReplayDetected)
    );
    assert_eq!(
        verifier.check_replay("key", "earlier", 100, 110),
        Err(DpopProofVerifierError::ReplayCacheFull)
    );
    verifier.check_replay("key", "later", 110, 120).unwrap();
    verifier.check_replay("key", "third", 110, 120).unwrap();
    let cache = verifier.replay_cache.lock().unwrap();
    assert_eq!(cache.keys.len(), 2);
    assert_eq!(cache.expirations.len(), 1);
}

#[test]
fn cloned_replay_verifiers_have_one_atomic_winner() {
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let verifier = verifier.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                verifier.check_replay("key", "shared", 100, 110)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(DpopProofVerifierError::ReplayDetected))
            .count(),
        1
    );
}

#[test]
fn proof_http_method_is_case_sensitive_before_replay_reservation() {
    let verifier = DpopProofVerifier::new(DpopProofVerifierConfig::default());
    let mut claims = DpopProofClaims {
        htm: "get".to_owned(),
        htu: "https://resource.example/userinfo".to_owned(),
        iat: 100,
        jti: "same-jti".to_owned(),
        ath: Some(access_token_hash("token")),
        nonce: None,
    };
    assert_eq!(
        verifier.validate_claims(
            &claims,
            "GET",
            &["https://resource.example/userinfo"],
            "token",
            100
        ),
        Err(DpopProofVerifierError::MethodMismatch)
    );
    assert!(verifier.replay_cache.lock().unwrap().keys.is_empty());
    claims.htm = "GET".to_owned();
    assert!(
        verifier
            .validate_claims(
                &claims,
                "GET",
                &["https://resource.example/userinfo"],
                "token",
                100
            )
            .is_ok()
    );
    verifier
        .check_replay("holder", "same-jti", 100, 110)
        .unwrap();
}
