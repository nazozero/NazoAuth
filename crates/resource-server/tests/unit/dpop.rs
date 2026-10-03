use super::*;
use jsonwebtoken::Algorithm;

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

    verifier.check_replay("key", "later", 100).unwrap();
    verifier.check_replay("key", "earlier", 90).unwrap();
    assert_eq!(
        verifier.check_replay("key", "earlier", 99),
        Err(DpopProofVerifierError::ReplayDetected)
    );
    assert_eq!(
        verifier.check_replay("key", "third", 99),
        Err(DpopProofVerifierError::ReplayCacheFull)
    );

    // The second insertion expires first, at the exact old retain boundary.
    verifier.check_replay("key", "third", 100).unwrap();
    assert_eq!(
        verifier.check_replay("key", "later", 100),
        Err(DpopProofVerifierError::ReplayDetected)
    );
    assert_eq!(
        verifier.check_replay("key", "earlier", 100),
        Err(DpopProofVerifierError::ReplayCacheFull)
    );
    verifier.check_replay("key", "later", 110).unwrap();
    verifier.check_replay("key", "third", 110).unwrap();
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
                verifier.check_replay("key", "shared", 100)
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
    verifier.check_replay("holder", "same-jti", 100).unwrap();
}
