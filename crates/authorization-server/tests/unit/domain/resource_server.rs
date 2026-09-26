use super::production::{same_key_generation, within_verification_cache_window};
use std::sync::Arc;

#[test]
fn verifier_cache_hits_only_the_same_live_snapshot_generation() {
    let original_manager =
        nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let original = original_manager.snapshot();
    let same_generation = original_manager.snapshot();
    assert!(same_key_generation(&original, &same_generation));

    // Test managers intentionally reuse the same public kid. Distinct
    // key material must still be treated as a rotation and miss.
    let rotated =
        nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA).snapshot();
    assert_eq!(original.active_kid, rotated.active_kid);
    assert!(!Arc::ptr_eq(&original, &rotated));
    assert_ne!(original.jwks(), rotated.jwks());
    assert!(!same_key_generation(&original, &rotated));
}

#[test]
fn verifier_cache_expires_at_retirement_even_without_a_new_generation() {
    let captured = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let deadline = captured + chrono::Duration::seconds(60);
    assert!(within_verification_cache_window(
        captured,
        Some(deadline),
        deadline - chrono::Duration::nanoseconds(1),
    ));
    assert!(!within_verification_cache_window(
        captured,
        Some(deadline),
        deadline
    ));
    assert!(!within_verification_cache_window(
        captured,
        Some(deadline),
        deadline + chrono::Duration::seconds(1),
    ));
}

#[test]
fn verifier_cache_rebuilds_after_clock_rollback_with_or_without_a_future_retirement() {
    let captured = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let rolled_back = captured - chrono::Duration::nanoseconds(1);
    for deadline in [None, Some(captured + chrono::Duration::seconds(60))] {
        assert!(!within_verification_cache_window(
            captured,
            deadline,
            rolled_back
        ));
        assert!(within_verification_cache_window(
            captured, deadline, captured
        ));
    }
}
