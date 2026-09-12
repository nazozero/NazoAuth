use super::production::same_key_generation;
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
