use super::*;
use nazo_identity::scim::{SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN};

#[test]
fn scim_cursor_protection_round_trips_and_rejects_tampering_or_truncation() {
    let protector = ServerScimCursorProtector::new("cursor-pepper")
        .expect("cursor protector should derive a key");
    let plaintext = b"tenant=system;actor=token-1;offset=20";
    let protected = protector
        .protect(plaintext)
        .expect("cursor should be encrypted");

    assert!(protected.len() > SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN);
    assert_eq!(
        protector
            .unprotect(&protected)
            .expect("cursor should decrypt"),
        plaintext
    );

    let mut tampered = protected.clone();
    tampered[SCIM_CURSOR_NONCE_LEN] ^= 1;
    assert!(protector.unprotect(&tampered).is_err());
    assert!(
        protector
            .unprotect(&[0; SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN])
            .is_err()
    );
}
