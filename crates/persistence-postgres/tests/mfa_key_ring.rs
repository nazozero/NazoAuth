#[test]
fn totp_key_ring_requires_distinct_non_empty_versioned_keys() {
    use nazo_postgres::{MfaTotpKey, MfaTotpKeyError, MfaTotpKeyRing};

    assert!(matches!(
        MfaTotpKey::new("", [0; 32]),
        Err(MfaTotpKeyError::EmptyId)
    ));
    assert_eq!(
        MfaTotpKeyError::EmptyId.to_string(),
        "MFA TOTP encryption key id must not be empty"
    );
    let current = MfaTotpKey::new("current", [1; 32]).expect("current key is valid");
    let previous = MfaTotpKey::new("current", [2; 32]).expect("previous key material is valid");
    assert!(matches!(
        MfaTotpKeyRing::new(current, Some(previous)),
        Err(MfaTotpKeyError::DuplicateId)
    ));

    let too_long = "k".repeat(129);
    assert!(matches!(
        MfaTotpKey::new(too_long, [0; 32]),
        Err(MfaTotpKeyError::IdTooLong)
    ));
    assert_eq!(
        MfaTotpKeyError::IdTooLong.to_string(),
        "MFA TOTP encryption key id must be at most 128 bytes"
    );

    let current = MfaTotpKey::new("current", [1; 32]).expect("current key is valid");
    let previous = MfaTotpKey::new("previous", [2; 32]).expect("previous key is valid");
    let ring = MfaTotpKeyRing::new(current, Some(previous)).expect("distinct key ids");
    assert_eq!(
        MfaTotpKeyError::DuplicateId.to_string(),
        "MFA TOTP current and previous key ids must differ"
    );
    assert_eq!(ring.current().id(), "current");
    assert_eq!(ring.current().key(), &[1; 32]);
    assert_eq!(ring.previous().expect("previous key").id(), "previous");
    assert_eq!(ring.previous().expect("previous key").key(), &[2; 32]);
}
