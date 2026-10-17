//! Pure-logic pins for the controller registry storage boundary (D01/D02).
//! Database-backed invariant and race tests live in `tests/controller_registry.rs`.

use super::{
    ControllerSlotStatus, NewControllerSlot, RotateControllerKey, lowest_free_slot_index,
    parse_slot_status, validate_kid,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

const CANONICAL_V7: &str = "018f6a52-3b7c-7cc9-9f2a-4f5a6b7c8d90";

fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

#[test]
fn kid_shape_must_be_unpadded_base64url_sha256_length() {
    assert!(validate_kid(&kid_of(&[7u8; 32])).is_ok());
    assert!(validate_kid("").is_err());
    assert!(validate_kid(&"a".repeat(42)).is_err());
    assert!(validate_kid(&"a".repeat(44)).is_err());
    // '+' and '/' belong to padded standard base64, never to this alphabet.
    let mut padded = kid_of(&[9u8; 32]).into_bytes();
    padded[0] = b'+';
    assert!(validate_kid(std::str::from_utf8(&padded).unwrap()).is_err());
}

#[test]
fn slot_index_selection_fills_lowest_free_and_stops_at_three() {
    let slots = |indices: &[i16]| -> Vec<super::StoredControllerSlot> {
        indices
            .iter()
            .map(|index| super::StoredControllerSlot {
                deployment_id: "d".to_owned(),
                controller_id: CANONICAL_V7.to_owned(),
                label: "l".to_owned(),
                kid: kid_of(&[0u8; 32]),
                public_key: vec![0u8; 32],
                slot_index: *index,
                issued_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now(),
                status: ControllerSlotStatus::Active,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .collect()
    };
    assert_eq!(lowest_free_slot_index(&[]), Some(0));
    assert_eq!(lowest_free_slot_index(&slots(&[0])), Some(1));
    assert_eq!(lowest_free_slot_index(&slots(&[0, 1])), Some(2));
    assert_eq!(lowest_free_slot_index(&slots(&[2])), Some(0));
    assert_eq!(lowest_free_slot_index(&slots(&[0, 2])), Some(1));
    // Revoked rows are filtered out before this point by the SQL predicate;
    // three active rows exhaust the index space.
    assert_eq!(lowest_free_slot_index(&slots(&[0, 1, 2])), None);
}

#[test]
fn status_catalog_is_closed() {
    assert_eq!(
        parse_slot_status("active"),
        Some(ControllerSlotStatus::Active)
    );
    assert_eq!(
        parse_slot_status("revoked"),
        Some(ControllerSlotStatus::Revoked)
    );
    assert_eq!(parse_slot_status("expired"), None);
    assert_eq!(parse_slot_status(""), None);
}

#[test]
fn summary_never_carries_public_key_bytes() {
    let slot = super::StoredControllerSlot {
        deployment_id: "dep".to_owned(),
        controller_id: CANONICAL_V7.to_owned(),
        label: "primary".to_owned(),
        kid: kid_of(&[11u8; 32]),
        public_key: vec![11u8; 32],
        slot_index: 0,
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now(),
        status: ControllerSlotStatus::Active,
        revoked_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let summary = slot.summary();
    let rendered = format!("{summary:?}");
    assert!(!rendered.contains("public_key"));
    assert_eq!(summary.kid, slot.kid);
    assert_eq!(summary.controller_id, slot.controller_id);
}

// Compile-time shape pin: private keys are not representable in write inputs
// because they carry exactly 32 public-key bytes.
const _: fn([u8; 32]) -> () = |_| ();

#[allow(dead_code)]
fn write_input_shapes(
    slot: NewControllerSlot,
    rotate: RotateControllerKey,
) -> ([u8; 32], [u8; 32]) {
    (slot.public_key, rotate.public_key)
}
