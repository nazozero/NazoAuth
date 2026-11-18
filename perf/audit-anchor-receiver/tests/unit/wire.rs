use super::*;

#[test]
fn signing_seed_accepts_both_encodings_and_rejects_wrong_lengths() {
    let seed = [0xabu8; 32];
    for value in [
        "ab".repeat(32),
        "AB".repeat(32),
        URL_SAFE_NO_PAD.encode(seed),
    ] {
        assert_eq!(parse_signing_key(&value).unwrap().to_bytes(), seed);
    }
    for value in [
        "ab".repeat(31),
        "ab".repeat(33),
        URL_SAFE_NO_PAD.encode([0u8; 31]),
    ] {
        assert!(parse_signing_key(&value).is_err());
    }
}

#[test]
fn event_hash_retains_floor_rounded_microseconds_on_both_sides_of_epoch() {
    let hash = |at| event_hash(1, &[0; 32], Uuid::nil(), "event", "security", at, b"{}");
    for (nanos, micros) in [
        (-1001, -2),
        (-1000, -1),
        (-999, -1),
        (-1, -1),
        (0, 0),
        (1, 0),
        (999, 0),
        (1000, 1),
        (1001, 1),
    ] {
        assert_eq!(
            hash(Timestamp::from_nanosecond(nanos).unwrap()),
            hash(Timestamp::from_microsecond(micros).unwrap())
        );
    }
    assert_ne!(
        hash(Timestamp::UNIX_EPOCH),
        hash(Timestamp::from_microsecond(-1).unwrap())
    );
}

#[test]
fn receipt_signatures_match_frozen_pre_migration_bytes() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let last_hash = encode_hash(&[2; 32]);
    let digest = encode_hash(&[3; 32]);
    for (input, canonical) in [
        ("2026-11-17T00:00:00Z", "2026-11-17T00:00:00Z"),
        ("2026-11-17T00:00:00.1Z", "2026-11-17T00:00:00.100Z"),
        ("2026-11-17T00:00:00.1234Z", "2026-11-17T00:00:00.123400Z"),
        (
            "2026-11-17T00:00:00.1234567Z",
            "2026-11-17T00:00:00.123456700Z",
        ),
        (
            "1969-12-31T23:59:59.999999999Z",
            "1969-12-31T23:59:59.999999999Z",
        ),
        ("2026-11-17T01:00:00.12+01:00", "2026-11-17T00:00:00.120Z"),
    ] {
        let mut receipt = receipt_for(
            "batch",
            "accepted",
            "deployment-1",
            1,
            1,
            1,
            &last_hash,
            &digest,
            None,
            false,
        );
        receipt.received_at = input.parse().unwrap();
        let body = sign_receipt(receipt, &key).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["received_at"],
            canonical
        );
        let receipt: AnchorReceipt = serde_json::from_slice(&body).unwrap();
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(receipt.signature)
            .unwrap()
            .try_into()
            .unwrap();
        let frozen = format!(
            r#"{{"schema_version":"nazo.audit.anchor.receipt.v1","checkpoint_kind":"batch","status":"accepted","deployment_id":"deployment-1","first_sequence":1,"last_sequence":1,"event_count":1,"last_hash":"{}","batch_digest":"{}","received_at":"{}","reject_reason":null,"permanent":false}}"#,
            last_hash, digest, canonical,
        );
        key.verifying_key()
            .verify_strict(
                frozen.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();
    }
}
