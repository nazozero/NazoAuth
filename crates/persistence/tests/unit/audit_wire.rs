use super::*;
#[test]
fn escaped_payload_counts_match_final_json_and_maximum_singleton_bound() {
    for payload in [
        "plain".to_owned(),
        "\\\"\n\t".repeat(5_000),
        "雪".repeat(10_000),
    ] {
        let event = SecurityAuditPendingDelivery {
            event_id: uuid::Uuid::now_v7(),
            sequence: 999_999,
            event_type: "event\"name".into(),
            event_category: "security".into(),
            payload_canonical: serde_json::json!({"value":payload}).to_string(),
            occurred_at: chrono::Utc::now(),
            previous_hash: vec![1; 32],
            event_hash: vec![2; 32],
        };
        let count = security_audit_event_wire_length(&event).unwrap();
        let mut second = event.clone();
        second.sequence += 1;
        let batch = SecurityAuditBatch {
            generation: 1,
            first_sequence: event.sequence,
            last_sequence: second.sequence,
            previous_hash: event.previous_hash.clone(),
            last_hash: second.event_hash.clone(),
            digest: vec![3; 32],
            attempts: 0,
            deliveries: vec![event, second],
        };
        let expected = security_audit_empty_envelope_wire_length(
            "deployment\"name",
            &batch.deliveries[0],
            &batch.deliveries[1],
            2,
        )
        .unwrap()
            + count
            + security_audit_event_wire_length(&batch.deliveries[1]).unwrap()
            + 1;
        assert_eq!(
            security_audit_batch_body("deployment\"name", &batch)
                .unwrap()
                .len(),
            expected
        );
    }
    let event = SecurityAuditPendingDelivery {
        event_id: uuid::Uuid::now_v7(),
        sequence: i64::MAX,
        event_type: "e".repeat(128),
        event_category: "c".repeat(64),
        payload_canonical: "\\".repeat(crate::MAX_SECURITY_AUDIT_PAYLOAD_BYTES),
        occurred_at: chrono::Utc::now(),
        previous_hash: vec![1; 32],
        event_hash: vec![2; 32],
    };
    let bytes = security_audit_empty_envelope_wire_length(&"d".repeat(128), &event, &event, 1)
        .unwrap()
        + security_audit_event_wire_length(&event).unwrap();
    assert!(bytes <= MAX_SECURITY_AUDIT_SINGLETON_ENVELOPE_BYTES);
}

#[test]
fn shared_encoder_matches_frozen_legacy_anchor_v2_wire_bytes() {
    // Frozen from the legacy envelope's declared field order and wire types,
    // independently of both shared sizing and encoding helpers.
    let event = SecurityAuditPendingDelivery {
        event_id: uuid::Uuid::from_u128(0xb1),
        sequence: 1,
        event_type: "test_event".to_owned(),
        event_category: "security".to_owned(),
        payload_canonical: r#"{"text":"snow 雪"}"#.to_owned(),
        occurred_at: "2026-10-01T00:00:00Z".parse().unwrap(),
        previous_hash: vec![1; 32],
        event_hash: vec![2; 32],
    };
    let batch = SecurityAuditBatch {
        generation: 1,
        first_sequence: 1,
        last_sequence: 1,
        previous_hash: vec![1; 32],
        last_hash: vec![2; 32],
        digest: vec![3; 32],
        attempts: 0,
        deliveries: vec![event],
    };
    let frozen = include_bytes!("../fixtures/audit-anchor-v2-legacy-wire.json");
    assert_eq!(
        security_audit_batch_body("frozen-deployment", &batch)
            .unwrap()
            .as_slice(),
        frozen
    );
}
