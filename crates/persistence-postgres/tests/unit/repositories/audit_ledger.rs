use super::*;
use nazo_persistence::audit_chain::security_audit_event_hash;
use serde_json::Value;

fn event(payload: Value) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload,
        occurred_at: Utc::now(),
    }
}

#[test]
fn audit_hash_is_domain_separated_and_chain_ordered() {
    let first = event(serde_json::json!({"subject_hash": "a"}));
    let first_payload = serde_json::to_vec(&first.payload).unwrap();
    let first_hash = security_audit_event_hash(
        1,
        &[0; 32],
        first.event_id,
        &first.event_type,
        &first.event_category,
        first.occurred_at,
        &first_payload,
    );

    let second = event(serde_json::json!({"subject_hash": "a"}));
    let second_payload = serde_json::to_vec(&second.payload).unwrap();
    let second_hash = security_audit_event_hash(
        2,
        &first_hash,
        second.event_id,
        &second.event_type,
        &second.event_category,
        second.occurred_at,
        &second_payload,
    );

    assert_ne!(first_hash, second_hash);
    assert_ne!(
        first_hash,
        security_audit_event_hash(
            1,
            &[0; 32],
            second.event_id,
            &second.event_type,
            &second.event_category,
            second.occurred_at,
            &second_payload,
        )
    );
}

#[test]
fn audit_event_validation_rejects_non_object_and_invalid_names() {
    let mut invalid = event(Value::String("not-an-object".to_owned()));
    assert!(validate_event(&invalid).is_err());
    invalid.payload = serde_json::json!({});
    invalid.event_type = "TokenIssued".to_owned();
    assert!(validate_event(&invalid).is_err());
}

#[test]
fn generic_audit_append_rejects_reserved_authorization_authority() {
    let mut reserved = event(serde_json::json!({}));
    reserved.event_type = "authorization_decision_committed".to_owned();
    assert!(validate_event_for_transaction(&reserved).is_err());
}

#[test]
fn payload_byte_count_matches_compact_json_and_exact_limit() {
    for payload in [
        serde_json::json!({}),
        serde_json::json!({"escaped": "\\\"\n\t", "unicode": "签名😀"}),
        serde_json::json!({"nested": [{"b": null, "a": [true, -17, 2.5]}, []]}),
    ] {
        let mut count = PayloadByteCount::default();
        serde_json::to_writer(&mut count, &payload).unwrap();
        assert_eq!(count.0, serde_json::to_vec(&payload).unwrap().len());
        assert!(validate_payload_size(&event(payload)).is_ok());
    }
    let empty_size = serde_json::to_vec(&serde_json::json!({"body": ""}))
        .unwrap()
        .len();
    for extra in [0, 1] {
        let payload = serde_json::json!({
            "body": "x".repeat(MAX_SECURITY_AUDIT_PAYLOAD_BYTES - empty_size + extra),
        });
        let mut count = PayloadByteCount::default();
        serde_json::to_writer(&mut count, &payload).unwrap();
        assert_eq!(count.0, MAX_SECURITY_AUDIT_PAYLOAD_BYTES + extra);
        assert_eq!(validate_payload_size(&event(payload)).is_ok(), extra == 0);
    }
}

#[test]
fn completed_single_mutation_preserves_insert_and_idempotent_replay_results() {
    assert!(single_audit_mutation(vec![AuditMutationRow { changed: true }]).unwrap());
    assert!(!single_audit_mutation(vec![AuditMutationRow { changed: false }]).unwrap());
}

#[test]
fn completed_single_mutation_rejects_missing_or_extra_rows() {
    assert!(single_audit_mutation(Vec::new()).is_err());
    assert!(
        single_audit_mutation(vec![
            AuditMutationRow { changed: true },
            AuditMutationRow { changed: false },
        ])
        .is_err()
    );
}
