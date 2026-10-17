use super::*;

#[test]
fn wire_record_borrows_session_fields_and_preserves_persisted_bytes() {
    let mut record = SessionRecord::new(
        UserId::new(Uuid::from_u128(1)).unwrap(),
        1_000,
        vec!["password".to_owned(), "otp".to_owned()],
        false,
        Some("oidc-sid".to_owned()),
    );
    record.add_logged_in_client("rp-a");
    let wire = SessionWireRecord::from(&record);
    assert!(matches!(wire.amr, Cow::Borrowed(_)));
    assert!(matches!(wire.oidc_sid, Some(Cow::Borrowed(_))));
    assert!(matches!(wire.logged_in_client_ids, Cow::Borrowed(_)));
    let raw = serde_json::to_string(&wire).unwrap();
    assert_eq!(
        raw,
        r#"{"user_id":"00000000-0000-0000-0000-000000000001","auth_time":1000,"amr":["password","otp"],"pending_mfa":false,"oidc_sid":"oidc-sid","logged_in_client_ids":["rp-a"]}"#
    );
    let decoded: SessionWireRecord = serde_json::from_str(&raw).unwrap();
    assert_eq!(SessionRecord::try_from(decoded).unwrap(), record);
}

#[test]
fn decoded_session_moves_owned_client_ids_and_preserves_first_occurrence_order() {
    let raw = r#"{"user_id":"00000000-0000-0000-0000-000000000001","auth_time":1000,"amr":["password"],"pending_mfa":false,"logged_in_client_ids":["rp-b","rp-a","rp-b"]}"#;
    let decoded: SessionWireRecord = serde_json::from_str(raw).unwrap();
    let first_allocation = decoded.logged_in_client_ids[0].as_ptr();
    let second_allocation = decoded.logged_in_client_ids[1].as_ptr();
    let record = SessionRecord::try_from(decoded).unwrap();
    assert_eq!(record.logged_in_client_ids(), ["rp-b", "rp-a"]);
    assert_eq!(record.logged_in_client_ids()[0].as_ptr(), first_allocation);
    assert_eq!(record.logged_in_client_ids()[1].as_ptr(), second_allocation);
}
