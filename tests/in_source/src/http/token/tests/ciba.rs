use super::*;

#[test]
fn ciba_request_key_hashes_auth_req_id() {
    let key = ciba_request_key("auth-req-id");

    assert!(key.starts_with("oauth:ciba:"));
    assert!(!key.contains("auth-req-id"));
    assert_eq!(key, ciba_request_key("auth-req-id"));
    assert_ne!(key, ciba_request_key("other"));
}

#[test]
fn ciba_status_serializes_as_protocol_state() {
    assert_eq!(
        serde_json::to_value(CibaStatus::Pending).unwrap(),
        json!("pending")
    );
}
