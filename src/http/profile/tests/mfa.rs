use super::*;
use chrono::Duration;

#[test]
fn protected_mfa_request_requires_code() {
    let payload = serde_json::from_value::<MfaProtectedRequest>(json!({"code": "123456"}));

    assert!(payload.is_ok());
}

#[test]
fn remembered_mfa_cookie_ttl_is_bounded_to_thirty_days() {
    assert_eq!(
        Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64).num_days(),
        30
    );
}
