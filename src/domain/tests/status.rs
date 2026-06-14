use super::*;

#[test]
fn access_request_status_codes_are_stable_database_contract() {
    assert_eq!(AccessRequestStatus::Pending.code(), 0);
    assert_eq!(AccessRequestStatus::Approved.code(), 1);
    assert_eq!(AccessRequestStatus::Rejected.code(), 2);
}

#[test]
fn access_request_status_rejects_unknown_database_codes() {
    for (raw, expected) in [
        (0, Some(AccessRequestStatus::Pending.code())),
        (1, Some(AccessRequestStatus::Approved.code())),
        (2, Some(AccessRequestStatus::Rejected.code())),
        (-1, None),
        (3, None),
        (i16::MAX, None),
    ] {
        assert_eq!(
            AccessRequestStatus::from_code(raw).map(AccessRequestStatus::code),
            expected,
            "unexpected access-request status mapping for {raw}"
        );
    }
}
