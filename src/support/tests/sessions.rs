use super::*;

#[test]
fn session_payload_requires_authentication_metadata_and_oidc_sid() {
    let valid = SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        pending_mfa: false,
        oidc_sid: Some("sid-1".to_owned()),
    };

    assert!(valid_session_payload(&valid, 1_001));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: None,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: Some(" ".to_owned()),
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 0,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 2_000,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            amr: Vec::new(),
            ..valid
        },
        1_001
    ));
}

#[test]
fn add_amr_deduplicates_methods() {
    let mut amr = vec!["password".to_owned()];

    add_amr(&mut amr, "otp");
    add_amr(&mut amr, "otp");

    assert_eq!(amr, vec!["password", "otp"]);
}
