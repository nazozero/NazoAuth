use super::*;

fn valid_payload() -> SessionPayload {
    SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        pending_mfa: false,
        oidc_sid: Some("sid-1".to_owned()),
    }
}

#[test]
fn session_payload_requires_authentication_metadata_and_oidc_sid() {
    let valid = valid_payload();

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
fn session_payload_allows_only_small_clock_skew_for_auth_time() {
    let mut payload = valid_payload();

    payload.auth_time = 1_030;
    assert!(valid_session_payload(&payload, 1_000));

    payload.auth_time = 1_031;
    assert!(!valid_session_payload(&payload, 1_000));
}

#[test]
fn session_payload_preserves_pending_mfa_as_metadata_not_validity() {
    let mut payload = valid_payload();
    payload.pending_mfa = true;

    assert!(valid_session_payload(&payload, 1_001));
}

#[test]
fn session_payload_requires_non_blank_oidc_sid_after_trimming() {
    for sid in ["", " ", "\t\n"] {
        let mut payload = valid_payload();
        payload.oidc_sid = Some(sid.to_owned());

        assert!(
            !valid_session_payload(&payload, 1_001),
            "blank sid {sid:?} must not produce an OIDC session"
        );
    }
}

#[test]
fn add_amr_deduplicates_methods() {
    let mut amr = vec!["password".to_owned()];

    add_amr(&mut amr, "otp");
    add_amr(&mut amr, "otp");

    assert_eq!(amr, vec!["password", "otp"]);
}

#[test]
fn add_amr_preserves_original_order_for_oidc_amr_claims() {
    let mut amr = vec!["pwd".to_owned(), "otp".to_owned()];

    add_amr(&mut amr, "mfa");
    add_amr(&mut amr, "pwd");

    assert_eq!(amr, vec!["pwd", "otp", "mfa"]);
}
