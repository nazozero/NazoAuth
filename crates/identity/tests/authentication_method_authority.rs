use nazo_identity::{
    UserId,
    session::{SessionRecord, recent_interactive_mfa, valid_authentication_metadata},
};

#[test]
fn session_amr_preserves_unknown_evidence_without_inventing_federation() {
    let mut session = SessionRecord::new(
        UserId::new(uuid::Uuid::now_v7()).unwrap(),
        1_700_000_000,
        vec!["pwd".into(), "hwk".into(), "vendor:custom".into()],
        false,
        Some("sid-original".into()),
    );
    session.add_amr("pwd");
    assert_eq!(session.amr(), ["pwd", "hwk", "vendor:custom"]);
    assert!(!recent_interactive_mfa(
        session.auth_time(),
        session.amr(),
        1_700_000_001
    ));
    assert_eq!(session.oidc_sid(), Some("sid-original"));
    assert!(valid_authentication_metadata(
        session.auth_time(),
        session.amr(),
        session.oidc_sid(),
        1_700_000_001
    ));
}

#[test]
fn real_session_metadata_rejects_empty_evidence_and_invalid_time_or_sid() {
    for amr in [
        vec![],
        vec!["".into()],
        vec![" ".into()],
        vec!["pwd".into(), "".into()],
    ] {
        assert!(!valid_authentication_metadata(
            1_000,
            &amr,
            Some("sid"),
            1_001
        ));
    }
    assert!(!valid_authentication_metadata(
        0,
        &["pwd".into()],
        Some("sid"),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_032,
        &["pwd".into()],
        Some("sid"),
        1_001
    ));
    assert!(!valid_authentication_metadata(
        1_000,
        &["pwd".into()],
        Some(" "),
        1_001
    ));
}

#[test]
fn credential_management_reuses_only_fresh_sufficient_authentication() {
    use nazo_identity::session::recent_credential_management_authentication as permits;
    let now = 1_700_000_000;
    for methods in [
        vec!["pwd".to_owned()],
        vec!["passkey".to_owned()],
        vec!["federated".to_owned()],
    ] {
        assert!(permits(now, &methods, false, now));
        assert!(!permits(now - 301, &methods, false, now));
        assert!(!permits(now + 1, &methods, false, now));
        assert!(!permits(now, &methods, true, now));
    }
    for methods in [
        vec!["pwd".into(), "otp".into(), "mfa".into()],
        vec!["passkey".into(), "passkey_uv".into(), "mfa".into()],
    ] {
        assert!(permits(now, &methods, true, now));
        assert!(!permits(now - 301, &methods, true, now));
    }
    assert!(!permits(
        now,
        &["passkey".into(), "remembered_mfa".into(), "mfa".into()],
        true,
        now
    ));
}
#[test]
fn totp_credentials_do_not_expose_seeds_in_debug_output() {
    use nazo_identity::TotpEnrollmentStart;
    let seed = "JBSWY3DPEHPK3PXP";
    let enrollment = TotpEnrollmentStart {
        secret_base32: seed.to_owned(),
        otpauth_uri: format!("otpauth://totp/test?secret={seed}"),
    };
    for output in [format!("{enrollment:?}"), format!("{enrollment:#?}")] {
        assert!(!output.contains(seed));
        assert!(output.contains("[REDACTED]"));
    }
}
