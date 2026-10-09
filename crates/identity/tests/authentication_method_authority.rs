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
fn totp_credentials_do_not_expose_seeds_in_debug_output() {
    use nazo_identity::ports::{TotpCredential, TotpEnrollment};
    let seed = "JBSWY3DPEHPK3PXP";
    let credential = TotpCredential {
        secret_base32: seed.to_owned(),
        last_used_step: Some(42),
    };
    let enrollment = TotpEnrollment {
        secret_base32: seed.to_owned(),
        confirmed: false,
        last_used_step: None,
    };
    for output in [format!("{credential:?}"), format!("{enrollment:#?}")] {
        assert!(!output.contains(seed));
        assert!(output.contains("[REDACTED]"));
    }
}
