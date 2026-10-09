use super::ClientAttestationProofWindow;

#[test]
fn client_attestation_window_preserves_inclusive_age_and_future_tolerance() {
    let window = ClientAttestationProofWindow::from_verified_issued_at(1_000).unwrap();
    assert!(!window.accepts(939));
    assert!(window.accepts(940));
    assert!(window.accepts(1_300));
    assert!(!window.accepts(1_301));
    assert_eq!(window.not_before(), 940);
    assert_eq!(window.expires_at(), 1_301);
    assert!(ClientAttestationProofWindow::from_verified_issued_at(i64::MIN).is_none());
    assert!(ClientAttestationProofWindow::from_verified_issued_at(i64::MAX).is_none());
}
