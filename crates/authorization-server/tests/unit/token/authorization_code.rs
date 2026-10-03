use super::*;

fn original_holder() -> nazo_auth::AuthorizationCodeHolderEvidence {
    nazo_auth::AuthorizationCodeHolderEvidence {
        version: 1,
        authenticated_client: false,
        pkce_s256: Some(pkce_s256(&"a".repeat(43))),
        dpop_jkt: Some("validated-dpop-key".to_owned()),
        mtls_x5t_s256: None,
        client_attestation_jkt: Some("validated-instance-key".to_owned()),
    }
}

#[test]
fn code_holder_evidence_requires_every_original_proof_and_version() {
    let expected = original_holder();
    assert!(holder_matches_original(&expected, &expected));
    let mut missing = expected.clone();
    missing.pkce_s256 = None;
    assert!(!holder_matches_original(&expected, &missing));
    let mut wrong = expected.clone();
    wrong.pkce_s256 = Some(pkce_s256(&"b".repeat(43)));
    assert!(!holder_matches_original(&expected, &wrong));
    let mut wrong = expected.clone();
    wrong.dpop_jkt = Some("other-validated-key".to_owned());
    assert!(!holder_matches_original(&expected, &wrong));
    let mut wrong = expected.clone();
    wrong.client_attestation_jkt = Some("other-validated-instance".to_owned());
    assert!(!holder_matches_original(&expected, &wrong));
    let mut wrong = expected.clone();
    wrong.version = 0;
    assert!(!holder_matches_original(&expected, &wrong));
    assert!(!holder_matches_original(&wrong, &expected));
}

#[test]
fn code_holder_evidence_ignores_only_additional_valid_proofs() {
    let mut expected = original_holder();
    expected.dpop_jkt = None;
    expected.client_attestation_jkt = None;
    assert!(holder_matches_original(&expected, &original_holder()));
    expected.authenticated_client = true;
    assert!(!holder_matches_original(&expected, &original_holder()));
    let mut authenticated = original_holder();
    authenticated.authenticated_client = true;
    assert!(holder_matches_original(&expected, &authenticated));
}

#[test]
fn empty_public_code_holder_is_never_a_possession_wildcard() {
    let mut empty = nazo_auth::AuthorizationCodeHolderEvidence {
        version: 1,
        authenticated_client: false,
        pkce_s256: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
    };
    assert!(!empty.is_well_formed());
    assert!(!holder_matches_original(&empty, &empty));
    assert!(!holder_matches_original(&original_holder(), &empty));
    empty.authenticated_client = true;
    assert!(holder_matches_original(&empty, &empty));
    empty.authenticated_client = false;
    empty.pkce_s256 = Some(String::new());
    assert!(!empty.is_well_formed());
}
