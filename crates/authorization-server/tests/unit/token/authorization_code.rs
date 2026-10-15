use super::*;
use nazo_auth::{
    AuthorizationCodeClientAuthentication as Auth, AuthorizationCodeHolderEvidence as Evidence,
};

fn matches_evidence(expected: &Evidence, candidate: &Evidence) -> bool {
    holder_matches_original(
        expected,
        candidate.authenticated_client(),
        candidate.pkce_s256(),
        candidate.dpop_jkt(),
        candidate.mtls_x5t_s256(),
        candidate.client_attestation_jkt(),
    )
}

fn original_holder() -> Evidence {
    Evidence::from_verified_requirements(
        Auth::Public,
        Some(pkce_s256(&"a".repeat(43))),
        Some("validated-dpop-key".to_owned()),
        None,
        Some("validated-instance-key".to_owned()),
    )
    .unwrap()
}

fn changed(expected: &Evidence, key: &str, value: serde_json::Value) -> Option<Evidence> {
    let mut stored = serde_json::to_value(expected).unwrap();
    stored[key] = value;
    Evidence::from_persisted(stored)
}

#[test]
fn code_holder_evidence_requires_every_original_proof_and_version() {
    let expected = original_holder();
    assert!(matches_evidence(&expected, &expected));
    for (key, value) in [
        ("pkce_s256", serde_json::Value::Null),
        ("pkce_s256", json!(pkce_s256(&"b".repeat(43)))),
        ("dpop_jkt", json!("other-validated-key")),
        ("client_attestation_jkt", json!("other-validated-instance")),
    ] {
        assert!(!matches_evidence(
            &expected,
            &changed(&expected, key, value).unwrap()
        ));
    }
    assert!(changed(&expected, "version", json!(0)).is_none());
    assert!(changed(&expected, "unknown_field", json!(true)).is_none());
    assert!(changed(&expected, "mtls_x5t_s256", json!("extra-mtls")).is_none());
}

#[test]
fn code_holder_evidence_ignores_only_additional_valid_proofs() {
    let expected = Evidence::from_verified_requirements(
        Auth::Public,
        original_holder().pkce_s256().map(ToOwned::to_owned),
        None,
        None,
        None,
    )
    .unwrap();
    assert!(matches_evidence(&expected, &original_holder()));
    let expected = changed(&expected, "authenticated_client", json!(true)).unwrap();
    assert!(!matches_evidence(&expected, &original_holder()));
    let authenticated = changed(&original_holder(), "authenticated_client", json!(true)).unwrap();
    assert!(matches_evidence(&expected, &authenticated));
}

#[test]
fn empty_public_code_holder_is_never_a_possession_wildcard() {
    assert!(Evidence::from_verified_requirements(Auth::Public, None, None, None, None).is_none());
    assert!(
        Evidence::from_verified_requirements(Auth::Public, Some(String::new()), None, None, None)
            .is_none()
    );
    let authenticated =
        Evidence::from_verified_requirements(Auth::Authenticated, None, None, None, None).unwrap();
    assert!(matches_evidence(&authenticated, &authenticated));
}

#[test]
fn borrowed_holder_matching_rejects_missing_or_changed_required_proofs() {
    for proof in 0..4 {
        let mut required = [None, None, None, None];
        required[proof] = Some("original-proof".to_owned());
        let [pkce, dpop, mtls, attestation] = required;
        let expected =
            Evidence::from_verified_requirements(Auth::Public, pkce, dpop, mtls, attestation)
                .unwrap();
        let matches = |candidate: [Option<&str>; 4]| {
            holder_matches_original(
                &expected,
                false,
                candidate[0],
                candidate[1],
                candidate[2],
                candidate[3],
            )
        };
        // Extra facts do not impose new requirements on the original holder.
        let mut candidate = [Some(""); 4];
        candidate[proof] = Some("original-proof");
        assert!(matches(candidate));
        for changed in [None, Some(""), Some("other-proof")] {
            candidate[proof] = changed;
            assert!(!matches(candidate));
        }
    }
}

#[test]
fn fresh_verified_certificate_is_projected_by_original_receipt_requirements() {
    let expected = Evidence::from_verified_requirements(
        Auth::Public,
        Some(pkce_s256(&"a".repeat(43))),
        None,
        Some("original-certificate".to_owned()),
        None,
    )
    .unwrap();
    let mut fresh = FreshCodeHolderFacts {
        client_authentication: Auth::Public,
        pkce_s256: expected.pkce_s256().map(Cow::Borrowed),
        dpop_jkt: Some("extra-validated-dpop"),
        certificate_thumbprint: Some("original-certificate"),
        client_attestation_jkt: None,
    };
    assert!(fresh.matches(&expected));
    fresh.certificate_thumbprint = Some("wrong-certificate");
    assert!(!fresh.matches(&expected));
    fresh.certificate_thumbprint = None;
    assert!(!fresh.matches(&expected));
}
