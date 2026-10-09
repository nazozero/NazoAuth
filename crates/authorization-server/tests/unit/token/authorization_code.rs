use super::*;
use nazo_auth::{
    AuthorizationCodeClientAuthentication as Auth, AuthorizationCodeHolderEvidence as Evidence,
};

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
    assert!(holder_matches_original(&expected, &expected));
    for (key, value) in [
        ("pkce_s256", serde_json::Value::Null),
        ("pkce_s256", json!(pkce_s256(&"b".repeat(43)))),
        ("dpop_jkt", json!("other-validated-key")),
        ("client_attestation_jkt", json!("other-validated-instance")),
    ] {
        assert!(!holder_matches_original(
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
    assert!(holder_matches_original(&expected, &original_holder()));
    let expected = changed(&expected, "authenticated_client", json!(true)).unwrap();
    assert!(!holder_matches_original(&expected, &original_holder()));
    let authenticated = changed(&original_holder(), "authenticated_client", json!(true)).unwrap();
    assert!(holder_matches_original(&expected, &authenticated));
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
    assert!(holder_matches_original(&authenticated, &authenticated));
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
        pkce_s256: expected.pkce_s256().map(ToOwned::to_owned),
        dpop_jkt: Some("extra-validated-dpop".to_owned()),
        certificate_thumbprint: Some("original-certificate".to_owned()),
        client_attestation_jkt: None,
    };
    assert!(fresh.matches(&expected));
    fresh.certificate_thumbprint = Some("wrong-certificate".to_owned());
    assert!(!fresh.matches(&expected));
    fresh.certificate_thumbprint = None;
    assert!(!fresh.matches(&expected));
}
