use nazo_identity::{AuthMethod, AuthenticationContext, IdentityModelError};
use serde_json::json;

#[test]
fn local_authentication_serializes_only_one_method_representation() {
    let context = AuthenticationContext::new(
        1_700_000_000,
        [
            AuthMethod::Password,
            AuthMethod::RememberedMfa,
            AuthMethod::Password,
        ],
    )
    .unwrap();
    let encoded = serde_json::to_value(&context).unwrap();

    assert_eq!(context.amr(), ["password", "remembered_mfa", "mfa"]);
    assert!(context.has_mfa());
    assert_eq!(encoded["amr"], json!(context.amr()));
    assert!(encoded.get("methods").is_none());
    assert_eq!(encoded.as_object().unwrap().len(), 3);
}

#[test]
fn persisted_amr_preserves_unknown_values_without_inventing_federation() {
    let context = AuthenticationContext::from_amr(
        1_700_000_000,
        ["pwd", "hwk", "vendor:custom", "pwd"],
        "sid-original",
        1_700_000_001,
    )
    .unwrap();

    assert_eq!(context.amr(), ["pwd", "hwk", "vendor:custom"]);
    assert!(!context.has_mfa());
    assert_eq!(
        serde_json::to_value(&context).unwrap(),
        json!({
            "auth_time": 1_700_000_000,
            "oidc_sid": "sid-original",
            "amr": ["pwd", "hwk", "vendor:custom"],
        })
    );
}

#[test]
fn single_method_authority_keeps_existing_metadata_validation() {
    assert_eq!(
        AuthenticationContext::from_amr(1_000, ["", " "], "sid", 1_001),
        Err(IdentityModelError::EmptyAuthenticationMethods)
    );
    assert_eq!(
        AuthenticationContext::from_amr(1_032, ["pwd"], "sid", 1_001),
        Err(IdentityModelError::FutureAuthenticationTime)
    );
    assert_eq!(
        AuthenticationContext::new(1_000, std::iter::empty()),
        Err(IdentityModelError::EmptyAuthenticationMethods)
    );
}
