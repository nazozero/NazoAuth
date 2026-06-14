use super::*;

#[test]
fn pkce_legacy_exception_is_limited_to_confidential_non_dpop_clients() {
    assert!(validate_pkce_compatibility_policy(false, "public", true).is_ok());
    assert!(validate_pkce_compatibility_policy(true, "confidential", false).is_ok());

    let public_err = validate_pkce_compatibility_policy(true, "public", false).unwrap_err();
    assert_eq!(
        public_err.to_string(),
        "PKCE compatibility exceptions are limited to confidential clients"
    );

    let dpop_err = validate_pkce_compatibility_policy(true, "confidential", true).unwrap_err();
    assert_eq!(dpop_err.to_string(), "DPoP-bound clients must use PKCE");
}
