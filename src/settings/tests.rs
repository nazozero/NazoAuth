use super::*;

#[test]
fn default_dpop_nonce_policy_is_required() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
}

#[test]
fn baseline_profile_can_use_optional_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "optional")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Optional);
}

#[test]
fn fapi_profiles_force_required_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([
        ("AUTHORIZATION_SERVER_PROFILE", "fapi2-security"),
        ("DPOP_NONCE_POLICY", "optional"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.dpop_nonce_policy, DpopNoncePolicy::Required);
}

#[test]
fn invalid_dpop_nonce_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "sometimes")]);

    let Err(err) = Settings::from_config(&config) else {
        panic!("invalid DPoP nonce policy must be rejected");
    };

    assert_eq!(
        err.to_string(),
        "DPOP_NONCE_POLICY must be required or optional, got sometimes"
    );
}

#[test]
fn dpop_nonce_policy_rejects_legacy_compatibility_alias() {
    for value in ["compat", "compatible"] {
        let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", value)]);

        let Err(err) = Settings::from_config(&config) else {
            panic!("legacy DPoP nonce policy alias must be rejected");
        };

        assert_eq!(
            err.to_string(),
            format!("DPOP_NONCE_POLICY must be required or optional, got {value}")
        );
    }
}

#[test]
fn default_request_object_jti_policy_is_optional() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.request_object_jti_policy,
        RequestObjectJtiPolicy::Optional
    );
}

#[test]
fn request_object_jti_policy_can_require_signed_jar_jti() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "required")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.request_object_jti_policy,
        RequestObjectJtiPolicy::RequiredForSignedJar
    );
}

#[test]
fn invalid_request_object_jti_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "always")]);

    assert!(Settings::from_config(&config).is_err());
}
