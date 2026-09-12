use super::*;

#[test]
fn native_sso_device_secret_hash_is_stable_and_non_raw() {
    let first = native_sso_device_secret_hash("secret");
    let second = native_sso_device_secret_hash("secret");

    assert_eq!(first, second);
    assert_ne!(first, "secret");
    assert!(!first.contains('='));
}

#[test]
fn native_sso_id_token_audience_requires_the_source_client() {
    let base = NativeSsoIdTokenClaims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        aud: json!("source-client"),
        ds_hash: "hash".to_owned(),
        sid: "sid-1".to_owned(),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
    };
    assert!(native_sso_id_token_audience_contains(
        &base,
        "source-client"
    ));
    assert!(!native_sso_id_token_audience_contains(
        &base,
        "other-client"
    ));

    let array = NativeSsoIdTokenClaims {
        aud: json!(["other-client", "source-client"]),
        ..base
    };
    assert!(native_sso_id_token_audience_contains(
        &array,
        "source-client"
    ));
    assert!(!native_sso_id_token_audience_contains(
        &array,
        "missing-client"
    ));

    let invalid = NativeSsoIdTokenClaims {
        aud: json!(42),
        ..array
    };
    assert!(!native_sso_id_token_audience_contains(
        &invalid,
        "source-client"
    ));
}

#[test]
fn new_native_sso_token_binding_requires_session_id() {
    assert!(new_native_sso_token_binding(None).is_none());

    let binding = new_native_sso_token_binding(Some("sid-1")).expect("sid should bind native SSO");
    assert_eq!(binding.sid, "sid-1");
    assert_eq!(
        binding.ds_hash,
        native_sso_device_secret_hash(&binding.device_secret)
    );
}
