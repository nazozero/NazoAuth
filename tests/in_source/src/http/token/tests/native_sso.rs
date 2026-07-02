use super::*;

fn token_form() -> TokenForm {
    TokenForm {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: Some("id-token".to_owned()),
        subject_token_type: Some(NATIVE_SSO_ID_TOKEN_TYPE.to_owned()),
        actor_token: Some("device-secret".to_owned()),
        actor_token_type: Some(NATIVE_SSO_DEVICE_SECRET_TYPE.to_owned()),
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

#[test]
fn native_sso_device_secret_hash_is_stable_and_non_raw() {
    let first = native_sso_device_secret_hash("secret");
    let second = native_sso_device_secret_hash("secret");

    assert_eq!(first, second);
    assert_ne!(first, "secret");
    assert!(!first.contains('='));
}

#[test]
fn native_sso_device_secret_key_does_not_embed_raw_secret() {
    let key = native_sso_device_secret_key("raw-device-secret");

    assert!(key.starts_with("oauth:native_sso:device_secret:"));
    assert!(!key.contains("raw-device-secret"));
}

#[test]
fn native_sso_profile_requires_id_token_and_device_secret_token_types() {
    let mut form = token_form();
    assert!(native_sso_profile_requested(&form));

    form.actor_token_type = Some("urn:ietf:params:oauth:token-type:access_token".to_owned());
    assert!(!native_sso_profile_requested(&form));
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
