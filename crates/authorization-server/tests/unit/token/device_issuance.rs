use super::required_device_code;
use crate::contracts::{
    oauth_error::{OAuthEndpointError, OAuthErrorFields},
    token_forms::TokenForm,
};
use crate::token::DEVICE_CODE_GRANT_TYPE;
use http::StatusCode;
fn token_error_fields(error: &OAuthEndpointError) -> &OAuthErrorFields {
    match error {
        OAuthEndpointError::Token { fields, .. } => fields,
        _ => panic!("expected token error"),
    }
}
fn device_token_form(device_code: Option<&str>) -> TokenForm {
    TokenForm {
        grant_type: DEVICE_CODE_GRANT_TYPE.to_owned(),
        code: None,
        device_code: device_code.map(ToOwned::to_owned),
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("device-client".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    }
}
#[test]
fn device_code_grant_requires_device_code_before_state_lookup() {
    let form = device_token_form(None);
    let response = required_device_code(&form).expect_err("missing device_code must fail");

    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "invalid_request");

    let form = device_token_form(Some("   "));
    let response = required_device_code(&form).expect_err("blank device_code must fail");
    assert_eq!(
        token_error_fields(&response).status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(token_error_fields(&response).error, "invalid_request");
}

use super::device_grant_key;

#[test]
fn device_grant_identity_only_depends_on_the_immutable_code() {
    let identity = device_grant_key("device-code");
    assert!(identity.starts_with("device_code:"));
    assert!(!identity.contains("device-code"));
    assert_eq!(identity, device_grant_key("device-code"));
    assert_ne!(identity, device_grant_key("other-device-code"));
}
