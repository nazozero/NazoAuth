use super::prepare_token_request;
use crate::contracts::{
    token_client_auth::BasicAuthorizationCredentials,
    token_forms::{ParsedTokenForm, PreAuthorizedTokenParameters, TokenForm},
};

fn parsed() -> ParsedTokenForm {
    ParsedTokenForm {
        form: TokenForm {
            grant_type: "client_credentials".into(),
            code: None,
            device_code: None,
            auth_req_id: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            device_secret: None,
            scope: None,
            client_id: Some("client".into()),
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
        },
        pre_authorized: PreAuthorizedTokenParameters {
            pre_authorized_code: None,
            tx_code: None,
            invalid: false,
        },
    }
}

#[test]
fn prepared_post_credentials_reuse_the_parsed_buffers() {
    let mut parsed = parsed();
    parsed.form.client_secret = Some("secret".into());
    let id = parsed.form.client_id.as_ref().unwrap().as_ptr();
    let secret = parsed.form.client_secret.as_ref().unwrap().as_ptr();
    let prepared = prepare_token_request(parsed, BasicAuthorizationCredentials::Absent).unwrap();
    let credentials = prepared.auth.credential_view(None, None);
    assert_eq!(credentials.client_id.unwrap().as_ptr(), id);
    assert_eq!(credentials.client_secret.unwrap().as_ptr(), secret);
    assert_eq!(credentials.method, "client_secret_post");
    assert_eq!(prepared.auth.form_client_id(), Some("client"));
    assert!(prepared.auth.presentation().form_client_secret);
    assert!(prepared.parsed.form.client_id.is_none());
    assert!(prepared.parsed.form.client_secret.is_none());
}

#[test]
fn prepared_assertion_credentials_reuse_the_parsed_buffers() {
    let mut parsed = parsed();
    parsed.form.client_assertion_type =
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into());
    parsed.form.client_assertion = Some("signed-client-assertion".into());
    let kind = parsed.form.client_assertion_type.as_ref().unwrap().as_ptr();
    let assertion = parsed.form.client_assertion.as_ref().unwrap().as_ptr();
    let prepared = prepare_token_request(parsed, BasicAuthorizationCredentials::Absent).unwrap();
    assert_eq!(
        prepared.auth.client_assertion_type().unwrap().as_ptr(),
        kind
    );
    assert_eq!(
        prepared.auth.client_assertion().unwrap().as_ptr(),
        assertion
    );
    assert!(prepared.client_auth_context.has_assertion);
    assert!(prepared.parsed.form.client_assertion_type.is_none());
    assert!(prepared.parsed.form.client_assertion.is_none());
}
