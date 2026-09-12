use nazo_oauth_server::contracts::{
    oauth_error::OAuthEndpointError,
    token_client_auth::{BasicAuthorizationCredentials, TokenClientAuthTransportFacts},
    token_endpoint::{TokenEndpointSuccess, prepare_token_request},
    token_forms::{ParsedTokenForm, PreAuthorizedTokenParameters, TokenForm},
};

fn parsed(grant: &str, audience: bool) -> ParsedTokenForm {
    ParsedTokenForm {
        form: TokenForm {
            grant_type: grant.into(),
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
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            audiences: Vec::new(),
            has_audience_param: audience,
        },
        pre_authorized: PreAuthorizedTokenParameters {
            pre_authorized_code: None,
            tx_code: None,
            invalid: false,
        },
    }
}

fn auth(conflicting: bool) -> TokenClientAuthTransportFacts {
    TokenClientAuthTransportFacts::from_parts(
        BasicAuthorizationCredentials::Malformed,
        conflicting.then(|| "form-client".into()),
        None,
        None,
        None,
    )
}

#[test]
fn audience_error_precedes_authentication_source_conflict() {
    let Err(OAuthEndpointError::Token {
        fields,
        basic_challenge,
    }) = prepare_token_request(parsed("client_credentials", true), auth(true))
    else {
        panic!("audience must fail before authentication sources")
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(
        fields.description,
        "audience is only valid for OAuth token exchange; use RFC 8707 resource elsewhere."
    );
    assert!(!basic_challenge);
}

#[test]
fn allowed_audience_still_rejects_conflicting_authentication_sources() {
    let Err(OAuthEndpointError::Token {
        fields,
        basic_challenge,
    }) = prepare_token_request(
        parsed(nazo_oauth_server::token::TOKEN_EXCHANGE_GRANT_TYPE, true),
        auth(true),
    )
    else {
        panic!("conflicting authentication sources must fail")
    };
    assert_eq!(fields.status, http::StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(
        fields.description,
        "同一 token 请求不能同时使用多种客户端认证方式."
    );
    assert!(!basic_challenge);
}

#[test]
fn preflight_leaves_credential_validation_to_execution() {
    assert!(prepare_token_request(parsed("client_credentials", false), auth(false)).is_ok());
    assert!(
        prepare_token_request(
            parsed(nazo_oauth_server::token::TOKEN_EXCHANGE_GRANT_TYPE, true),
            auth(false),
        )
        .is_ok()
    );
}

#[test]
fn token_results_are_send_without_a_framework_response_wrapper() {
    fn assert_send<T: Send>() {}
    assert_send::<Result<TokenEndpointSuccess, OAuthEndpointError>>();
}
