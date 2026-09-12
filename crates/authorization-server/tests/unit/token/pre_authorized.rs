use super::pre_authorized_parameters;
use crate::contracts::{
    oauth_error::OAuthEndpointError, token_forms::PreAuthorizedTokenParameters,
};
use http::StatusCode;

#[test]
fn parses_required_code_and_optional_tx_code_once() {
    let mut parameters = PreAuthorizedTokenParameters {
        pre_authorized_code: Some("code-1".into()),
        tx_code: Some("1234".into()),
        invalid: false,
    };
    let parsed =
        pre_authorized_parameters(&mut parameters).expect("valid pre-authorized token parameters");
    assert_eq!(parsed, ("code-1".to_owned(), Some("1234".to_owned())));
}

#[test]
fn rejects_missing_empty_and_repeated_issuance_parameters() {
    for (code, tx_code, invalid) in [
        (None, None, false),
        (None, Some("1234"), false),
        (None, None, true),
        (Some("one"), None, true),
        (None, Some("one"), true),
    ] {
        let mut parameters = PreAuthorizedTokenParameters {
            pre_authorized_code: code.map(str::to_owned),
            tx_code: tx_code.map(str::to_owned),
            invalid,
        };
        let error = pre_authorized_parameters(&mut parameters)
            .expect_err("invalid pre-authorized parameters must fail");
        assert!(matches!(
            error,
            OAuthEndpointError::Token {
                fields: crate::contracts::oauth_error::OAuthErrorFields {
                    status: StatusCode::BAD_REQUEST,
                    ..
                },
                ..
            }
        ));
    }
}
