use actix_web::http::header;
use actix_web::test::TestRequest;
use actix_web::web::Bytes;
use nazo_http_actix::parse_token_form_with_pre_authorized;
use nazo_oauth_server::contracts::token_forms::PreAuthorizedTokenParameters;

fn parsed_parameters(body: &str) -> PreAuthorizedTokenParameters {
    let body = format!("grant_type=client_credentials&{body}");
    let request = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    parse_token_form_with_pre_authorized(&request, &Bytes::from(body))
        .expect("token form should parse")
        .pre_authorized
}

#[test]
fn parses_required_code_and_optional_tx_code_once() {
    let parameters = parsed_parameters("pre-authorized_code=code-1&tx_code=1234&ignored=value");
    assert_eq!(parameters.pre_authorized_code.as_deref(), Some("code-1"));
    assert_eq!(parameters.tx_code.as_deref(), Some("1234"));
    assert!(!parameters.invalid);
}

#[test]
fn rejects_missing_empty_and_repeated_issuance_parameters() {
    for (body, code, tx_code, invalid) in [
        ("", None, None, false),
        ("tx_code=1234", None, Some("1234"), false),
        ("pre-authorized_code=", None, None, true),
        (
            "pre-authorized_code=one&pre-authorized_code=two",
            Some("one"),
            None,
            true,
        ),
        ("tx_code=one&tx_code=two", None, Some("one"), true),
    ] {
        let parameters = parsed_parameters(body);
        assert_eq!(parameters.pre_authorized_code.as_deref(), code, "{body}");
        assert_eq!(parameters.tx_code.as_deref(), tx_code, "{body}");
        assert_eq!(parameters.invalid, invalid, "{body}");
    }
}
