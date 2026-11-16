use super::*;

use nazo_auth::parse_resource_indicator_parameter;
use nazo_oauth_server::authorization::AuthorizationApplication;

fn authorization_post_request(content_type: &str, query: &str) -> HttpRequest {
    http::Request::post(format!("/authorize?{query}"))
        .header(header::CONTENT_TYPE, content_type)
        .body(Bytes::new())
        .unwrap()
}

#[test]
fn authorization_post_form_requires_form_urlencoded_content_type() {
    let req = authorization_post_request("application/json", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(br#"{"response_type":"code"}"#),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_oauth_error_code(response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_rejects_non_utf8_body() {
    let req = authorization_post_request("application/x-www-form-urlencoded", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(&[0xff, 0xfe]),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_oauth_error_code(response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_rejects_duplicate_oauth_parameter_in_query() {
    let req = authorization_post_request(
        "application/x-www-form-urlencoded",
        "response_type=code&response_type=token",
    );

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(b"client_id=client"),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_oauth_error_code(response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_rejects_duplicate_oauth_parameter_in_body() {
    let req = authorization_post_request("application/x-www-form-urlencoded; charset=utf-8", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(b"response_type=code&response_type=token"),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_oauth_error_code(response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_preserves_unknown_parameters_without_duplicate_rejection() {
    let req = authorization_post_request("application/x-www-form-urlencoded", "");

    let parsed = parse_authorization_post_form(
        &req,
        &Bytes::from_static(b"response_type=code&custom=a&custom=b"),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap();

    assert_eq!(
        parsed.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(parsed.get("custom").map(String::as_str), Some("b"));
}

#[test]
fn authorization_query_preserves_multiple_resource_indicators() {
    let parsed = parse_authorization_query(
        "response_type=code&resource=https%3A%2F%2Fapi.example%2Fone&resource=https%3A%2F%2Fapi.example%2Ftwo",
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap();

    assert_eq!(
        parse_resource_indicator_parameter(parsed.get("resource").map(String::as_str)).unwrap(),
        vec![
            "https://api.example/one".to_owned(),
            "https://api.example/two".to_owned(),
        ]
    );
}

#[test]
fn authorization_post_form_preserves_multiple_resource_indicators() {
    let req = authorization_post_request("application/x-www-form-urlencoded", "");

    let parsed = parse_authorization_post_form(
        &req,
        &Bytes::from_static(
            b"response_type=code&resource=https%3A%2F%2Fapi.example%2Fone&resource=https%3A%2F%2Fapi.example%2Ftwo",
        ),
        AuthorizationApplication::duplicate_parameters(),
    )
    .unwrap();

    assert_eq!(
        parse_resource_indicator_parameter(parsed.get("resource").map(String::as_str)).unwrap(),
        vec![
            "https://api.example/one".to_owned(),
            "https://api.example/two".to_owned(),
        ]
    );
}

fn response_oauth_error_code(response: HttpResponse) -> Option<String> {
    let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
    body["error"].as_str().map(str::to_owned)
}
