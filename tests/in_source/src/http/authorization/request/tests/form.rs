use super::*;
use actix_web::test::TestRequest;

fn authorization_post_request(content_type: &str, query: &str) -> HttpRequest {
    TestRequest::post()
        .uri(&format!("/authorize?{query}"))
        .insert_header((header::CONTENT_TYPE, content_type))
        .to_http_request()
}

#[test]
fn authorization_post_form_requires_form_urlencoded_content_type() {
    let req = authorization_post_request("application/json", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(br#"{"response_type":"code"}"#),
        &authorization_duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_json_error(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_rejects_non_utf8_body() {
    let req = authorization_post_request("application/x-www-form-urlencoded", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(&[0xff, 0xfe]),
        &authorization_duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_json_error(&response).as_deref(),
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
        &authorization_duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_json_error(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_rejects_duplicate_oauth_parameter_in_body() {
    let req = authorization_post_request("application/x-www-form-urlencoded; charset=utf-8", "");

    let response = parse_authorization_post_form(
        &req,
        &Bytes::from_static(b"response_type=code&response_type=token"),
        &authorization_duplicate_parameters(),
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_json_error(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn authorization_post_form_preserves_unknown_parameters_without_duplicate_rejection() {
    let req = authorization_post_request("application/x-www-form-urlencoded", "");

    let parsed = parse_authorization_post_form(
        &req,
        &Bytes::from_static(b"response_type=code&custom=a&custom=b"),
        &authorization_duplicate_parameters(),
    )
    .unwrap();

    assert_eq!(
        parsed.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(parsed.get("custom").map(String::as_str), Some("b"));
}
