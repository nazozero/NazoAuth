use super::*;
use actix_web::test::TestRequest;
use proptest::prelude::*;

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

#[test]
fn token_form_rejects_duplicate_defined_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=authorization_code&grant_type=refresh_token"),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_form_ignores_unknown_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=client_credentials&unknown=a"),
    )
    .unwrap();

    assert_eq!(form.grant_type, "client_credentials");
}

#[test]
fn token_form_accepts_standard_resource_parameter_as_audience() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com",
        ),
    )
    .unwrap();

    assert_eq!(form.audiences, vec!["https://api.example.com"]);
}

#[test]
fn token_form_accepts_multiple_resource_parameters_as_audiences() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fpayments.example.com",
        ),
    )
    .unwrap();

    assert_eq!(
        form.audiences,
        vec!["https://api.example.com", "https://payments.example.com"]
    );
}

#[test]
fn token_form_rejects_duplicate_resource_values() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fapi.example.com",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_form_rejects_invalid_resource_parameter() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=client_credentials&resource=api"),
    );

    assert!(matches!(
        result,
        Err(TokenFormError::InvalidResourceParameter)
    ));
}

#[test]
fn token_form_rejects_conflicting_resource_and_audience() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&audience=resource%3A%2F%2Fdefault&resource=https%3A%2F%2Fapi.example.com",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&audience=resource%3A%2F%2Fdefault",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_management_form_rejects_duplicate_defined_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result =
        parse_token_management_form(&req, &Bytes::from_static(b"token=token-1&token=token-2"));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::DuplicateParameter)
    ));
}

#[test]
fn token_management_form_tracks_token_type_hint_duplicates() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_management_form(
        &req,
        &Bytes::from_static(
            b"token=token-1&token_type_hint=access_token&token_type_hint=refresh_token",
        ),
    );

    assert!(matches!(
        result,
        Err(TokenManagementFormError::DuplicateParameter)
    ));
}

#[test]
fn token_management_form_accepts_token_type_hint_without_requiring_known_value() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_management_form(
        &req,
        &Bytes::from_static(b"token=token-1&token_type_hint=opaque_hint"),
    )
    .unwrap();

    assert_eq!(form.token, "token-1");
    assert_eq!(form.token_type_hint.as_deref(), Some("opaque_hint"));
}

#[test]
fn token_management_form_requires_form_content_type() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();

    let result = parse_token_management_form(&req, &Bytes::from_static(b"token=token-1"));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::InvalidContentType)
    ));
}

#[test]
fn token_management_form_requires_non_empty_token() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_management_form(&req, &Bytes::from_static(b"token="));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::MissingToken)
    ));
}

#[test]
fn token_management_form_error_is_not_cacheable() {
    let response = token_management_form_error(TokenManagementFormError::MissingToken);

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

proptest! {
    #[test]
    fn resource_parameter_accepts_absolute_uris_without_fragments(
        host in "[a-z][a-z0-9]{0,12}\\.example",
        path in "[a-zA-Z0-9/_-]{0,32}",
        query in prop::option::of("[a-zA-Z0-9_=&-]{1,32}")
    ) {
        let req = form_request();
        let query_suffix = query
            .as_deref()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        let resource = format!("https://{host}/{path}{query_suffix}");
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &resource)
            .finish();

        let form = parse_token_form(&req, &Bytes::from(encoded)).unwrap();

        prop_assert_eq!(form.audiences, vec![resource]);
    }

    #[test]
    fn resource_parameter_rejects_relative_or_fragment_uris(
        resource in "[a-zA-Z0-9/_-]{1,32}",
        fragment in "[a-zA-Z0-9_-]{1,16}"
    ) {
        let req = form_request();
        let relative = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &resource)
            .finish();
        let with_fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &format!("https://api.example/{resource}#{fragment}"))
            .finish();

        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(relative)),
            Err(TokenFormError::InvalidResourceParameter)
        ));
        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(with_fragment)),
            Err(TokenFormError::InvalidResourceParameter)
        ));
    }

    #[test]
    fn duplicate_defined_parameters_are_rejected_regardless_of_value(
        first in "[a-zA-Z0-9_-]{0,16}",
        second in "[a-zA-Z0-9_-]{0,16}"
    ) {
        let req = form_request();
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &first)
            .append_pair("client_id", &second)
            .finish();

        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(body)),
            Err(TokenFormError::DuplicateParameter)
        ));
    }
}
