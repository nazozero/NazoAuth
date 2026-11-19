use bytes::Bytes;
use nazoauth::integration::conformance;

#[test]
fn production_presenters_keep_headers_status_and_body_allocation() {
    for (name, expected) in conformance::response_cases() {
        let pointer = expected.body().as_ptr();
        let empty = expected.body().is_empty();
        let actual = nazo_http_worker::forward_response(expected.clone())
            .map(|body| body.into_inner().unwrap_or_default());
        conformance::assert_response(&expected, &actual);
        if !empty {
            assert_eq!(actual.body().as_ptr(), pointer, "{name}");
        }
    }
}

#[test]
fn empty_responses_have_no_synthetic_body() {
    let response = http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(Bytes::new())
        .unwrap();
    let actual = nazo_http_worker::forward_response(response);
    assert_eq!(actual.status(), http::StatusCode::NO_CONTENT);
    assert!(actual.into_body().into_inner().is_none());
}
