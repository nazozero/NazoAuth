use super::*;

#[test]
fn jwt_provider_error_creates_provider_error_kind() {
    let error = jwt_provider_error("test error message");
    let display = format!("{error}");
    assert!(
        display.contains("test error message"),
        "error display should contain message: {display}"
    );
}

#[test]
fn jwt_provider_error_is_jsonwebtoken_error() {
    use std::error::Error;
    let error = jwt_provider_error("some error");
    let source = error.source();
    assert!(
        source.is_none(),
        "jsonwebtoken::Error with Provider kind should not have a source"
    );
}

#[test]
fn jwt_provider_error_with_empty_message() {
    let error = jwt_provider_error("");
    let display = format!("{error}");
    assert!(!display.is_empty());
}

#[test]
fn jwt_provider_error_with_owned_string() {
    let msg = "dynamic".to_owned() + " error";
    let error = jwt_provider_error(msg);
    assert!(format!("{error}").contains("dynamic error"));
}
