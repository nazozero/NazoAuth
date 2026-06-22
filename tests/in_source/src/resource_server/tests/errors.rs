use super::*;

#[test]
fn bearer_error_response_does_not_leak_internal_verifier_reason() {
    let response = http_bearer_error_response(&ResourceServerRequestError::InvalidToken(
        ResourceServerVerifierError::UnknownKeyId,
    ));

    assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .unwrap(),
        r#"Bearer error="invalid_token", error_description="Access token is invalid.""#
    );
    assert_eq!(
        response.body(),
        r#"{"error":"invalid_token","error_description":"Access token is invalid."}"#
    );
    assert!(!response.body().contains("UnknownKeyId"));
}
