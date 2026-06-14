use super::*;
use proptest::prelude::*;

#[test]
fn oauth_token_error_description_keeps_rfc_allowed_ascii() {
    assert_eq!(
        oauth_error_description("Authorization code has already been used.").as_ref(),
        "Authorization code has already been used."
    );
}

#[test]
fn oauth_token_error_description_replaces_disallowed_text() {
    assert_eq!(
        oauth_error_description("授权码已被使用.").as_ref(),
        "Request failed."
    );
    assert_eq!(
        oauth_error_description("invalid\\request").as_ref(),
        "Request failed."
    );
}

#[test]
fn oauth_bearer_error_includes_rfc6750_challenge_fields() {
    let response = oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Access token expired.",
    );

    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(
            r#"Bearer error="invalid_token", error_description="Access token expired.""#
        )
    );
}

#[test]
fn oauth_bearer_error_sanitizes_challenge_description() {
    let response = oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已失效.");

    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(
            r#"Bearer error="invalid_token", error_description="Request failed.""#
        )
    );
}

#[actix_web::test]
async fn authorization_error_response_is_json_no_store_and_sanitized() {
    let response = authorization_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "redirect_uri 含有非法字符.",
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
}

proptest! {
    #[test]
    fn oauth_error_description_preserves_only_rfc_allowed_ascii(
        allowed in "[\\t\\n\\r !#-\\[\\]-~]{0,128}",
        disallowed in "[^\\t\\n\\r !#-\\[\\]-~]{1,32}"
    ) {
        let allowed_description = oauth_error_description(&allowed);
        let disallowed_description = oauth_error_description(&disallowed);

        prop_assert_eq!(allowed_description.as_ref(), allowed.as_str());
        prop_assert_eq!(disallowed_description.as_ref(), "Request failed.");
    }

    #[test]
    fn bearer_challenge_never_serializes_non_ascii_descriptions(
        error in "[a-z_]{1,32}",
        description in "\\PC{1,64}"
    ) {
        let challenge = bearer_challenge(&error, &description);
        let rendered = challenge.to_str().unwrap();

        if description.bytes().all(is_oauth_error_description_byte) {
            let expected = format!(r#"error_description="{}""#, description);
            prop_assert!(rendered.contains(&expected));
        } else {
            prop_assert!(rendered.contains(r#"error_description="Request failed.""#));
        }
    }
}
