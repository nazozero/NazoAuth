use super::*;

#[test]
fn form_parser_accepts_login_fields_and_next() {
    let parsed = parse_login_form(
        "email=user%40example.test&password=s3cret&next=%2Fauthorize%3Fclient_id%3Dabc",
    )
    .expect("form should parse");
    assert_eq!(parsed.email, "user@example.test");
    assert_eq!(parsed.password, "s3cret");
    assert_eq!(parsed.next.as_deref(), Some("/authorize?client_id=abc"));
}

#[actix_web::test]
async fn form_parser_rejects_duplicate_login_fields() {
    let err =
        match parse_login_form("email=a%40example.test&email=b%40example.test&password=s3cret") {
            Ok(_) => panic!("duplicate login form field must be rejected"),
            Err(response) => response,
        };

    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    let body = actix_web::body::to_bytes(err.into_body())
        .await
        .expect("response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("access_token").is_none());
}

#[test]
fn safe_relative_next_allows_authorization_path_only_when_relative() {
    assert_eq!(
        safe_relative_next("/authorize?client_id=abc").as_deref(),
        Some("/authorize?client_id=abc")
    );
    assert!(safe_relative_next("https://evil.example/authorize").is_none());
    assert!(safe_relative_next("//evil.example/authorize").is_none());
    assert!(safe_relative_next("/ui/auth?next=%2Fauthorize").is_none());
    assert!(safe_relative_next("/authorize.evil/path").is_none());
}
