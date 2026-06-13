use super::*;

#[test]
fn post_body_access_token_accepts_single_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    let UserInfoAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from form body");
    };
    assert_eq!(token, "token-1");
}

#[test]
fn userinfo_accepts_only_userinfo_or_default_audience() {
    let mut settings = Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();

    assert!(userinfo_audience_allowed(
        &settings,
        &json!("resource://default")
    ));
    assert!(userinfo_audience_allowed(
        &settings,
        &json!("https://issuer.example/userinfo")
    ));
    assert!(userinfo_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/userinfo"])
    ));
    assert!(!userinfo_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(!userinfo_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/fapi/resource"])
    ));
}

#[test]
fn post_body_access_token_accepts_form_content_type_parameters() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        ))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    let UserInfoAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from form body");
    };
    assert_eq!(token, "token-1");
}

#[test]
fn post_body_access_token_rejects_missing_content_type() {
    let req = actix_web::test::TestRequest::post().to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    assert!(matches!(token, UserInfoAccessToken::Missing));
}

#[test]
fn post_body_access_token_rejects_non_form_content_type() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    assert!(matches!(token, UserInfoAccessToken::Missing));
}

#[test]
fn post_body_access_token_rejects_duplicate_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = userinfo_access_token(
        &req,
        &Bytes::from_static(b"access_token=token-1&access_token=token-2"),
    );

    assert!(matches!(token, UserInfoAccessToken::InvalidRequest));
}

#[test]
fn query_access_token_is_not_accepted() {
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo?access_token=query-token")
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::new());

    assert!(matches!(token, UserInfoAccessToken::Missing));
}

#[test]
fn authorization_header_access_token_accepts_single_value() {
    let req = actix_web::test::TestRequest::get()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::new());

    let UserInfoAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from authorization header");
    };
    assert_eq!(token, "header-token");
}

#[test]
fn access_token_rejects_multiple_transport_methods() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=body-token"));

    assert!(matches!(token, UserInfoAccessToken::InvalidRequest));
}

#[test]
fn authorization_header_ignores_non_form_body_access_token_field() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let token = userinfo_access_token(&req, &Bytes::from_static(b"access_token=body-token"));

    let UserInfoAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from authorization header");
    };
    assert_eq!(token, "header-token");
}
