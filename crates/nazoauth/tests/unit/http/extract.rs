use bytes::Bytes;
use http::header;

use super::{
    AccessTokenAuthScheme, ResourceAccessToken, request_uses_form_urlencoded, resource_access_token,
};

fn assert_present(
    actual: ResourceAccessToken<'_>,
    expected_scheme: AccessTokenAuthScheme,
    expected_token: &str,
) {
    let ResourceAccessToken::Present(scheme, token) = actual else {
        panic!("expected a presented access token");
    };
    assert_eq!(scheme, expected_scheme);
    assert_eq!(token, expected_token);
}

#[test]
fn form_content_type_is_case_insensitive_and_accepts_parameters() {
    let request = http::Request::builder()
        .header(
            header::CONTENT_TYPE,
            "Application/X-WWW-Form-Urlencoded; charset=utf-8",
        )
        .body(Bytes::new())
        .unwrap();
    assert!(request_uses_form_urlencoded(&request));

    let request = http::Request::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::new())
        .unwrap();
    assert!(!request_uses_form_urlencoded(&request));
}

#[test]
fn access_token_transport_rejects_duplicates_and_signed_form_transport() {
    let request = http::Request::builder()
        .method("POST")
        .header(header::AUTHORIZATION, "Bearer header-token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        super::resource_access_token(&request, b"access_token=body-token", false),
        super::ResourceAccessToken::InvalidRequest
    );

    let request = http::Request::builder()
        .method("POST")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        super::resource_access_token(&request, b"access_token=body-token", true),
        super::ResourceAccessToken::InvalidRequest
    );
}

#[test]
fn bearer_and_dpop_authorization_schemes_are_case_insensitive() {
    for (raw, expected) in [
        ("bearer token", super::AccessTokenAuthScheme::Bearer),
        ("dpop token", super::AccessTokenAuthScheme::DPoP),
    ] {
        let request = http::Request::builder()
            .header(header::AUTHORIZATION, raw)
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            super::authorization_access_token(request.headers()),
            Some((expected, "token"))
        );
    }
}

#[test]
fn form_access_token_accepts_one_value_and_content_type_parameters() {
    for content_type in [
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=utf-8",
    ] {
        let request = http::Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, content_type)
            .body(Bytes::new())
            .unwrap();
        assert_present(
            resource_access_token(&request, b"access_token=token-1", false),
            AccessTokenAuthScheme::Bearer,
            "token-1",
        );
    }
}

#[test]
fn form_access_token_requires_post_and_form_content_type() {
    for request in [
        http::Request::builder()
            .method("POST")
            .body(Bytes::new())
            .unwrap(),
        http::Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Bytes::new())
            .unwrap(),
        http::Request::builder()
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Bytes::new())
            .unwrap(),
    ] {
        assert_eq!(
            resource_access_token(&request, b"access_token=token-1", false),
            ResourceAccessToken::Missing
        );
    }
}

#[test]
fn form_access_token_rejects_duplicates_and_treats_blank_as_missing() {
    let request = http::Request::builder()
        .method("POST")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(
            &request,
            b"access_token=token-1&access_token=token-2",
            false,
        ),
        ResourceAccessToken::InvalidRequest
    );
    assert_eq!(
        resource_access_token(&request, b"access_token=%20%20%09", false),
        ResourceAccessToken::Missing
    );
}

#[test]
fn form_access_token_ignores_unrelated_fields() {
    let request = http::Request::builder()
        .method("POST")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"scope=openid&token_type=Bearer", false),
        ResourceAccessToken::Missing
    );
}

#[test]
fn query_access_token_is_not_a_supported_transport() {
    let request = http::Request::builder()
        .uri("/resource?access_token=query-token")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, &[], false),
        ResourceAccessToken::Missing
    );
}

#[test]
fn authorization_header_wins_only_when_form_transport_is_absent() {
    let request = http::Request::builder()
        .method("POST")
        .header(header::AUTHORIZATION, "Bearer header-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Bytes::new())
        .unwrap();
    assert_present(
        resource_access_token(&request, b"access_token=body-token", false),
        AccessTokenAuthScheme::Bearer,
        "header-token",
    );

    let request = http::Request::builder()
        .method("POST")
        .header(header::AUTHORIZATION, "Bearer header-token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"access_token=body-token", false),
        ResourceAccessToken::InvalidRequest
    );
}

#[test]
fn bearer_transport_rejects_blank_first_duplicates_and_mixed_query_without_changing_query_only() {
    for header in [None, Some("Bearer header-token")] {
        let mut builder = http::Request::builder()
            .method("POST")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = header {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let request = builder.body(Bytes::new()).unwrap();
        for body in [
            b"access_token=&access%5Ftoken=second".as_slice(),
            b"access_token=first&access_token=",
            b"access_token=&access_token=",
        ] {
            assert_eq!(
                resource_access_token(&request, body, false),
                ResourceAccessToken::InvalidRequest
            );
            assert_eq!(
                resource_access_token(&request, body, true),
                ResourceAccessToken::InvalidRequest
            );
        }
    }
    let request = http::Request::builder()
        .uri("/userinfo?access%5Ftoken=query-value")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"", false),
        ResourceAccessToken::Missing
    );
    let request = http::Request::builder()
        .uri("/userinfo?access%5Ftoken=query-value")
        .header(header::AUTHORIZATION, "Bearer header-token")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"", false),
        ResourceAccessToken::InvalidRequest
    );
    let request = http::Request::builder()
        .method("POST")
        .uri("/userinfo?access_token=query-value")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"access_token=body-token", false),
        ResourceAccessToken::InvalidRequest
    );
    let request = http::Request::builder()
        .header(header::AUTHORIZATION, "Bearer first")
        .header(header::AUTHORIZATION, "Bearer second")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        resource_access_token(&request, b"", false),
        ResourceAccessToken::InvalidRequest
    );
}
