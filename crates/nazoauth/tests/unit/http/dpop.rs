use bytes::Bytes;
use http::{StatusCode, header};
use nazo_auth::DpopReplayAudit;
use nazo_oauth_server::security::dpop::dpop_target_uri;

use super::*;

#[test]
fn header_parser_rejects_duplicate_or_non_utf8_proofs() {
    let duplicate = http::Request::builder()
        .header("DPoP", "proof-1")
        .header("DPoP", "proof-2")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        dpop_proof_header(duplicate.headers()),
        Err(DpopError::MalformedProof)
    );

    let non_utf8 = http::Request::builder()
        .header(
            "DPoP",
            HeaderValue::from_bytes(b"\xff").expect("header bytes"),
        )
        .body(Bytes::new())
        .unwrap();
    assert_eq!(
        dpop_proof_header(non_utf8.headers()),
        Err(DpopError::MalformedProof)
    );
}

#[test]
fn header_parser_distinguishes_absent_blank_and_present_proofs() {
    let absent = http::Request::builder().body(Bytes::new()).unwrap();
    assert_eq!(dpop_proof_header(absent.headers()), Ok(None));
    assert!(!dpop_proof_present(absent.headers()));

    let blank = http::Request::builder()
        .header("DPoP", "  ")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_proof_header(blank.headers()), Ok(None));
    assert!(dpop_proof_present(blank.headers()));

    let present = http::Request::builder()
        .header("DPoP", " proof.jwt ")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_proof_header(present.headers()), Ok(Some("proof.jwt")));
}

#[test]
fn target_uri_selects_only_the_configured_request_origin() {
    for (authority, expected) in [
        (
            Some("ISSUER.example:443"),
            Ok("https://issuer.example/token".to_owned()),
        ),
        (
            Some("mtls.example:8443"),
            Ok("https://mtls.example:8443/token".to_owned()),
        ),
        (Some("mtls.example"), Err(DpopError::InvalidProof)),
        (Some("issuer.example:65536"), Err(DpopError::InvalidProof)),
        (Some("attacker.example"), Err(DpopError::InvalidProof)),
        (Some("user@issuer.example"), Err(DpopError::InvalidProof)),
        (None, Err(DpopError::InvalidProof)),
    ] {
        assert_eq!(
            dpop_target_uri(
                "https://issuer.example/",
                "https://mtls.example:8443/",
                authority,
                "/token"
            ),
            expected
        );
    }
}

#[test]
fn authority_ignores_forwarding_headers_and_rejects_conflicting_targets() {
    let request = http::Request::builder()
        .header("Host", "issuer.example")
        .header("Forwarded", "host=mtls.example;proto=https")
        .header("X-Forwarded-Host", "mtls.example")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_request_authority(&request), Some("issuer.example"));
    let duplicate = http::Request::builder()
        .header("Host", "issuer.example")
        .header("Host", "mtls.example")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_request_authority(&duplicate), None);
    let conflict = http::Request::builder()
        .uri("https://mtls.example/token")
        .header("Host", "issuer.example")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_request_authority(&conflict), None);
    let absolute = http::Request::builder()
        .uri("https://mtls.example/token")
        .body(Bytes::new())
        .unwrap();
    assert_eq!(dpop_request_authority(&absolute), Some("mtls.example"));
}

#[test]
fn token_endpoint_errors_preserve_status_headers_content_type_and_body() {
    let cases = [
        (DpopError::MissingProof, StatusCode::BAD_REQUEST),
        (DpopError::MalformedProof, StatusCode::BAD_REQUEST),
        (
            DpopError::ReplayDetected(DpopReplayAudit {
                jti_hash: "hash".to_owned(),
                key_id: None,
            }),
            StatusCode::BAD_REQUEST,
        ),
        (
            DpopError::StateStoreUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ];
    for (error, expected_status) in cases {
        let response = dpop_error_response(error, DpopErrorContext::TokenEndpoint);
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        let body = response.into_body();
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON error");
        assert!(body["error"].is_string());
        assert!(body["error_description"].is_string());
    }
}

#[test]
fn nonce_challenge_preserves_context_specific_status_and_headers() {
    let token = dpop_error_response(
        DpopError::UseNonce("nonce-1".to_owned()),
        DpopErrorContext::TokenEndpoint,
    );
    assert_eq!(token.status(), StatusCode::BAD_REQUEST);
    assert_eq!(token.headers().get("dpop-nonce").unwrap(), "nonce-1");

    let resource = dpop_error_response(
        DpopError::UseNonce("nonce-1".to_owned()),
        DpopErrorContext::ProtectedResource,
    );
    assert_eq!(resource.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resource.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert!(!resource.headers().contains_key(header::CACHE_CONTROL));
}

#[test]
fn mounted_dpop_target_preserves_external_path_without_double_prefix() {
    let path = "/tenant/auth/openid4vci/offers/one%2Ftwo";
    for (authority, origin) in [
        ("issuer.example", "https://issuer.example"),
        ("mtls.example:8443", "https://mtls.example:8443"),
    ] {
        assert_eq!(
            dpop_target_uri(
                "https://issuer.example/tenant/auth",
                "https://mtls.example:8443/tenant/auth",
                Some(authority),
                path,
            )
            .unwrap(),
            format!("{origin}{path}")
        );
    }
}
