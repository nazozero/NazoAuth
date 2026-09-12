use super::*;
use actix_web::body::to_bytes;
use serde_json::Value;

#[actix_web::test]
async fn json_success_is_no_store_and_returns_next_dpop_nonce() {
    let response = userinfo_success_response(UserinfoSuccess {
        representation: UserinfoRepresentation::Claims(serde_json::json!({"sub": "subject"})),
        dpop_nonce: Some("next-nonce".to_owned()),
    });
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(response.headers().get("dpop-nonce").unwrap(), "next-nonce");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body()).await.unwrap()).unwrap(),
        serde_json::json!({"sub": "subject"})
    );
}

#[actix_web::test]
async fn protected_success_keeps_jwt_media_type_and_cache_headers() {
    let response = userinfo_success_response(UserinfoSuccess {
        representation: UserinfoRepresentation::Jwt("signed.jwt".to_owned()),
        dpop_nonce: None,
    });
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/jwt"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(to_bytes(response.into_body()).await.unwrap(), "signed.jwt");
}

#[actix_web::test]
async fn use_dpop_nonce_keeps_challenge_and_nonce_headers() {
    let response = userinfo_error_response(UserinfoError::Dpop(UserinfoDpopError::UseNonce(
        "required-nonce".to_owned(),
    )));
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        "required-nonce"
    );
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["error"], "use_dpop_nonce");
}

#[actix_web::test]
async fn error_mapping_preserves_bearer_status_and_code() {
    let cases = [
        (
            UserinfoError::InvalidAudience,
            StatusCode::UNAUTHORIZED,
            "invalid_token",
        ),
        (
            UserinfoError::InsufficientScope,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
        ),
        (
            UserinfoError::QueryUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
        (
            UserinfoError::ResponseProtectionFailed,
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
        ),
    ];
    for (error, status, error_code) in cases {
        let response = userinfo_error_response(error);
        assert_eq!(response.status(), status);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body["error"], error_code);
    }
}
