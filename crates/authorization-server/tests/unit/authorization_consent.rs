use super::*;
use chrono::{Duration, Utc};
use serde_json::json;
fn consent_payload(user_id: Uuid) -> ConsentPayload {
    ConsentPayload {
        request_id: "req-123".to_owned(),
        user_id,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: Some("query".to_owned()),
        nonce: Some("nonce-value".to_owned()),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-secret".to_owned()),
        acr: Some("urn:mace:incommon:iap:silver".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: vec![],
        id_token_claims: vec!["auth_time".to_owned()],
        id_token_claim_requests: vec![],
        code_challenge: Some("challenge-material".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: Some("dpop-binding".to_owned()),
        mtls_x5t_s256: Some("mtls-binding".to_owned()),
        pushed_request_uri: Some("urn:ietf:params:oauth:request_uri:par-1".to_owned()),
        pushed_request_digest: None,
        signed_authorization_response_required: None,
        session_management_allowed: None,
        authorization_code_ttl_seconds: None,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

#[test]
fn missing_or_malformed_consent_state_has_original_error() {
    let OAuthEndpointError::Json(fields) = malformed_or_missing_consent_error() else {
        panic!("consent failure must be JSON");
    };
    assert_eq!(fields.status, StatusCode::BAD_REQUEST);
    assert_eq!(fields.error, "invalid_request");
    assert_eq!(fields.description, "授权请求不存在或已过期,请重新发起授权.");
}

#[test]
fn consent_payload_is_bound_to_current_user() {
    let current_user_id = Uuid::from_u128(0x11111111111111111111111111111111);
    let attacker_user_id = Uuid::from_u128(0x22222222222222222222222222222222);
    let payload = consent_payload(attacker_user_id);
    let OAuthEndpointError::Json(fields) = validate_consent_payload_user(payload, current_user_id)
        .expect_err("payload owned by a different user must be rejected")
    else {
        panic!("mismatched consent must be JSON error");
    };
    assert_eq!(fields.status, StatusCode::FORBIDDEN);
    assert_eq!(fields.error, "access_denied");
    assert_eq!(fields.description, "当前会话与授权请求不匹配.");
}

#[test]
fn matching_consent_payload_user_is_preserved_for_response_building() {
    let current_user_id = Uuid::from_u128(0x33333333333333333333333333333333);
    let payload = consent_payload(current_user_id);
    let validated = validate_consent_payload_user(payload.clone(), current_user_id)
        .expect("matching user should preserve the consent snapshot");
    assert_eq!(validated.request_id, payload.request_id);
    assert_eq!(validated.client_id, payload.client_id);
    assert_eq!(validated.redirect_uri, payload.redirect_uri);
    assert_eq!(validated.scopes, payload.scopes);
}
