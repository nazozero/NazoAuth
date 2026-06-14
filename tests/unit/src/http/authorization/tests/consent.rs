use super::*;

fn consent_payload(user_id: Uuid) -> ConsentPayload {
    ConsentPayload {
        request_id: "req-123".to_owned(),
        user_id,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        authorization_details: json!({"type": "payment", "amount": "100.00"}),
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
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

#[test]
fn missing_or_malformed_consent_payload_fails_closed() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":"req-123"}"#.to_owned())).is_none());
}

#[actix_web::test]
async fn missing_consent_state_returns_protocol_invalid_request_without_tokens() {
    let (status, body) = response_json(malformed_or_missing_consent_response()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert_ne!(
        body["error_description"],
        "授权请求不存在或已过期,请重新发起授权."
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn consent_payload_is_bound_to_current_user() {
    let current_user_id = uuid_fixture(0x11111111111111111111111111111111);
    let attacker_user_id = uuid_fixture(0x22222222222222222222222222222222);
    let payload = consent_payload(attacker_user_id);

    let err = validate_consent_payload_user(payload, current_user_id)
        .expect_err("payload owned by a different user must be rejected");
    let (status, body) = response_json(err).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "Request failed.");
    assert_ne!(body["error_description"], "当前会话与授权请求不匹配.");
    assert!(body.get("client_id").is_none());
    assert!(body.get("redirect_uri").is_none());
    assert!(body.get("request_id").is_none());
}

#[test]
fn matching_consent_payload_user_is_preserved_for_response_building() {
    let current_user_id = uuid_fixture(0x33333333333333333333333333333333);
    let payload = consent_payload(current_user_id);

    let validated = validate_consent_payload_user(payload.clone(), current_user_id)
        .expect("matching user should preserve the consent snapshot");

    assert_eq!(validated.request_id, payload.request_id);
    assert_eq!(validated.client_id, payload.client_id);
    assert_eq!(validated.redirect_uri, payload.redirect_uri);
    assert_eq!(validated.scopes, payload.scopes);
}

#[actix_web::test]
async fn consent_page_response_exposes_only_page_safe_fields() {
    let payload = consent_payload(uuid_fixture(0x44444444444444444444444444444444));

    let (status, body) = response_json(consent_page_response(
        payload,
        Some("csrf-token".to_owned()),
    ))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["request_id"], "req-123");
    assert_eq!(body["client_id"], "client-a");
    assert_eq!(body["client_name"], "Client A");
    assert_eq!(body["redirect_uri"], "https://client.example/callback");
    assert_eq!(body["scopes"], json!(["openid", "profile"]));
    assert_eq!(body["csrf_token"], "csrf-token");

    let object = body
        .as_object()
        .expect("consent response should be an object");
    assert_eq!(object.len(), 6);
    for forbidden in [
        "user_id",
        "authorization_details",
        "state",
        "nonce",
        "auth_time",
        "amr",
        "oidc_sid",
        "acr",
        "code_challenge",
        "code_challenge_method",
        "dpop_jkt",
        "mtls_x5t_s256",
        "pushed_request_uri",
        "issued_at",
        "expires_at",
    ] {
        assert!(
            object.get(forbidden).is_none(),
            "{forbidden} must not be exposed to the browser consent page"
        );
    }
}
