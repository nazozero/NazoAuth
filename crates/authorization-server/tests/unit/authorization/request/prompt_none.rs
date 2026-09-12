use super::ConsentPayload;
use chrono::{Duration, Utc};
use nazo_auth::parse_scope;
use serde_json::{Value, json};
use uuid::Uuid;
pub(super) fn stored_grant_covers_requested_authorization(
    stored_scopes: &Value,
    stored_resource_indicators: &Value,
    stored_authorization_details: &Value,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> bool {
    nazo_auth::stored_grant_covers_requested_authorization(
        &nazo_auth::StoredAuthorizationGrant {
            scopes: stored_scopes.clone(),
            resource_indicators: stored_resource_indicators.clone(),
            authorization_details: stored_authorization_details.clone(),
        },
        requested_scopes,
        requested_resource_indicators,
        requested_authorization_details,
    )
}

#[test]
fn stored_grant_covers_prompt_none_request_when_scope_is_subset() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "profile", "email"]),
        &json!([]),
        &json!([]),
        &parse_scope("openid email"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_or_malformed_scope_sets() {
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "profile"]),
        &json!([]),
        &json!([]),
        &parse_scope("openid email"),
        &[],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!({"scope": "openid"}),
        &json!([]),
        &json!([]),
        &parse_scope("openid"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_does_not_cover_new_resource_indicators() {
    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!([
            "https://api.example/accounts",
            "https://api.example/profile"
        ]),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/accounts")],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!(["https://api.example/accounts"]),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/payments")],
        &json!([]),
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "email"]),
        &json!({"resource": "https://api.example/accounts"}),
        &json!([]),
        &parse_scope("openid"),
        &[String::from("https://api.example/accounts")],
        &json!([]),
    ));
}

#[test]
fn stored_grant_treats_empty_requested_authorization_details_as_already_covered() {
    let stored_high_risk_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &json!([]),
        &stored_high_risk_details,
        &parse_scope("openid"),
        &[],
        &json!([]),
    ));
}

#[test]
fn stored_grant_requires_exact_authorization_details_binding() {
    let scopes = json!(["openid", "payments"]);
    let read_details = json!([{"type":"account_information","actions":["read"]}]);
    let different_read_details =
        json!([{"type":"account_information","actions":["read"],"locations":["acct-2"]}]);

    assert!(stored_grant_covers_requested_authorization(
        &scopes,
        &json!([]),
        &read_details,
        &parse_scope("openid payments"),
        &[],
        &read_details,
    ));
    assert!(!stored_grant_covers_requested_authorization(
        &scopes,
        &json!([]),
        &read_details,
        &parse_scope("openid payments"),
        &[],
        &different_read_details,
    ));
}

#[test]
fn stored_grant_never_silently_reuses_high_risk_authorization_details() {
    let payment_details = json!([{
        "type": "payment_initiation",
        "actions": ["write"],
        "instructedAmount": {"currency": "USD", "amount": "10.00"}
    }]);

    assert!(!stored_grant_covers_requested_authorization(
        &json!(["openid", "payments"]),
        &json!([]),
        &payment_details,
        &parse_scope("openid payments"),
        &[],
        &payment_details,
    ));
}

fn prompt_none_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: format!("request-{}", Uuid::now_v7()),
        user_id: Uuid::now_v7(),
        client_id: "client-prompt-none".to_owned(),
        client_name: "Prompt None Client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["sid".to_owned()],
        id_token_claim_requests: Vec::new(),
        code_challenge: Some(crate::crypto::pkce_s256(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        signed_authorization_response_required: Some(false),
        session_management_allowed: Some(false),
        authorization_code_ttl_seconds: Some(60),
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

#[test]
fn prompt_none_preserves_original_private_payload_claims_when_storing_code() {
    use super::issue_authorization_code_without_interaction_with_context;
    use crate::authorization::{AuthorizationOutcome, AuthorizationRequestFacts};
    use crate::test_support::authorization::Fixture;
    use std::sync::atomic::Ordering;
    let fixture = Fixture::new(
        Err(nazo_auth::AuthorizationPortError::Unavailable),
        Ok(None),
    );
    fixture
        .ports
        .record_code_writes
        .store(true, Ordering::SeqCst);
    let application = fixture.make_application();
    let payload = prompt_none_payload();
    let facts = AuthorizationRequestFacts {
        source_ip: "192.0.2.10",
        session_id: None,
        user_agent: None,
    };
    let result =
        futures_executor::block_on(issue_authorization_code_without_interaction_with_context(
            &application.context(),
            &facts,
            payload.clone(),
        ))
        .expect("the normalized private payload issues a code");
    let AuthorizationOutcome::Redirect { location } = result else {
        panic!("query response must redirect")
    };
    let location = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    let code = query.get("code").expect("redirect carries issued code");
    assert_eq!(query.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        query.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(!query.contains_key("error"));
    let writes = fixture.ports.stored_codes.lock().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].hash, crate::crypto::blake3_hex(code));
    assert_eq!(writes[0].ttl_seconds, 60);
    let nazo_auth::AuthorizationCodeState::Pending { payload: stored } = &writes[0].state else {
        panic!("new code must be pending")
    };
    assert_eq!(stored.user_id, payload.user_id);
    assert_eq!(stored.client_id, payload.client_id);
    assert_eq!(stored.scopes, payload.scopes);
    assert_eq!(stored.nonce, payload.nonce);
    assert_eq!(stored.oidc_sid, payload.oidc_sid);
    assert_eq!(stored.id_token_claims, vec!["sid"]);
    assert_eq!(stored.id_token_claims, payload.id_token_claims);
    assert_eq!(stored.userinfo_claims, payload.userinfo_claims);
    assert_eq!((stored.expires_at - stored.issued_at).num_seconds(), 60);
    assert_eq!(fixture.ports.calls(), ["store_authorization_code"]);
}
