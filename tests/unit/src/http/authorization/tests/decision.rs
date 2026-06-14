use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset};

fn decision_state() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.auth_code_ttl_seconds = 60;

    AppState {
        diesel_db: create_pool(
            "postgres://nazo_authorize_test_invalid:nazo_authorize_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: Arc::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn consent_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: "request-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        redirect_uri: "https://client.example/callback?existing=1".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn redirect_location(response: &HttpResponse) -> url::Url {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization response should redirect")
        .to_str()
        .expect("Location header should be valid UTF-8");
    url::Url::parse(location).expect("redirect location should remain absolute")
}

#[test]
fn authorization_decision_is_explicit_allowlist() {
    assert!(matches!(
        parse_authorization_decision("approve"),
        Some(AuthorizationDecision::Approve)
    ));
    assert!(matches!(
        parse_authorization_decision("deny"),
        Some(AuthorizationDecision::Deny)
    ));
    assert!(parse_authorization_decision("anything-else").is_none());
    assert!(parse_authorization_decision(" approve ").is_none());
}

#[test]
fn missing_or_malformed_consent_payload_is_rejected() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":1}"#.to_owned())).is_none());
}

#[actix_web::test]
async fn denied_authorization_redirect_preserves_state_without_issuing_code() {
    let state = decision_state();
    let payload = consent_payload();
    let response = authorization_error_redirect(&state, &payload, "access_denied").await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        parsed.as_str().split('?').next(),
        Some("https://client.example/callback")
    );
    assert_eq!(pairs.get("existing").map(String::as_str), Some("1"));
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("code"),
        "authorization denial must never include an authorization code"
    );
}

#[actix_web::test]
async fn approved_authorization_redirect_omits_error_and_carries_only_the_new_code() {
    let state = decision_state();
    let response = authorization_response_redirect(
        &state,
        "https://client.example/callback",
        "client-1",
        None,
        Some("code-1"),
        None,
        Some("opaque-state"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(pairs.get("code").map(String::as_str), Some("code-1"));
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("error"),
        "successful authorization redirect must not include stale error state"
    );
}
