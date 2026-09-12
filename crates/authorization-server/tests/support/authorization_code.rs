use super::TokenForm;
use chrono::{Duration, Utc};
use nazo_auth::CodePayload;
use serde_json::json;
use uuid::Uuid;

pub(super) const VALID_CODE_VERIFIER: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

pub(super) fn code_payload(redirect_uri_was_supplied: bool) -> CodePayload {
    let now = Utc::now();
    CodePayload {
        code_id: "code-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        nonce: None,
        auth_time: now.timestamp(),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: now,
        expires_at: now + Duration::seconds(300),
    }
}

pub(super) fn form_for_code(code: &str) -> TokenForm {
    TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some(code.to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: Some("https://client.example/callback".to_owned()),
        code_verifier: Some(VALID_CODE_VERIFIER.to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    }
}
