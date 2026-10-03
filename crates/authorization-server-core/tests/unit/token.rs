use super::RefreshTokenAuthenticationContext;

#[test]
fn authentication_context_accepts_only_the_current_version() {
    let context = RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: "client-1".to_owned(),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        id_token_sid: Some("sid".to_owned()),
        acr: Some("1".to_owned()),
        nonce: Some("nonce".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: Vec::new(),
        id_token_claims: vec!["email".to_owned()],
        id_token_claim_requests: Vec::new(),
    };
    assert!(context.is_well_formed());
    let unsupported = RefreshTokenAuthenticationContext {
        version: RefreshTokenAuthenticationContext::CURRENT_VERSION + 1,
        ..context
    };
    assert!(!unsupported.is_supported_version());
}

#[test]
fn public_unbound_refresh_proofs_are_retained_until_token_expiry() {
    use super::{MAX_SPENT_PROOFS_PER_REFRESH_FAMILY, refresh_spent_proof_limit};

    assert_eq!(refresh_spent_proof_limit("public", None, None), None);
    assert_eq!(refresh_spent_proof_limit("unknown", None, None), None);
    for client_type in ["public", "confidential"] {
        for (dpop, mtls) in [(Some("dpop"), None), (None, Some("mtls"))] {
            assert_eq!(
                refresh_spent_proof_limit(client_type, dpop, mtls),
                Some(MAX_SPENT_PROOFS_PER_REFRESH_FAMILY)
            );
        }
    }
    assert_eq!(
        refresh_spent_proof_limit("confidential", None, None),
        Some(MAX_SPENT_PROOFS_PER_REFRESH_FAMILY)
    );
}

#[test]
fn refresh_authority_keeps_the_immutable_contract_and_generation_sid_separate() {
    use super::{RefreshContract, RefreshToken};
    let now = chrono::Utc::now();
    let token = RefreshToken {
        id: uuid::Uuid::now_v7(),
        token_blake3: [1; 32],
        tenant_id: uuid::Uuid::now_v7(),
        token_family_id: uuid::Uuid::now_v7(),
        client_id: uuid::Uuid::now_v7(),
        user_id: Some(uuid::Uuid::now_v7()),
        contract_key: [2; 32],
        contract_audiences: vec!["original-resource".to_owned()],
        scopes: serde_json::json!(["openid", "offline_access"]),
        audience: serde_json::json!(["narrowed-resource"]),
        authorization_details: serde_json::json!([{"type": "account_information"}]),
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        revoked_at: None,
        subject: "pairwise-subject".to_owned(),
        dpop_jkt: Some("source-jkt".to_owned()),
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: RefreshTokenAuthenticationContext {
            version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
            issuer: "https://issuer.example".to_owned(),
            audience: "client".to_owned(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_owned()],
            oidc_sid: Some("oidc-sid".to_owned()),
            id_token_sid: Some("current-id-token-sid".to_owned()),
            acr: Some("1".to_owned()),
            nonce: Some("first-response-nonce".to_owned()),
            userinfo_claims: vec!["email".to_owned()],
            userinfo_claim_requests: Vec::new(),
            id_token_claims: vec!["email".to_owned()],
            id_token_claim_requests: Vec::new(),
        },
    };
    let expected = RefreshContract {
        subject: token.subject.clone(),
        scopes: crate::string_array_values(&token.scopes),
        audiences: token.contract_audiences.clone(),
        authorization_details: token.authorization_details.clone(),
        authentication_context: token.authentication_context.clone(),
    }
    .persisted();
    let authority = token.authority();
    assert_eq!(authority.contract, expected);
    assert_eq!(
        authority.contract.canonical_bytes(),
        expected.canonical_bytes()
    );
    assert_eq!(authority.contract_key, [2; 32]);
    assert_eq!(authority.current_audiences, vec!["narrowed-resource"]);
    assert_eq!(
        authority.id_token_sid.as_deref(),
        Some("current-id-token-sid")
    );
    assert_eq!(
        token.authentication_context.nonce.as_deref(),
        Some("first-response-nonce")
    );
    assert_eq!(
        token.authentication_context.id_token_sid.as_deref(),
        Some("current-id-token-sid")
    );
}
