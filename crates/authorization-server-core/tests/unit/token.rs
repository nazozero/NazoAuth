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
