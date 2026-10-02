use super::*;

#[test]
fn browser_binding_digest_is_tenant_scoped_and_canonical_hex() {
    let tenant_a = crate::TenantId::new(uuid::Uuid::from_u128(1)).unwrap();
    let tenant_b = crate::TenantId::new(uuid::Uuid::from_u128(2)).unwrap();
    let seed = [7_u8; 32];
    let digest = browser_binding_hash(tenant_a, &seed);
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(digest, browser_binding_hash(tenant_a, &seed));
    assert_ne!(digest, browser_binding_hash(tenant_b, &seed));
    assert_ne!(digest, browser_binding_hash(tenant_a, &[8_u8; 32]));
}

#[test]
fn legacy_state_deserializes_without_inventing_a_browser_binding() {
    let oidc: OidcFederationState = serde_json::from_value(serde_json::json!({
        "nonce": "nonce",
        "pkce_verifier": "verifier",
        "created_at": 1
    }))
    .unwrap();
    let social: SocialFederationState = serde_json::from_value(serde_json::json!({
        "provider_id": "social",
        "pkce_verifier": "verifier",
        "created_at": 1
    }))
    .unwrap();
    assert!(oidc.browser_binding_hash.is_none());
    assert!(social.browser_binding_hash.is_none());
    assert!(
        serde_json::to_value(oidc)
            .unwrap()
            .get("browser_binding_hash")
            .is_none()
    );
    assert!(
        serde_json::to_value(social)
            .unwrap()
            .get("browser_binding_hash")
            .is_none()
    );
}
