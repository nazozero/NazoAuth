use super::*;
use crate::domain::ConfirmationClaims;

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://as.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "client".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 2,
        cnf,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

#[test]
fn access_token_introspection_type_matches_issued_bearer_token_type() {
    assert_eq!(
        introspection_access_token_type(&access_claims(None)),
        "Bearer"
    );
}

#[test]
fn access_token_introspection_type_matches_issued_dpop_token_type() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: Some("thumbprint".to_owned()),
        x5t_s256: None,
    }));

    assert_eq!(introspection_access_token_type(&claims), "DPoP");
}

#[test]
fn mtls_bound_access_token_introspection_type_remains_bearer() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("certificate-thumbprint".to_owned()),
    }));

    assert_eq!(introspection_access_token_type(&claims), "Bearer");
}

#[test]
fn refresh_token_introspection_metadata_omits_access_token_type() {
    let issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let token = TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: None,
        scopes: json!(["openid", "offline_access"]),
        authorization_details: json!([]),
        issued_at,
        expires_at: issued_at + Duration::days(30),
        revoked_at: None,
        subject: "subject".to_owned(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };

    let body = active_refresh_token_introspection_body(&token, "client-1");

    assert_eq!(body.get("active"), Some(&json!(true)));
    assert_eq!(body.get("client_id"), Some(&json!("client-1")));
    assert_eq!(body.get("scope"), Some(&json!("openid offline_access")));
    assert_eq!(
        body.get("exp"),
        Some(&json!(issued_at.timestamp() + 30 * 24 * 60 * 60))
    );
    assert_eq!(body.get("iat"), Some(&json!(issued_at.timestamp())));
    assert_eq!(body.get("sub"), Some(&json!("subject")));
    assert!(!body.as_object().unwrap().contains_key("token_type"));
    assert!(!body.as_object().unwrap().contains_key("jti"));
}
