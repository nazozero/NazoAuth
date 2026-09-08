use super::*;

fn valid_context(auth_time: i64) -> nazo_auth::RefreshTokenAuthenticationContext {
    nazo_auth::RefreshTokenAuthenticationContext {
        version: nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION,
        issuer: "https://issuer.example".to_owned(),
        audience: "resource".to_owned(),
        auth_time,
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        id_token_sid: None,
        acr: None,
        nonce: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
    }
}

fn valid_refresh_token() -> NewRefreshToken {
    let issued_at = Utc::now();
    NewRefreshToken {
        raw_token: "refresh".to_owned(),
        tenant_id: Uuid::now_v7(),
        family_id: Uuid::now_v7(),
        rotated_from_id: None,
        lost_response_retry: None,
        client_id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        authorization_details: serde_json::json!([]),
        issued_at,
        expires_at: issued_at + Duration::hours(1),
        subject: "subject".to_owned(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        authentication_context: valid_context(issued_at.timestamp()),
    }
}

#[test]
fn refresh_token_validation_accepts_complete_current_context() {
    let token = valid_refresh_token();
    let value = validate_new_refresh_token(&token).expect("complete refresh token is valid");
    assert_eq!(value["version"], 1);
    assert_eq!(value["audience"], "resource");
}

#[test]
fn refresh_token_validation_rejects_malformed_context_and_audiences() {
    let mut invalid_version = valid_refresh_token();
    invalid_version.authentication_context.version = 2;
    assert!(matches!(
        validate_new_refresh_token(&invalid_version),
        Err(RepositoryError::Consistency(message)) if message.contains("complete current")
    ));

    let mut no_audiences = valid_refresh_token();
    no_audiences.audiences.clear();
    assert!(validate_new_refresh_token(&no_audiences).is_err());

    let mut blank_audience = valid_refresh_token();
    blank_audience.audiences = vec!["  ".to_owned()];
    assert!(validate_new_refresh_token(&blank_audience).is_err());

    let mut future_authentication = valid_refresh_token();
    future_authentication.authentication_context.auth_time =
        future_authentication.issued_at.timestamp() + 1;
    assert!(validate_new_refresh_token(&future_authentication).is_err());

    let mut empty_amr = valid_refresh_token();
    empty_amr.authentication_context.amr.clear();
    assert!(validate_new_refresh_token(&empty_amr).is_err());
}
