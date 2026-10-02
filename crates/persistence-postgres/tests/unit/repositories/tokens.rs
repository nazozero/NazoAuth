use super::*;
use nazo_auth::NewRefreshToken;

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

fn valid_refresh_token() -> nazo_auth::RefreshTokenCommit {
    let issued_at = Utc::now();
    nazo_auth::RefreshTokenCommit::IssueNew {
        token: NewRefreshToken {
            raw_token: "refresh".to_owned(),
            member_id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            family_id: Uuid::now_v7(),
            rotated_from_id: None,
            lost_response_retry: None,
            client_id: Uuid::now_v7(),
            user_id: Some(Uuid::now_v7()),
            audiences: vec!["resource".to_owned()],
            issued_at,
            expires_at: issued_at + Duration::hours(1),
            dpop_jkt: None,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
            id_token_sid: None,
        },
        contract: nazo_auth::RefreshContract {
            scopes: vec!["openid".to_owned()],
            audiences: vec!["resource".to_owned()],
            authorization_details: serde_json::json!([]),
            subject: "subject".to_owned(),
            authentication_context: valid_context(issued_at.timestamp()),
        }
        .persisted(),
    }
}

#[test]
fn refresh_token_validation_accepts_complete_current_context() {
    let token = valid_refresh_token();
    validate_refresh_commit(&token).expect("complete refresh token is valid");
}

#[test]
fn refresh_token_validation_rejects_malformed_context_and_audiences() {
    let mut invalid_version = valid_refresh_token();
    contract_mut(&mut invalid_version)
        .authentication_context
        .version = 2;
    assert!(matches!(
        validate_refresh_commit(&invalid_version),
        Err(RepositoryError::Consistency(message)) if message.contains("complete immutable")
    ));

    let mut no_audiences = valid_refresh_token();
    token_mut(&mut no_audiences).audiences.clear();
    assert!(validate_refresh_commit(&no_audiences).is_err());

    let mut blank_audience = valid_refresh_token();
    token_mut(&mut blank_audience).audiences = vec!["  ".to_owned()];
    assert!(validate_refresh_commit(&blank_audience).is_err());

    let mut future_authentication = valid_refresh_token();
    let future_time = token_mut(&mut future_authentication).issued_at.timestamp() + 1;
    contract_mut(&mut future_authentication)
        .authentication_context
        .auth_time = future_time;
    assert!(validate_refresh_commit(&future_authentication).is_err());

    let mut empty_amr = valid_refresh_token();
    contract_mut(&mut empty_amr)
        .authentication_context
        .amr
        .clear();
    assert!(validate_refresh_commit(&empty_amr).is_err());
}

#[test]
fn refresh_family_lock_key_is_the_shared_high_xor_low_formula() {
    // The maintenance reclaim must try-lock exactly the key writers take with
    // pg_advisory_xact_lock; a divergent formula would open a second lock
    // domain and allow a cleanup to race an in-flight rotation.
    let family_id =
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").expect("uuid should parse");
    let expected = 0x0011_2233_4455_6677_i64 ^ 0x8899_aabb_ccdd_eeff_u64 as i64;
    assert_eq!(refresh_family_lock_key(family_id), expected);
    assert_eq!(refresh_family_lock_key(Uuid::nil()), 0);
    assert_eq!(refresh_family_lock_key(Uuid::from_u128(u128::MAX)), 0);
}

fn token_mut(refresh: &mut nazo_auth::RefreshTokenCommit) -> &mut NewRefreshToken {
    let nazo_auth::RefreshTokenCommit::IssueNew { token, .. } = refresh else {
        unreachable!()
    };
    token
}
fn contract_mut(refresh: &mut nazo_auth::RefreshTokenCommit) -> &mut nazo_auth::RefreshContract {
    let nazo_auth::RefreshTokenCommit::IssueNew { contract, .. } = refresh else {
        unreachable!()
    };
    contract
}

#[test]
fn refresh_contract_preparation_preserves_the_original_canonical_digest() {
    let mut refresh = valid_refresh_token();
    contract_mut(&mut refresh).authorization_details = serde_json::json!([
        {"type": "account_information", "locations": ["https://resource.example"], "actions": ["read"]}
    ]);
    let contract = refresh.contract();
    let expected = contract.persisted();
    let prepared = prepare_refresh_contract(&refresh).unwrap().unwrap();
    assert_eq!(prepared.contract_value, serde_json::to_value(&expected).unwrap());
    assert_eq!(prepared.contract_blake3, expected.blake3_digest().to_vec());
    assert_eq!(contract.canonical_bytes(), expected.canonical_bytes());
}

#[test]
fn refresh_contract_preparation_rejects_each_nonpersistent_context_field() {
    for nonce in [true, false] {
        let mut refresh = valid_refresh_token();
        let context = &mut contract_mut(&mut refresh).authentication_context;
        if nonce {
            context.nonce = Some("first-response-nonce".to_owned());
        } else {
            context.id_token_sid = Some("current-generation-sid".to_owned());
        }
        assert!(prepare_refresh_contract(&refresh).is_err());
    }
}
