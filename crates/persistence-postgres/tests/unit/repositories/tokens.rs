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

        acr: None,

        userinfo_claim_requests: (Vec::new()).into(),
        id_token_claim_requests: (Vec::new()).into(),
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
        .clone(),
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
        .version = nazo_auth::RefreshTokenAuthenticationContext::CURRENT_VERSION + 1;
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
    let expected = contract.clone();
    let prepared = prepare_refresh_contract(&refresh).unwrap().unwrap();
    assert_eq!(
        prepared.contract_value,
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(
        prepared.contract_blake3,
        blake3::hash(&serde_json::to_vec(&expected).unwrap())
            .as_bytes()
            .to_vec()
    );
    assert_eq!(contract, &expected);
}

#[test]
fn refresh_contract_preparation_excludes_response_only_facts() {
    let mut refresh = valid_refresh_token();
    token_mut(&mut refresh).id_token_sid = Some("current-generation-sid".to_owned());
    let prepared = prepare_refresh_contract(&refresh).unwrap().unwrap();
    let context = &prepared.contract_value["authentication_context"];
    assert!(context.get("nonce").is_none());
    assert!(context.get("id_token_sid").is_none());
    assert_eq!(
        refresh.token().unwrap().id_token_sid.as_deref(),
        Some("current-generation-sid")
    );
}

fn ownership_family(contract: &RefreshContract) -> RefreshFamilyRow {
    let now = Utc::now();
    RefreshFamilyRow {
        tenant_id: Uuid::from_u128(1),
        token_family_id: Uuid::from_u128(2),
        client_id: Uuid::from_u128(3),
        user_id: Some(Uuid::from_u128(4)),
        contract_blake3: (*blake3::hash(&serde_json::to_vec(&contract).unwrap()).as_bytes())
            .to_vec(),
        current_member_id: Uuid::from_u128(5),
        current_token_blake3: vec![6; 32],
        current_audience: serde_json::json!(["resource://a"]),
        current_issued_at: now,
        current_expires_at: now + Duration::hours(1),
        current_id_token_sid: Some("generation-sid".into()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
        revoked_at: None,
        reuse_detected_at: None,
    }
}

#[test]
fn ownership_current_moves_original_grant_and_spent_keeps_both_audience_views() {
    let contract = RefreshContract {
        subject: "subject".into(),
        scopes: vec!["openid".into()],
        audiences: vec!["resource://a".into(), "resource://b".into()],
        authorization_details: serde_json::json!([]),
        authentication_context: valid_context(1_700_000_000),
    };
    let family = ownership_family(&contract);
    let spent_contract = contract.clone();
    let original_allocation = contract.audiences.as_ptr();
    let current = token_from_current(family.clone(), contract).unwrap();
    assert_eq!(current.contract_audiences, ["resource://a", "resource://b"]);
    assert_eq!(current.contract_audiences.as_ptr(), original_allocation);
    assert_eq!(current.audience, ["resource://a"]);
    assert_eq!(current.id_token_sid.as_deref(), Some("generation-sid"));
    let spent = SpentRefreshTokenRow {
        refresh_token_blake3: vec![7; 32],
        member_id: Uuid::from_u128(8),
        spent_at: family.current_issued_at,
        expires_at: family.current_expires_at,
    };
    let mut restored = token_from_spent(spent, family, spent_contract).unwrap();
    assert_eq!(
        restored.contract_audiences,
        ["resource://a", "resource://b"]
    );
    assert_eq!(restored.audience, ["resource://a", "resource://b"]);
    restored.audience[0] = "changed".into();
    assert_eq!(
        restored.contract_audiences,
        ["resource://a", "resource://b"]
    );
    assert_eq!(restored.id_token_sid.as_deref(), Some("generation-sid"));
}

#[tokio::test]
async fn ownership_public_uuid_boundary_keeps_consistency_error_before_connection() {
    let pool = crate::create_pool("not-a-database-url", 1).unwrap();
    let repo = TokenRepository::new(pool.clone());
    for tenant_id in ["", "not-a-uuid", "00000000-0000-0000-0000-00000000000g"] {
        let result = repo
            .access_token_state_revoked(RevocationLookupKey {
                tenant_id,
                jti: "jti",
                client_id: "client",
                subject: "subject",
                user_id: None,
                subject_type: Some("client"),
                client_epoch: None,
                user_epoch: None,
            })
            .await;
        assert!(
            matches!(result, Err(RepositoryError::Consistency(message)) if message == "invalid token tenant")
        );
    }
    assert_eq!(pool.status().size, 0);
    for (client_epoch, user_epoch, user_id) in [
        (None, Some(1), None),
        (Some(-1), None, None),
        (Some(1), Some(-1), None),
        (Some(1), Some(1), Some("invalid-user")),
    ] {
        let tenant = Uuid::from_u128(1);
        let text = tenant.to_string();
        assert!(
            repo.access_token_state_revoked(RevocationLookupKey {
                tenant_id: &text,
                jti: "jti",
                client_id: "client",
                subject: "subject",
                user_id,
                subject_type: Some("user"),
                client_epoch,
                user_epoch,
            })
            .await
            .unwrap()
        );
        assert!(
            repo.access_token_state_revoked_typed(TypedRevocationLookupKey {
                tenant_id: tenant,
                jti: "jti",
                client_id: "client",
                subject: "subject",
                user_id,
                subject_type: Some("user"),
                client_epoch,
                user_epoch,
            })
            .await
            .unwrap()
        );
    }
    assert_eq!(pool.status().size, 0);
}

#[test]
fn new_family_requires_current_encoding_and_nonblank_generation_sid() {
    let mut legacy = valid_refresh_token();
    contract_mut(&mut legacy).authentication_context.version = 1;
    assert!(validate_refresh_commit(&legacy).is_err());
    for sid in ["", " "] {
        let mut invalid = valid_refresh_token();
        token_mut(&mut invalid).id_token_sid = Some(sid.into());
        assert!(validate_refresh_commit(&invalid).is_err());
    }
}

#[test]
fn current_refresh_audience_rejects_malformed_json_instead_of_dropping_values() {
    let contract = valid_refresh_token().contract().clone();
    for audience in [
        serde_json::json!(null),
        serde_json::json!("resource"),
        serde_json::json!(["resource", 1]),
        serde_json::json!({"resource": true}),
    ] {
        let mut family = ownership_family(&contract);
        family.current_audience = audience;
        assert!(
            matches!(token_from_current(family, contract.clone()), Err(RepositoryError::Consistency(message)) if message.contains("string array"))
        );
    }
    let current = token_from_current(ownership_family(&contract), contract).unwrap();
    assert_eq!(current.audience, ["resource://a"]);
}
