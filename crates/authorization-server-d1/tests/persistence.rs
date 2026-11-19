#![cfg(feature = "local-sqlite")]
mod support;
use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
    AuthorizationRepositoryPort, CommitTokenIssuance, CommitTokenIssuanceResult, NewRefreshToken,
    RefreshContract, RefreshTokenAuthenticationContext, RefreshTokenCommit, TokenIssuanceMode,
    TokenIssuedAuditFields, TokenPrincipalState, TokenRepositoryPort,
};
use serde_json::json;
use std::sync::{Arc, Barrier};
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

fn token(mode: TokenIssuanceMode, refresh: Option<RefreshTokenCommit>) -> CommitTokenIssuance {
    let issuance_id = Uuid::new_v4();
    CommitTokenIssuance {
        authorization_id: Some(
            refresh
                .as_ref()
                .map(RefreshTokenCommit::family_id)
                .unwrap_or(issuance_id),
        ),
        principal_state: TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: USER.to_string(),
        issuance_id,
        tenant_id: TENANT,
        client_id: CLIENT,
        user_id: Some(USER),
        mode,
        access_token_jti: Uuid::new_v4().to_string(),
        access_token_expires_at: (Timestamp::now() + SignedDuration::from_secs(600)).as_second(),
        refresh_token: refresh,
        native_sso_source: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: "client".into(),
            subject_hash: "subject".into(),
            scope: "openid".into(),
            audience: vec!["https://api.example".into()],
        },
    }
}
fn code(identity: &str) -> TokenIssuanceMode {
    TokenIssuanceMode::AuthorizationCode {
        code_identity: format!("authorization_code:v2:{identity}"),
        grant_expires_at: Timestamp::now() + SignedDuration::from_secs(300),
        holder: nazo_auth::AuthorizationCodeHolderEvidence::from_verified_requirements(
            nazo_auth::AuthorizationCodeClientAuthentication::Public,
            Some("pkce".into()),
            None,
            None,
            None,
        )
        .unwrap(),
    }
}
fn refresh(raw: &str, family_id: Uuid) -> NewRefreshToken {
    let now = Timestamp::now();
    NewRefreshToken {
        raw_token: raw.into(),
        member_id: Uuid::new_v4(),
        tenant_id: TENANT,
        family_id,
        rotated_from_id: None,
        lost_response_retry: None,
        client_id: CLIENT,
        user_id: Some(USER),
        audiences: vec!["https://api.example".into()],
        issued_at: now,
        expires_at: now + SignedDuration::from_secs(3600),
        id_token_sid: Some("id-token-session".into()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        client_attestation_jkt: None,
    }
}
fn contract() -> RefreshContract {
    RefreshContract {
        subject: USER.to_string(),
        scopes: vec!["openid".into(), "offline_access".into()],
        audiences: vec!["https://api.example".into()],
        authorization_details: json!([]),
        authentication_context: RefreshTokenAuthenticationContext {
            version: 2,
            issuer: "https://issuer.example".into(),
            audience: "client".into(),
            auth_time: Timestamp::now().as_second(),
            amr: vec!["pwd".into()],
            oidc_sid: Some("session".into()),
            acr: None,
            userinfo_claim_requests: Default::default(),
            id_token_claim_requests: Default::default(),
        },
    }
}
fn decision(request: &str) -> AuthorizationDecisionCommit {
    let now = Timestamp::now();
    AuthorizationDecisionCommit {
        tenant_id: TENANT,
        user_id: USER,
        client_id: "client".into(),
        request_id: request.into(),
        pushed_request_uri: Some("urn:request:test".into()),
        valid_until: now + SignedDuration::from_secs(60),
        retain_until: now + SignedDuration::from_secs(600),
        decision: AuthorizationDecisionKind::Approve,
        event_id: Uuid::new_v4(),
        occurred_at: now,
        audit_fields: json!({"decision":"approve"}),
        scopes: vec!["openid".into()],
        resource_indicators: vec!["https://api.example".into()],
        authorization_details: json!([]),
    }
}

#[test]
fn single_use_commit_has_one_winner_under_concurrency() {
    let (_, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(24));
    let tasks = (0..24)
        .map(|_| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.commit_token_issuance(token(code("race"), None))).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let outcomes = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == CommitTokenIssuanceResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == CommitTokenIssuanceResult::AlreadyUsed)
            .count(),
        23
    );
    let receipt =
        block_on(provider.single_use_redemption(TENANT, CLIENT, "authorization_code:v2:race"))
            .unwrap()
            .unwrap();
    assert!(receipt.authorization_code_holder.is_some());
}
#[test]
fn audit_failure_rolls_back_code_fence_and_refresh_family() {
    block_on(async {
        let (database, provider) = fixture().await;
        database.execute_sql("CREATE TRIGGER reject_required_audit BEFORE INSERT ON nazo_audit BEGIN SELECT RAISE(ABORT,'unavailable'); END;").unwrap();
        let family = Uuid::new_v4();
        let input = token(
            code("failed"),
            Some(RefreshTokenCommit::IssueNew {
                token: refresh("secret", family),
                contract: contract(),
            }),
        );
        assert!(provider.commit_token_issuance(input).await.is_err());
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:failed")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .refresh_token(TENANT, "secret")
                .await
                .unwrap()
                .is_none()
        );
        database
            .execute_sql("DROP TRIGGER reject_required_audit")
            .unwrap();
        assert_eq!(
            provider
                .commit_token_issuance(token(code("failed"), None))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
    })
}
#[test]
fn inactive_and_stale_principals_cannot_commit() {
    block_on(async {
        let (database, provider) = fixture().await;
        let mut input = token(code("stale"), None);
        input.principal_state.client_epoch = 1;
        assert_eq!(
            provider.commit_token_issuance(input).await.unwrap(),
            CommitTokenIssuanceResult::ClientInactive
        );
        database
            .execute_sql("UPDATE nazo_users SET epoch=1")
            .unwrap();
        assert_eq!(
            provider
                .commit_token_issuance(token(code("stale"), None))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::SubjectInactive
        );
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:stale")
                .await
                .unwrap()
                .is_none()
        );
    })
}
#[test]
fn expired_code_does_not_leave_receipt() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut mode = code("expired");
        if let TokenIssuanceMode::AuthorizationCode {
            grant_expires_at, ..
        } = &mut mode
        {
            *grant_expires_at = Timestamp::now() - SignedDuration::from_secs(1);
        }
        assert_eq!(
            provider
                .commit_token_issuance(token(mode, None))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::GrantExpired
        );
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:expired")
                .await
                .unwrap()
                .is_none()
        );
    })
}
#[test]
fn rotation_preserves_contract_and_reuse_revokes_family() {
    block_on(async {
        let (_, provider) = fixture().await;
        let family = Uuid::new_v4();
        let original = refresh("original", family);
        assert_eq!(
            provider
                .commit_token_issuance(token(
                    code("new"),
                    Some(RefreshTokenCommit::IssueNew {
                        token: original,
                        contract: contract()
                    })
                ))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let source = provider
            .refresh_token(TENANT, "original")
            .await
            .unwrap()
            .unwrap();
        let mut successor = refresh("successor", family);
        successor.rotated_from_id = Some(source.id);
        let input = token(
            TokenIssuanceMode::Fresh,
            Some(RefreshTokenCommit::UseExisting {
                authority: source.authority(),
                rotation: Some(successor),
            }),
        );
        assert_eq!(
            provider.commit_token_issuance(input.clone()).await.unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let next = provider
            .refresh_token(TENANT, "successor")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(next.contract, source.contract);
        assert_eq!(next.contract_key, source.contract_key);
        let mut duplicate = input;
        duplicate.issuance_id = Uuid::new_v4();
        duplicate.access_token_jti = Uuid::new_v4().to_string();
        assert_eq!(
            provider.commit_token_issuance(duplicate).await.unwrap(),
            CommitTokenIssuanceResult::RotationConflict
        );
        assert!(
            provider
                .refresh_token(TENANT, "successor")
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            !provider
                .refresh_family_active(TENANT, family, USER)
                .await
                .unwrap()
        );
    })
}
#[test]
fn sender_bound_lost_response_retry_checks_direct_edge() {
    block_on(async {
        let (_, provider) = fixture().await;
        let family = Uuid::new_v4();
        let mut original = refresh("first", family);
        original.dpop_jkt = Some("holder".into());
        provider
            .commit_token_issuance(token(
                code("retry"),
                Some(RefreshTokenCommit::IssueNew {
                    token: original,
                    contract: contract(),
                }),
            ))
            .await
            .unwrap();
        let source = provider
            .refresh_token(TENANT, "first")
            .await
            .unwrap()
            .unwrap();
        let mut second = refresh("second", family);
        second.rotated_from_id = Some(source.id);
        second.dpop_jkt = source.dpop_jkt.clone();
        provider
            .commit_token_issuance(token(
                TokenIssuanceMode::Fresh,
                Some(RefreshTokenCommit::UseExisting {
                    authority: source.authority(),
                    rotation: Some(second),
                }),
            ))
            .await
            .unwrap();
        let started = Timestamp::now();
        let snapshot = provider
            .refresh_token_snapshot(TENANT, "first", CLIENT, started, false)
            .await
            .unwrap()
            .unwrap();
        let successor = snapshot.successor.unwrap().unwrap();
        let mut third = refresh("third", family);
        third.rotated_from_id = Some(successor.id);
        third.dpop_jkt = successor.dpop_jkt.clone();
        third.lost_response_retry = Some(nazo_auth::LostResponseRetry {
            original_id: source.id,
            original_blake3: source.token_blake3,
            retry_started_at: started,
        });
        assert_eq!(
            provider
                .commit_token_issuance(token(
                    TokenIssuanceMode::Fresh,
                    Some(RefreshTokenCommit::UseExisting {
                        authority: successor.authority(),
                        rotation: Some(third)
                    })
                ))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        assert!(
            provider
                .refresh_token_snapshot(TENANT, "first", CLIENT, Timestamp::now(), false)
                .await
                .unwrap()
                .unwrap()
                .successor
                .unwrap()
                .is_none()
        );
    })
}
#[test]
fn unbound_public_spent_proof_survives_more_than_sixty_four_rotations() {
    block_on(async {
        let (_, provider) = fixture().await;
        let family = Uuid::new_v4();
        provider
            .commit_token_issuance(token(
                code("history"),
                Some(RefreshTokenCommit::IssueNew {
                    token: refresh("generation-0", family),
                    contract: contract(),
                }),
            ))
            .await
            .unwrap();
        for generation in 1..=70 {
            let source = provider
                .refresh_token(TENANT, &format!("generation-{}", generation - 1))
                .await
                .unwrap()
                .unwrap();
            let mut next = refresh(&format!("generation-{generation}"), family);
            next.rotated_from_id = Some(source.id);
            assert_eq!(
                provider
                    .commit_token_issuance(token(
                        TokenIssuanceMode::Fresh,
                        Some(RefreshTokenCommit::UseExisting {
                            authority: source.authority(),
                            rotation: Some(next)
                        })
                    ))
                    .await
                    .unwrap(),
                CommitTokenIssuanceResult::Committed
            );
        }
        assert!(
            provider
                .refresh_token(TENANT, "generation-0")
                .await
                .unwrap()
                .is_some()
        );
    })
}
#[test]
fn decision_and_par_consumption_have_one_winner() {
    let (_, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(16));
    let tasks = (0..16)
        .map(|index| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.commit_decision(decision(&format!("request-{index}")))).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == AuthorizationDecisionCommitResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == AuthorizationDecisionCommitResult::Conflict)
            .count(),
        15
    );
}
#[test]
fn prompt_none_requires_current_grant_coverage() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut input = decision("quiet");
        input.decision = AuthorizationDecisionKind::PromptNone;
        assert_eq!(
            provider.commit_decision(input.clone()).await.unwrap(),
            AuthorizationDecisionCommitResult::GrantUnavailable
        );
        let mut approval = decision("approval");
        approval.pushed_request_uri = None;
        assert_eq!(
            provider.commit_decision(approval).await.unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        assert_eq!(
            provider.commit_decision(input).await.unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let mut broader = decision("broad");
        broader.pushed_request_uri = None;
        broader.decision = AuthorizationDecisionKind::PromptNone;
        broader.scopes.push("email".into());
        assert_eq!(
            provider.commit_decision(broader).await.unwrap(),
            AuthorizationDecisionCommitResult::GrantUnavailable
        );
    })
}
#[test]
fn tenant_mismatch_is_rejected_before_writes() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut input = token(code("other"), None);
        input.tenant_id = Uuid::new_v4();
        assert!(provider.commit_token_issuance(input).await.is_err());
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:other")
                .await
                .unwrap()
                .is_none()
        );
    })
}

#[test]
fn mismatched_family_owner_cannot_revoke_another_clients_family() {
    block_on(async {
        let (database, provider) = fixture().await;
        let family = Uuid::new_v4();
        provider
            .commit_token_issuance(token(
                code("owner"),
                Some(RefreshTokenCommit::IssueNew {
                    token: refresh("owned", family),
                    contract: contract(),
                }),
            ))
            .await
            .unwrap();
        let source = provider
            .refresh_token(TENANT, "owned")
            .await
            .unwrap()
            .unwrap();
        database
            .execute_sql(
                "UPDATE nazo_refresh_families SET client_id='00000000-0000-0000-0000-000000000099'",
            )
            .unwrap();
        let mut next = refresh("unrelated", family);
        next.rotated_from_id = Some(source.id);
        assert_eq!(
            provider
                .commit_token_issuance(token(
                    TokenIssuanceMode::Fresh,
                    Some(RefreshTokenCommit::UseExisting {
                        authority: source.authority(),
                        rotation: Some(next)
                    })
                ))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::RefreshGrantUnavailable
        );
        assert!(
            provider
                .refresh_token(TENANT, "owned")
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
    })
}
#[test]
fn audit_failure_rolls_back_refresh_compromise() {
    block_on(async {
        let (database, provider) = fixture().await;
        let family = Uuid::new_v4();
        provider
            .commit_token_issuance(token(
                code("revoke-failure"),
                Some(RefreshTokenCommit::IssueNew {
                    token: refresh("first", family),
                    contract: contract(),
                }),
            ))
            .await
            .unwrap();
        let source = provider
            .refresh_token(TENANT, "first")
            .await
            .unwrap()
            .unwrap();
        let mut second = refresh("second", family);
        second.rotated_from_id = Some(source.id);
        provider
            .commit_token_issuance(token(
                TokenIssuanceMode::Fresh,
                Some(RefreshTokenCommit::UseExisting {
                    authority: source.authority(),
                    rotation: Some(second),
                }),
            ))
            .await
            .unwrap();
        database.execute_sql("CREATE TRIGGER reject_reuse_audit BEFORE INSERT ON nazo_audit WHEN NEW.event_type='refresh_reuse_detected' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END").unwrap();
        let mut late = refresh("late", family);
        late.rotated_from_id = Some(source.id);
        assert!(
            provider
                .commit_token_issuance(token(
                    TokenIssuanceMode::Fresh,
                    Some(RefreshTokenCommit::UseExisting {
                        authority: source.authority(),
                        rotation: Some(late)
                    })
                ))
                .await
                .is_err()
        );
        assert!(
            provider
                .refresh_token(TENANT, "second")
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
    })
}
#[test]
fn family_capacity_retires_oldest_within_scope() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut families = Vec::new();
        for index in 0..11 {
            let family = Uuid::from_u128(100 + index);
            let mut next = refresh(&format!("capacity-{index}"), family);
            next.issued_at = Timestamp::now() - SignedDuration::from_secs(100 - index as i64);
            let mut original_contract = contract();
            original_contract.authentication_context.auth_time = next.issued_at.as_second();
            families.push(family);
            assert_eq!(
                provider
                    .commit_token_issuance(token(
                        code(&format!("capacity-{index}")),
                        Some(RefreshTokenCommit::IssueNew {
                            token: next,
                            contract: original_contract
                        })
                    ))
                    .await
                    .unwrap(),
                CommitTokenIssuanceResult::Committed
            );
        }
        assert!(
            !provider
                .refresh_family_active(TENANT, families[0], USER)
                .await
                .unwrap()
        );
        for family in &families[1..] {
            assert!(
                provider
                    .refresh_family_active(TENANT, *family, USER)
                    .await
                    .unwrap()
            );
        }
    })
}
#[test]
fn unsafe_javascript_integer_epoch_is_rejected() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut client = support::client();
        client.id = Uuid::new_v4();
        client.registration.client_id = "large-epoch".into();
        assert!(
            provider
                .provision_client(&client, None, 9_007_199_254_740_992)
                .await
                .is_err()
        );
        assert!(
            provider
                .client_by_id("large-epoch")
                .await
                .unwrap()
                .is_none()
        );
    })
}
#[test]
fn signing_key_compare_and_swap_has_one_winner() {
    use nazo_key_management::{
        PersistedSigningKeyset, SigningKeyRepository, SigningKeysetCompareAndSwapResult,
    };
    let (_, provider) = block_on(fixture());
    let provider = Arc::new(provider);
    block_on(provider.create_if_absent(PersistedSigningKeyset {
        revision: 1,
        public_metadata: json!({"generation":1}),
        encrypted_private_material: vec![1, 2, 3],
        wrapping_key_id: "wrap".into(),
    }))
    .unwrap();
    let barrier = Arc::new(Barrier::new(12));
    let tasks = (0..12)
        .map(|index| {
            let provider = provider.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                block_on(provider.compare_and_swap(
                    1,
                    PersistedSigningKeyset {
                        revision: 2,
                        public_metadata: json!({"winner":index}),
                        encrypted_private_material: vec![4, 5, 6],
                        wrapping_key_id: "wrap".into(),
                    },
                ))
                .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, SigningKeysetCompareAndSwapResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(block_on(provider.load()).unwrap().unwrap().revision, 2);
}

#[test]
fn redemption_expiry_closes_authority_before_cleanup() {
    block_on(async {
        let (database, provider) = fixture().await;
        assert_eq!(
            provider
                .commit_token_issuance(token(code("receipt-expiry"), None))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:receipt-expiry")
                .await
                .unwrap()
                .is_some()
        );
        database
            .execute_sql("UPDATE nazo_redemptions SET retain_until=0")
            .unwrap();
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "authorization_code:v2:receipt-expiry")
                .await
                .unwrap()
                .is_none()
        );
    })
}

#[test]
fn malformed_commit_cannot_create_redemption_or_refresh_authority() {
    type Mutation = fn(&mut CommitTokenIssuance);
    let cases: &[(&str, Mutation)] = &[
        ("nil issuance", |input| input.issuance_id = Uuid::nil()),
        ("nil client", |input| input.client_id = Uuid::nil()),
        ("blank jti", |input| input.access_token_jti = "  \t".into()),
        ("empty subject", |input| input.subject.clear()),
        ("oversized subject", |input| input.subject = "x".repeat(256)),
        ("negative client epoch", |input| {
            input.principal_state.client_epoch = -1
        }),
        ("negative user epoch", |input| {
            input.principal_state.user_epoch = Some(-1)
        }),
        ("missing user epoch", |input| {
            input.principal_state.user_epoch = None
        }),
        ("blank single-use key", |input| {
            input.mode = TokenIssuanceMode::SingleUse {
                grant_key: "  ".into(),
                grant_expires_at: Timestamp::now() + SignedDuration::from_secs(60),
            }
        }),
        ("code without holder", |input| {
            input.mode = TokenIssuanceMode::SingleUse {
                grant_key: "authorization_code:v2:malformed".into(),
                grant_expires_at: Timestamp::now() + SignedDuration::from_secs(60),
            }
        }),
        ("legacy code identity", |input| {
            if let TokenIssuanceMode::AuthorizationCode { code_identity, .. } = &mut input.mode {
                *code_identity = "authorization_code:malformed".into();
            }
        }),
    ];
    for (name, mutate) in cases {
        block_on(async {
            let (_, provider) = fixture().await;
            let mut input = token(
                code("malformed"),
                Some(RefreshTokenCommit::IssueNew {
                    token: refresh("malformed-refresh", Uuid::new_v4()),
                    contract: contract(),
                }),
            );
            mutate(&mut input);
            let key = match &input.mode {
                TokenIssuanceMode::AuthorizationCode { code_identity, .. } => code_identity.clone(),
                TokenIssuanceMode::SingleUse { grant_key, .. } => grant_key.clone(),
                TokenIssuanceMode::Fresh => unreachable!(),
            };
            assert!(
                matches!(
                    provider.commit_token_issuance(input).await,
                    Err(nazo_auth::TokenPortError::CorruptData)
                ),
                "{name}"
            );
            assert!(
                provider
                    .single_use_redemption(TENANT, CLIENT, &key)
                    .await
                    .unwrap()
                    .is_none(),
                "{name}"
            );
            assert!(
                provider
                    .refresh_token(TENANT, "malformed-refresh")
                    .await
                    .unwrap()
                    .is_none(),
                "{name}"
            );
        });
    }
}

#[test]
fn refresh_rotation_cannot_widen_a_previously_narrowed_audience() {
    block_on(async {
        let (_, provider) = fixture().await;
        let family = Uuid::new_v4();
        let mut original_contract = contract();
        original_contract
            .audiences
            .push("https://second-api.example".into());
        let mut original = refresh("wide", family);
        original.audiences = original_contract.audiences.clone();
        assert_eq!(
            provider
                .commit_token_issuance(token(
                    code("narrowing"),
                    Some(RefreshTokenCommit::IssueNew {
                        token: original,
                        contract: original_contract,
                    })
                ))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let wide = provider
            .refresh_token(TENANT, "wide")
            .await
            .unwrap()
            .unwrap();
        let mut narrowed = refresh("narrowed", family);
        narrowed.rotated_from_id = Some(wide.id);
        assert_eq!(
            provider
                .commit_token_issuance(token(
                    TokenIssuanceMode::Fresh,
                    Some(RefreshTokenCommit::UseExisting {
                        authority: wide.authority(),
                        rotation: Some(narrowed),
                    })
                ))
                .await
                .unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let narrow = provider
            .refresh_token(TENANT, "narrowed")
            .await
            .unwrap()
            .unwrap();
        let mut widened = refresh("widened", family);
        widened.rotated_from_id = Some(narrow.id);
        widened.audiences = wide.contract.audiences.clone();
        assert!(matches!(
            provider
                .commit_token_issuance(token(
                    TokenIssuanceMode::Fresh,
                    Some(RefreshTokenCommit::UseExisting {
                        authority: narrow.authority(),
                        rotation: Some(widened),
                    })
                ))
                .await,
            Err(nazo_auth::TokenPortError::CorruptData)
        ));
        assert!(
            provider
                .refresh_token(TENANT, "widened")
                .await
                .unwrap()
                .is_none()
        );
        let still_live = provider
            .refresh_token(TENANT, "narrowed")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_live.id, narrow.id);
        assert!(still_live.revoked_at.is_none());
    })
}
