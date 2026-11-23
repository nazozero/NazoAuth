#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationDecisionCommit, AuthorizationDecisionCommitResult, AuthorizationDecisionKind,
    AuthorizationPortError, AuthorizationRepositoryPort, CommitTokenIssuance,
    CommitTokenIssuanceResult, NewRefreshToken, RefreshContract, RefreshTokenAuthenticationContext,
    RefreshTokenCommit, TokenIssuanceMode, TokenIssuedAuditFields, TokenPrincipalState,
    TokenRepositoryPort,
};
use serde_json::json;
use support::{CLIENT, TENANT, USER, fixture};
use uuid::Uuid;

fn issuance(id: Uuid) -> CommitTokenIssuance {
    CommitTokenIssuance {
        authorization_id: Some(id),
        principal_state: TokenPrincipalState {
            client_epoch: 0,
            user_epoch: Some(0),
            subject_bound: false,
        },
        subject: USER.to_string(),
        issuance_id: id,
        tenant_id: TENANT,
        client_id: CLIENT,
        user_id: Some(USER),
        mode: TokenIssuanceMode::Fresh,
        access_token_jti: Uuid::new_v4().to_string(),
        access_token_expires_at: (Timestamp::now() + SignedDuration::from_secs(600)).as_second(),
        refresh_token: None,
        native_sso_source: None,
        audit_fields: TokenIssuedAuditFields {
            client_id: "client".into(),
            subject_hash: "subject".into(),
            scope: "openid".into(),
            audience: vec!["https://api.example".into()],
        },
    }
}

fn decision(id: Uuid, request: &str) -> AuthorizationDecisionCommit {
    let now = Timestamp::now();
    AuthorizationDecisionCommit {
        tenant_id: TENANT,
        user_id: USER,
        client_id: "client".into(),
        request_id: request.into(),
        pushed_request_uri: None,
        valid_until: now + SignedDuration::from_secs(60),
        retain_until: now + SignedDuration::from_secs(600),
        decision: AuthorizationDecisionKind::Approve,
        event_id: id,
        occurred_at: now,
        audit_fields: json!({"decision":"approve"}),
        scopes: vec!["openid".into()],
        resource_indicators: vec!["https://api.example".into()],
        authorization_details: json!([]),
    }
}

fn new_family(id: Uuid) -> RefreshTokenCommit {
    let now = Timestamp::now();
    let audiences = vec!["https://api.example".into()];
    RefreshTokenCommit::IssueNew {
        token: NewRefreshToken {
            raw_token: "new-refresh-after-stale-admission".into(),
            member_id: Uuid::new_v4(),
            tenant_id: TENANT,
            family_id: id,
            rotated_from_id: None,
            lost_response_retry: None,
            client_id: CLIENT,
            user_id: Some(USER),
            audiences: audiences.clone(),
            issued_at: now,
            expires_at: now + SignedDuration::from_secs(3600),
            id_token_sid: None,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            client_attestation_jkt: None,
        },
        contract: RefreshContract {
            subject: USER.to_string(),
            scopes: vec!["openid".into(), "offline_access".into()],
            audiences,
            authorization_details: json!([]),
            authentication_context: RefreshTokenAuthenticationContext {
                version: RefreshTokenAuthenticationContext::CURRENT_VERSION,
                issuer: "https://issuer.example".into(),
                audience: "client".into(),
                auth_time: now.as_second(),
                amr: vec!["pwd".into()],
                oidc_sid: None,
                acr: None,
                userinfo_claim_requests: Default::default(),
                id_token_claim_requests: Default::default(),
            },
        },
    }
}

#[test]
fn prior_issuance_event_cannot_authorize_a_new_redemption_after_admission_fails() {
    block_on(async {
        let (_, provider) = fixture().await;
        let id = Uuid::new_v4();
        assert_eq!(
            provider.commit_token_issuance(issuance(id)).await.unwrap(),
            CommitTokenIssuanceResult::Committed
        );
        let mut invalid = issuance(id);
        invalid.principal_state.client_epoch = 1;
        invalid.mode = TokenIssuanceMode::SingleUse {
            grant_key: "new-grant-with-stale-epoch".into(),
            grant_expires_at: Timestamp::now() + SignedDuration::from_secs(60),
        };
        let family = Uuid::new_v4();
        invalid.authorization_id = Some(family);
        invalid.refresh_token = Some(new_family(family));
        assert!(!matches!(
            provider.commit_token_issuance(invalid).await,
            Ok(CommitTokenIssuanceResult::Committed)
        ));
        assert!(
            provider
                .single_use_redemption(TENANT, CLIENT, "new-grant-with-stale-epoch")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider
                .refresh_token(TENANT, "new-refresh-after-stale-admission")
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn prior_decision_event_cannot_authorize_an_expired_request_or_replace_its_grant() {
    block_on(async {
        let (_, provider) = fixture().await;
        let id = Uuid::new_v4();
        assert_eq!(
            provider
                .commit_decision(decision(id, "original"))
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let mut invalid = decision(id, "expired-new-request");
        invalid.valid_until = Timestamp::now() - SignedDuration::from_secs(1);
        invalid.scopes.push("profile".into());
        assert!(!matches!(
            provider.commit_decision(invalid).await,
            Ok(AuthorizationDecisionCommitResult::Committed)
        ));
        assert_eq!(
            provider.grant(USER, CLIENT).await.unwrap().unwrap().scopes,
            json!(["openid"])
        );
    });
}

#[test]
fn ignored_audit_cannot_reuse_a_decision_after_its_receipt_expires() {
    block_on(async {
        let (database, provider) = fixture().await;
        assert_eq!(
            provider
                .commit_decision(decision(Uuid::new_v4(), "approve"))
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        let mut prompt_none = decision(Uuid::new_v4(), "prompt-none");
        prompt_none.decision = AuthorizationDecisionKind::PromptNone;
        prompt_none.valid_until = Timestamp::now() + SignedDuration::from_secs(1);
        prompt_none.retain_until = prompt_none.valid_until;
        assert_eq!(
            provider.commit_decision(prompt_none.clone()).await.unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(provider.prune_expired(100).await.unwrap(), 1);
        database
            .execute_sql(&format!(
                "CREATE TRIGGER ignore_prior_decision BEFORE INSERT ON nazo_audit
             WHEN NEW.event_id='{}' BEGIN SELECT RAISE(IGNORE); END;",
                prompt_none.event_id
            ))
            .unwrap();
        assert!(!matches!(
            provider.commit_decision(prompt_none).await,
            Ok(AuthorizationDecisionCommitResult::Committed)
        ));
        assert_eq!(provider.prune_expired(100).await.unwrap(), 0);
    });
}

#[test]
fn unrelated_audit_type_or_tenant_cannot_authorize_an_expired_decision() {
    block_on(async {
        for (tenant, event_type) in [
            (TENANT, "token_issued"),
            (Uuid::from_u128(99), "authorization_decision"),
        ] {
            let (database, provider) = fixture().await;
            let event = Uuid::new_v4();
            database.execute_sql(&format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) VALUES('{tenant}','{event}','{event_type}','test',0,'{{}}')"
            )).unwrap();
            let mut invalid = decision(event, "expired-request");
            invalid.valid_until = Timestamp::now() - SignedDuration::from_secs(1);
            assert!(!matches!(
                provider.commit_decision(invalid).await,
                Ok(AuthorizationDecisionCommitResult::Committed)
            ));
            assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
        }
    });
}

#[test]
fn a_decision_fence_cannot_expire_before_the_request_it_protects() {
    block_on(async {
        let (_, provider) = fixture().await;
        let mut invalid = decision(Uuid::new_v4(), "under-retained-request");
        invalid.retain_until = Timestamp::now() - SignedDuration::from_secs(1);
        assert!(matches!(
            provider.commit_decision(invalid).await,
            Err(AuthorizationPortError::CorruptData)
        ));
        assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
    });
}

#[test]
fn authorization_completion_requires_the_receipt_grant_and_history() {
    block_on(async {
        for table in ["nazo_decisions", "nazo_grants", "nazo_grant_activity"] {
            let (database, provider) = fixture().await;
            database.execute_sql(&format!("CREATE TRIGGER suppress BEFORE INSERT ON {table} BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
            assert!(
                provider
                    .commit_decision(decision(Uuid::new_v4(), "ignored"))
                    .await
                    .is_err(),
                "{table}"
            );
            assert!(provider.grant(USER, CLIENT).await.unwrap().is_none());
            database.execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit) AND NOT EXISTS(SELECT 1 FROM nazo_decisions) AND NOT EXISTS(SELECT 1 FROM nazo_grant_activity) THEN 1 ELSE 0 END;").unwrap();
        }
        let (database, provider) = fixture().await;
        assert_eq!(
            provider
                .commit_decision(decision(Uuid::new_v4(), "first"))
                .await
                .unwrap(),
            AuthorizationDecisionCommitResult::Committed
        );
        database.execute_sql("CREATE TRIGGER suppress BEFORE UPDATE ON nazo_grant_activity BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            provider
                .commit_decision(decision(Uuid::new_v4(), "second"))
                .await
                .is_err()
        );
        database.execute_sql("CREATE TEMP TABLE assertion(ok INTEGER CHECK(ok=1)); INSERT INTO assertion SELECT CASE WHEN (SELECT count(*) FROM nazo_decisions)=1 AND (SELECT count(*) FROM nazo_audit)=1 AND (SELECT authorization_count FROM nazo_grant_activity)=1 THEN 1 ELSE 0 END;").unwrap();
    });
}

#[test]
fn machine_final_check_requires_the_active_tenant_client_and_original_epoch() {
    block_on(async {
        let (_, provider) = fixture().await;
        assert!(
            provider
                .machine_client_active(TENANT, CLIENT, 0)
                .await
                .unwrap()
        );
        assert!(
            !provider
                .machine_client_active(TENANT, CLIENT, 1)
                .await
                .unwrap()
        );
        assert!(
            !provider
                .machine_client_active(TENANT, Uuid::now_v7(), 0)
                .await
                .unwrap()
        );
        assert!(
            provider
                .machine_client_active(Uuid::now_v7(), CLIENT, 0)
                .await
                .is_err()
        );
    });
}
