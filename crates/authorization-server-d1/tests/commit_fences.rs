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
