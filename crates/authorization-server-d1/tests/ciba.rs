#![cfg(feature = "local-sqlite")]

mod support;

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    CibaAtomicResult, CibaAuthenticationContext, CibaDecision, CibaDecisionFailure,
    CibaPingFinishOutcome, CibaPingFinishResult, CibaPingNotification, CibaPingNotificationStatus,
    CibaPollCommit, CibaRequestState, CibaService, CibaStatePortError, CibaStateStorePort,
    CibaStatus, CommitTokenIssuance, CommitTokenIssuanceResult, TokenIssuanceMode,
    TokenIssuedAuditFields, TokenPrincipalState, TokenRepositoryPort,
};
use nazo_identity::{TenantId, UserId};
use nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_persistence::CibaAccountStore;
use std::sync::{Arc, Barrier};
use support::{CLIENT, TENANT, USER};
use uuid::Uuid;

async fn fixture() -> (Database, D1Provider) {
    let (database, provider) = support::fixture().await;
    database
        .execute_sql(include_str!("../migrations/0005_ciba_scim.sql"))
        .unwrap();
    (database, provider)
}

fn pending(ping: bool) -> CibaRequestState {
    let now = Timestamp::now().as_second();
    CibaRequestState {
        client_id: "client".into(),
        user_id: USER,
        scopes: vec!["openid".into()],
        audiences: vec!["https://api.example".into()],
        acr: None,
        authentication_context: None,
        binding_message: Some("Confirm sign in".into()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 300,
        retention_expires_at: now + 420,
        last_poll_at: None,
        ping_notification: ping.then(|| CibaPingNotification {
            auth_req_id: None,
            endpoint: "https://client.example/ping".into(),
            client_notification_token: Some("private-notification-token".into()),
            status: CibaPingNotificationStatus::AwaitingDecision,
            attempts: 0,
            next_attempt_at: None,
        }),
    }
}

fn approval() -> CibaDecision {
    CibaDecision::Approve(CibaAuthenticationContext {
        auth_time: Timestamp::now().as_second(),
        amr: vec!["passkey".into()],
        oidc_sid: Some("sid".into()),
    })
}

#[test]
fn creation_uses_store_deadlines_and_binds_ping_handle_without_overwriting_collision() {
    block_on(async {
        let (_, provider) = fixture().await;
        let state = pending(true);
        assert_eq!(
            provider
                .create_with_authorization_deadline("expired-capability", &state, Some(1))
                .await
                .unwrap(),
            CibaAtomicResult::DeadlineElapsed
        );
        assert!(provider.load("expired-capability").await.unwrap().is_none());
        assert_eq!(
            provider.create("request", &state).await.unwrap(),
            CibaAtomicResult::Applied
        );
        let mut different = state.clone();
        different.user_id = Uuid::new_v4();
        assert_eq!(
            provider.create("request", &different).await.unwrap(),
            CibaAtomicResult::Conflict
        );
        let stored = provider.load("request").await.unwrap().unwrap();
        assert_eq!(stored.state().user_id, USER);
        assert_eq!(
            stored
                .state()
                .ping_notification
                .as_ref()
                .unwrap()
                .auth_req_id
                .as_deref(),
            Some("request")
        );
        assert_eq!(
            stored.version().retention_expires_at(),
            state.retention_expires_at
        );
    });
}

#[test]
fn concurrent_snapshot_replacement_has_one_winner_and_cannot_change_retention() {
    let (_, provider) = block_on(fixture());
    let state = pending(false);
    block_on(provider.create("cas", &state)).unwrap();
    let stored = block_on(provider.load("cas")).unwrap().unwrap();
    let version = Arc::new(stored.version().clone());
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(12));
    let results = std::thread::scope(|scope| {
        let joins = (0..12)
            .map(|index| {
                let provider = provider.clone();
                let version = version.clone();
                let barrier = barrier.clone();
                let mut next = state.clone();
                next.last_poll_at = Some(state.issued_at + index);
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.replace("cas", &version, &next)).unwrap()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == CibaAtomicResult::Applied)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == CibaAtomicResult::Conflict)
            .count(),
        11
    );
    let current = block_on(provider.load("cas")).unwrap().unwrap();
    let mut longer = current.state().clone();
    longer.retention_expires_at += 1;
    assert_eq!(
        block_on(provider.replace("cas", current.version(), &longer)).unwrap_err(),
        CibaStatePortError::CorruptData
    );
    assert_eq!(
        block_on(provider.replace_with_authorization_deadline(
            "cas",
            current.version(),
            current.state(),
            Some(1)
        ))
        .unwrap(),
        CibaAtomicResult::DeadlineElapsed
    );
    assert_eq!(
        block_on(provider.delete_with_authorization_deadline("cas", current.version(), Some(1)))
            .unwrap(),
        CibaAtomicResult::DeadlineElapsed
    );
    assert_eq!(
        block_on(provider.load("cas")).unwrap().unwrap().version(),
        current.version()
    );
}

#[test]
fn shared_service_preserves_poll_throttle_user_binding_and_final_decision() {
    block_on(async {
        let (_, provider) = fixture().await;
        let service = CibaService::new(provider.clone());
        let state = pending(false);
        service
            .create_unique(&state, || "flow".into())
            .await
            .unwrap();
        let stored = service.load("flow").await.unwrap().unwrap();
        assert!(matches!(
            service
                .poll("flow", "client", stored, || state.issued_at)
                .await
                .unwrap(),
            CibaPollCommit::AuthorizationPending
        ));
        let stored = service.load("flow").await.unwrap().unwrap();
        assert!(matches!(
            service
                .poll("flow", "client", stored, || state.issued_at)
                .await
                .unwrap(),
            CibaPollCommit::SlowDown
        ));
        assert!(matches!(
            service
                .decide("flow", approval(), Some(Uuid::new_v4()), || state.issued_at)
                .await,
            Err(CibaDecisionFailure::UserMismatch)
        ));
        service
            .decide("flow", approval(), Some(USER), || state.issued_at)
            .await
            .unwrap();
        assert!(matches!(
            service
                .decide("flow", CibaDecision::Deny, Some(USER), || state.issued_at)
                .await,
            Err(CibaDecisionFailure::AlreadyHandled)
        ));
        let approved = service.load("flow").await.unwrap().unwrap();
        assert_eq!(approved.state().interval_seconds, 10);
        assert!(matches!(
            service
                .poll("flow", "client", approved, || state.issued_at)
                .await
                .unwrap(),
            CibaPollCommit::Approved(_)
        ));
        service
            .create_unique(&state, || "deny".into())
            .await
            .unwrap();
        service
            .decide("deny", CibaDecision::Deny, Some(USER), || state.issued_at)
            .await
            .unwrap();
        assert!(matches!(
            service
                .poll(
                    "deny",
                    "client",
                    service.load("deny").await.unwrap().unwrap(),
                    || state.issued_at
                )
                .await
                .unwrap(),
            CibaPollCommit::Denied
        ));
    });
}

#[test]
fn ping_claim_is_exclusive_and_old_attempts_cannot_finish_a_reclaimed_delivery() {
    let (_, provider) = block_on(fixture());
    let state = pending(true);
    let service = CibaService::new(provider.clone());
    block_on(service.create_unique(&state, || "ping".into())).unwrap();
    assert_eq!(
        block_on(provider.claim_due(state.issued_at, state.issued_at + 15, 8))
            .unwrap()
            .scanned,
        0
    );
    block_on(service.decide("ping", approval(), Some(USER), || state.issued_at)).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let provider = Arc::new(provider);
    let deliveries = std::thread::scope(|scope| {
        let joins = (0..8)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.claim_due(state.issued_at, state.issued_at + 15, 8))
                        .unwrap()
                        .deliveries
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .flat_map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(deliveries.len(), 1);
    let first = &deliveries[0];
    assert_eq!(first.auth_req_id, "ping");
    assert_eq!(first.attempts, 1);
    let reclaimed = block_on(provider.claim_due(state.issued_at + 16, state.issued_at + 31, 8))
        .unwrap()
        .deliveries
        .pop()
        .unwrap();
    assert_eq!(reclaimed.attempts, 2);
    assert_eq!(
        block_on(provider.finish(first, CibaPingFinishOutcome::Delivered)).unwrap(),
        CibaPingFinishResult::Conflict
    );
    assert_eq!(
        block_on(provider.finish(
            &reclaimed,
            CibaPingFinishOutcome::RetryAt(state.issued_at + 20)
        ))
        .unwrap(),
        CibaPingFinishResult::Applied
    );
    let third = block_on(provider.claim_due(state.issued_at + 20, state.issued_at + 35, 8))
        .unwrap()
        .deliveries
        .pop()
        .unwrap();
    assert_eq!(third.attempts, 3);
    assert_eq!(
        block_on(provider.finish(&third, CibaPingFinishOutcome::Delivered)).unwrap(),
        CibaPingFinishResult::Applied
    );
    let stored = block_on(provider.load("ping")).unwrap().unwrap();
    let notification = stored.state().ping_notification.as_ref().unwrap();
    assert_eq!(notification.status, CibaPingNotificationStatus::Delivered);
    assert!(
        notification.client_notification_token.is_none() && notification.next_attempt_at.is_none()
    );
    assert_eq!(
        block_on(provider.claim_due(state.issued_at + 40, state.issued_at + 55, 8))
            .unwrap()
            .scanned,
        0
    );
}

#[test]
fn expiry_retires_ping_secret_and_missing_or_foreign_state_never_delivers() {
    block_on(async {
        let (database, provider) = fixture().await;
        let state = pending(true);
        let service = CibaService::new(provider.clone());
        service
            .create_unique(&state, || "expired-ping".into())
            .await
            .unwrap();
        service
            .decide("expired-ping", CibaDecision::Deny, Some(USER), || {
                state.issued_at
            })
            .await
            .unwrap();
        let batch = provider
            .claim_due(state.expires_at, state.expires_at + 15, 8)
            .await
            .unwrap();
        assert_eq!(batch.scanned, 1);
        assert!(batch.deliveries.is_empty());
        let stored = provider.load("expired-ping").await.unwrap().unwrap();
        let notification = stored.state().ping_notification.as_ref().unwrap();
        assert_eq!(notification.status, CibaPingNotificationStatus::Failed);
        assert!(notification.client_notification_token.is_none());
        let other = D1Provider::new(database, TenantId::new(Uuid::new_v4()).unwrap());
        assert!(other.load("expired-ping").await.unwrap().is_none());
        assert_eq!(
            other
                .claim_due(state.issued_at, state.issued_at + 15, 8)
                .await
                .unwrap()
                .scanned,
            0
        );
    });
}

fn issuance() -> CommitTokenIssuance {
    let id = Uuid::new_v4();
    let now = Timestamp::now();
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
        mode: TokenIssuanceMode::SingleUse {
            grant_key: nazo_oauth_server::token::ciba::state::ciba_grant_key("approved"),
            grant_expires_at: now + SignedDuration::from_secs(300),
        },
        access_token_jti: Uuid::new_v4().to_string(),
        access_token_expires_at: (now + SignedDuration::from_secs(600)).as_second(),
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

#[test]
fn approved_ciba_grant_commit_is_single_use_and_audit_failure_does_not_consume_it() {
    let (database, provider) = block_on(fixture());
    let service = CibaService::new(provider.clone());
    block_on(service.create_unique(&pending(false), || "approved".into())).unwrap();
    block_on(service.decide("approved", approval(), Some(USER), || {
        Timestamp::now().as_second()
    }))
    .unwrap();
    database.execute_sql("CREATE TRIGGER fail_ciba_token BEFORE INSERT ON nazo_audit WHEN NEW.event_type='token_issued' BEGIN SELECT RAISE(ABORT,'required audit unavailable'); END;").unwrap();
    assert!(block_on(provider.commit_token_issuance(issuance())).is_err());
    database
        .execute_sql("DROP TRIGGER fail_ciba_token;")
        .unwrap();
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(8));
    let results = std::thread::scope(|scope| {
        let joins = (0..8)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.commit_token_issuance(issuance())).unwrap()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|value| **value == CommitTokenIssuanceResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|value| **value == CommitTokenIssuanceResult::AlreadyUsed)
            .count(),
        7
    );
}

#[test]
fn account_projection_is_tenant_bound_and_storage_failure_keeps_pending_state() {
    block_on(async {
        let (database, provider) = fixture().await;
        let tenant = TenantId::new(TENANT).unwrap();
        let user = UserId::new(USER).unwrap();
        assert_eq!(
            CibaAccountStore::by_email(&provider, tenant, "test@example.com")
                .await
                .unwrap()
                .unwrap()
                .user_id(),
            user
        );
        assert_eq!(
            CibaAccountStore::by_id(&provider, tenant, user)
                .await
                .unwrap()
                .unwrap()
                .id(),
            USER
        );
        assert!(
            CibaAccountStore::by_id(&provider, TenantId::new(Uuid::new_v4()).unwrap(), user)
                .await
                .is_err()
        );
        let state = pending(false);
        provider.create("unavailable", &state).await.unwrap();
        database.execute_sql("CREATE TRIGGER fail_ciba_state BEFORE UPDATE ON nazo_state WHEN OLD.kind='ciba' BEGIN SELECT RAISE(ABORT,'state unavailable'); END;").unwrap();
        let service = CibaService::new(provider);
        assert!(matches!(
            service
                .decide("unavailable", approval(), Some(USER), || state.issued_at)
                .await,
            Err(CibaDecisionFailure::Storage(_))
        ));
        assert_eq!(
            service
                .load("unavailable")
                .await
                .unwrap()
                .unwrap()
                .state()
                .status,
            CibaStatus::Pending
        );
    });
}
