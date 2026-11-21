#![cfg(feature = "local-sqlite")]

use std::sync::{Arc, Barrier};

use futures_executor::block_on;
use jiff::{SignedDuration, Timestamp};
use nazo_auth::{
    AuthorizationCodeBeginResult, AuthorizationCodeState, AuthorizationCodeTransitionResult,
    AuthorizationPortError, AuthorizationStateStorePort, ClientAttestationProofWindow, CodePayload,
    DpopStateStorePort, PushedAuthorizationRequest, RequestRateLimitBucket, RequestRateLimitPort,
    TokenStateStorePort,
};
use nazo_identity::{
    SessionId, SessionRotationOutcome, SessionUpdateOutcome, TenantId, UserId,
    ports::{LoginSessionCreate, LoginSessionPort, LoginThrottlePort, SessionStorePort},
    session::SessionRecord,
};
use nazo_oauth_server_d1::{D1Provider, Database};
use nazo_resource_server::{DpopReplayConsumption, DpopReplayConsumptionResult, DpopReplayKey};
use serde_json::json;
use uuid::Uuid;

fn fixture() -> (Database, D1Provider) {
    let database = Database::in_memory().unwrap();
    database.execute_schema().unwrap();
    let provider = D1Provider::new(database.clone(), TenantId::new(Uuid::from_u128(1)).unwrap());
    (database, provider)
}

fn session() -> SessionRecord {
    let mut value = SessionRecord::new(
        UserId::new(Uuid::from_u128(2)).unwrap(),
        7,
        Timestamp::now().as_second(),
        vec!["pwd".into()],
        false,
        Some("oidc-session".into()),
    );
    value.record_authentication_at(Timestamp::now());
    value.add_logged_in_client("client");
    value
}

fn code() -> CodePayload {
    CodePayload {
        redemption_contract_version: nazo_auth::AUTHORIZATION_CODE_REDEMPTION_VERSION,
        code_id: "code".into(),
        user_id: Uuid::from_u128(2),
        client_id: "client".into(),
        redirect_uri: "https://client.example/cb".into(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".into()],
        resource_indicators: vec![],
        authorization_details: json!([{"type":"payment_initiation","integer":9_007_199_254_740_993_u64,"unsigned":u64::MAX}]),
        nonce: None,
        auth_time: Timestamp::now().as_second(),
        amr: vec!["pwd".into()],
        oidc_sid: Some("session".into()),
        acr: None,
        userinfo_claim_requests: vec![].into(),
        id_token_claim_requests: vec![].into(),
        pkce: None.into(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        expires_at: Timestamp::now() + SignedDuration::from_secs(60),
    }
}

#[test]
fn concurrent_replay_has_one_winner_and_scopes_by_tenant_and_key_tuple() {
    let (database, provider) = fixture();
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(32));
    let winners = std::thread::scope(|scope| {
        let joins = (0..32)
            .map(|_| {
                let provider = provider.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    block_on(provider.consume_replay("key", "proof", 60)).unwrap()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|join| usize::from(join.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(winners, 1);
    let other = D1Provider::new(database, TenantId::new(Uuid::from_u128(3)).unwrap());
    assert!(block_on(other.consume_replay("key", "proof", 60)).unwrap());
    assert!(block_on(provider.consume_replay("a:b", "c", 60)).unwrap());
    assert!(block_on(provider.consume_replay("a", "b:c", 60)).unwrap());
    assert_eq!(
        block_on(DpopReplayConsumption::consume(
            provider.as_ref(),
            DpopReplayKey {
                jkt: "key",
                jti: "proof",
                expires_at: Timestamp::now().as_second() + 60,
            }
        ))
        .unwrap(),
        DpopReplayConsumptionResult::Replay
    );
}

#[test]
fn database_clock_rejects_expired_and_future_replay_windows() {
    let (database, provider) = fixture();
    let nonce = Uuid::new_v4().to_string();
    let now = Timestamp::now().as_second();
    assert!(!block_on(provider.consume_jar("client", "expired", now - 1)).unwrap());
    assert!(
        !block_on(provider.consume_client_attestation_proof(
            "client",
            "future",
            ClientAttestationProofWindow::from_verified_issued_at(now + 600).unwrap()
        ))
        .unwrap()
    );
    assert!(
        block_on(provider.consume_client_attestation_proof(
            "client",
            "current",
            ClientAttestationProofWindow::from_verified_issued_at(now).unwrap()
        ))
        .unwrap()
    );
    assert!(
        !block_on(provider.consume_client_attestation_proof(
            "client",
            "current",
            ClientAttestationProofWindow::from_verified_issued_at(now).unwrap()
        ))
        .unwrap()
    );
    block_on(DpopStateStorePort::issue_nonce(&provider, &nonce, 60)).unwrap();
    assert!(block_on(DpopStateStorePort::validate_nonce(&provider, &nonce)).unwrap());
    assert!(block_on(DpopStateStorePort::validate_nonce(&provider, &nonce)).unwrap());
    database
        .execute_sql("UPDATE nazo_state SET expires_at=unixepoch()-1")
        .unwrap();
    assert!(!block_on(DpopStateStorePort::validate_nonce(&provider, &nonce)).unwrap());
    assert!(
        block_on(provider.consume_client_attestation_proof(
            "client",
            "current",
            ClientAttestationProofWindow::from_verified_issued_at(now).unwrap()
        ))
        .unwrap()
    );
}

#[test]
fn par_is_immutable_and_opaque_revision_prevents_stale_delete() {
    let (_, provider) = fixture();
    let payload = PushedAuthorizationRequest {
        client_id: "client".into(),
        params: Default::default(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Timestamp::now(),
        expires_at: Timestamp::now() + SignedDuration::from_secs(60),
    };
    block_on(provider.store_par("uri", &payload, 60)).unwrap();
    let first = block_on(provider.load_par("uri")).unwrap().unwrap();
    assert_eq!(
        block_on(provider.store_par("uri", &payload, 600)),
        Err(AuthorizationPortError::Conflict)
    );
    assert!(block_on(provider.compare_and_delete_par("uri", &first.version)).unwrap());
    block_on(provider.store_par("uri", &payload, 60)).unwrap();
    assert!(!block_on(provider.compare_and_delete_par("uri", &first.version)).unwrap());
    assert!(block_on(provider.load_par("uri")).unwrap().is_some());
}

#[test]
fn authorization_code_consumption_is_atomic_and_preserves_large_json_integers() {
    let (_, provider) = fixture();
    let payload = code();
    block_on(provider.store_authorization_code(
        "code-hash",
        &AuthorizationCodeState::Pending {
            payload: payload.clone(),
        },
        60,
    ))
    .unwrap();
    assert_eq!(
        block_on(provider.mark_authorization_code(
            "code-hash",
            &AuthorizationCodeState::Consumed,
            60
        ))
        .unwrap(),
        AuthorizationCodeTransitionResult::Pending
    );
    let provider = Arc::new(provider);
    let results = std::thread::scope(|scope| {
        (0..24)
            .map(|_| {
                let provider = provider.clone();
                scope.spawn(move || {
                    block_on(provider.begin_authorization_code("code-hash", Timestamp::now()))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AuthorizationCodeBeginResult::Consuming(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AuthorizationCodeBeginResult::Busy))
            .count(),
        23
    );
    let consumed_payload = results
        .into_iter()
        .find_map(|result| match result {
            AuthorizationCodeBeginResult::Consuming(payload) => Some(payload),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        serde_json::to_value(consumed_payload).unwrap(),
        serde_json::to_value(payload).unwrap()
    );
    assert_eq!(
        block_on(provider.mark_authorization_code(
            "code-hash",
            &AuthorizationCodeState::Consumed,
            60
        ))
        .unwrap(),
        AuthorizationCodeTransitionResult::Applied
    );
    assert!(matches!(
        block_on(provider.begin_authorization_code("code-hash", Timestamp::now())).unwrap(),
        AuthorizationCodeBeginResult::Consumed(_)
    ));
    block_on(TokenStateStorePort::delete_authorization_code(
        provider.as_ref(),
        "code-hash",
    ))
    .unwrap();
    assert!(matches!(
        block_on(provider.begin_authorization_code("code-hash", Timestamp::now())).unwrap(),
        AuthorizationCodeBeginResult::Missing
    ));
}

#[test]
fn malformed_authorization_code_never_becomes_issuance_authority() {
    let (database, provider) = fixture();
    block_on(provider.store_authorization_code(
        "code",
        &AuthorizationCodeState::Pending { payload: code() },
        60,
    ))
    .unwrap();
    database
        .execute_sql("UPDATE nazo_state SET value='invalid JSON' WHERE kind='code'")
        .unwrap();
    assert!(matches!(
        block_on(provider.begin_authorization_code("code", Timestamp::now())).unwrap(),
        AuthorizationCodeBeginResult::Malformed
    ));
    assert_eq!(
        block_on(provider.mark_authorization_code("code", &AuthorizationCodeState::Consumed, 60))
            .unwrap(),
        AuthorizationCodeTransitionResult::Malformed
    );
    assert!(block_on(provider.load_authorization_code("code")).is_err());
}

#[test]
fn reauthentication_nonce_is_consumed_once_without_losing_microseconds() {
    let (_, provider) = fixture();
    let nonce = Uuid::new_v4().to_string();
    let micros = Timestamp::now().as_microsecond();
    block_on(provider.store_reauth_nonce(&nonce, micros, 60)).unwrap();
    assert_eq!(
        block_on(provider.take_reauth_nonce(&nonce)).unwrap(),
        Some(micros)
    );
    assert_eq!(block_on(provider.take_reauth_nonce(&nonce)).unwrap(), None);
}

#[test]
fn replacing_session_preserves_old_on_collision_and_invalidates_on_success() {
    let (_, provider) = fixture();
    let record = session();
    block_on(provider.create("old", &record, 60)).unwrap();
    block_on(provider.create("occupied", &record, 60)).unwrap();
    assert_eq!(
        block_on(provider.create_replacing(Some("old"), "occupied", &record, 60)).unwrap(),
        LoginSessionCreate::Collision
    );
    assert!(
        block_on(provider.load(&SessionId::new("old")))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        block_on(provider.create_replacing(Some("old"), "new", &record, 60)).unwrap(),
        LoginSessionCreate::Created
    );
    assert!(
        block_on(provider.load(&SessionId::new("old")))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        block_on(provider.load(&SessionId::new("new")))
            .unwrap()
            .unwrap()
            .record(),
        &record
    );
    assert_eq!(
        block_on(provider.create_replacing(Some("new"), "new", &record, 60)).unwrap(),
        LoginSessionCreate::Collision
    );
    assert!(
        block_on(provider.load(&SessionId::new("new")))
            .unwrap()
            .is_some()
    );
}

#[test]
fn replacement_failure_rolls_back_new_session_and_keeps_old() {
    for failure in ["RAISE(ABORT,'injected storage failure')", "RAISE(IGNORE)"] {
        let (database, provider) = fixture();
        let record = session();
        block_on(provider.create("old", &record, 60)).unwrap();
        database
            .execute_sql(&format!(
                "CREATE TRIGGER fail_delete BEFORE DELETE ON nazo_state BEGIN SELECT {failure}; END"
            ))
            .unwrap();
        assert!(block_on(provider.create_replacing(Some("old"), "new", &record, 60)).is_err());
        assert!(
            block_on(provider.load(&SessionId::new("old")))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(provider.load(&SessionId::new("new")))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn state_writes_and_deletions_reject_ignored_required_effects() {
    block_on(async {
        let (database, provider) = fixture();
        database.execute_sql("CREATE TRIGGER suppress BEFORE INSERT ON nazo_state BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            DpopStateStorePort::issue_nonce(&provider, "nonce", 60)
                .await
                .is_err()
        );
        assert!(
            nazo_resource_server::DpopNonceStorage::issue_nonce(
                &provider,
                "nonce",
                Timestamp::now().as_second() + 60
            )
            .await
            .is_err()
        );
        database.execute_sql("DROP TRIGGER suppress").unwrap();
        provider.create("session", &session(), 60).await.unwrap();
        database.execute_sql("CREATE TRIGGER suppress BEFORE DELETE ON nazo_state BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(provider.delete(&SessionId::new("session")).await.is_err());
        assert!(
            provider
                .load(&SessionId::new("session"))
                .await
                .unwrap()
                .is_some()
        );
        assert!(!provider.delete(&SessionId::new("missing")).await.unwrap());
    });
}

#[test]
fn concurrent_session_rotations_create_exactly_one_replacement() {
    let (_, provider) = fixture();
    let old = SessionId::new("old");
    let record = session();
    block_on(provider.create("old", &record, 60)).unwrap();
    let snapshot = block_on(provider.load(&old)).unwrap().unwrap();
    let outcomes = std::thread::scope(|scope| {
        (0..24)
            .map(|index| {
                let provider = &provider;
                let record = &record;
                let old = &old;
                let expected = snapshot.version();
                scope.spawn(move || {
                    block_on(provider.rotate(
                        old,
                        expected,
                        &SessionId::new(format!("new-{index}")),
                        record,
                        60,
                    ))
                    .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == SessionRotationOutcome::Applied)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == SessionRotationOutcome::Conflict)
            .count(),
        23
    );
    assert!(block_on(provider.load(&old)).unwrap().is_none());
    assert_eq!(
        (0..24)
            .filter(
                |index| block_on(provider.load(&SessionId::new(format!("new-{index}"))))
                    .unwrap()
                    .is_some()
            )
            .count(),
        1
    );
}

#[test]
fn session_cas_fences_stale_rotation_and_preserves_expiry() {
    let (database, provider) = fixture();
    let id = SessionId::new("old");
    let record = session();
    block_on(provider.create("old", &record, 60)).unwrap();
    let snapshot = block_on(provider.load(&id)).unwrap().unwrap();
    let mut updated = record.clone();
    updated.add_amr("mfa");
    database.execute_sql("CREATE TRIGGER forbid_extend BEFORE UPDATE OF expires_at ON nazo_state WHEN NEW.expires_at != OLD.expires_at BEGIN SELECT RAISE(ABORT,'expiry changed'); END").unwrap();
    assert_eq!(
        block_on(provider.compare_and_set(&id, snapshot.version(), &updated)).unwrap(),
        SessionUpdateOutcome::Applied
    );
    assert_eq!(
        block_on(provider.compare_and_set(&id, snapshot.version(), &record)).unwrap(),
        SessionUpdateOutcome::Conflict
    );
    assert_eq!(
        block_on(provider.rotate(&id, snapshot.version(), &SessionId::new("new"), &record, 60))
            .unwrap(),
        SessionRotationOutcome::Conflict
    );
    assert_eq!(
        block_on(provider.load(&id)).unwrap().unwrap().record(),
        &updated
    );
    database.execute_sql("DROP TRIGGER forbid_extend; UPDATE nazo_state SET expires_at=unixepoch()-1 WHERE kind='session'").unwrap();
    assert_eq!(
        block_on(provider.compare_and_set(&id, snapshot.version(), &record)).unwrap(),
        SessionUpdateOutcome::Missing
    );
}

#[test]
fn session_rotation_collision_leaves_source_and_destination_unchanged() {
    let (_, provider) = fixture();
    let record = session();
    block_on(provider.create("old", &record, 60)).unwrap();
    block_on(provider.create("new", &record, 60)).unwrap();
    let old = SessionId::new("old");
    let snapshot = block_on(provider.load(&old)).unwrap().unwrap();
    assert_eq!(
        block_on(provider.rotate(
            &old,
            snapshot.version(),
            &SessionId::new("new"),
            &record,
            60
        ))
        .unwrap(),
        SessionRotationOutcome::Collision
    );
    assert!(block_on(provider.load(&old)).unwrap().is_some());
    assert!(
        block_on(provider.load(&SessionId::new("new")))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        block_on(provider.rotate(&old, snapshot.version(), &old, &record, 60)).unwrap(),
        SessionRotationOutcome::Collision
    );
}

#[test]
fn fixed_window_counter_is_atomic_and_resets_after_expiry() {
    let (database, provider) = fixture();
    let mut counts = std::thread::scope(|scope| {
        (0..32)
            .map(|_| {
                let provider = &provider;
                scope.spawn(move || {
                    block_on(provider.increment(RequestRateLimitBucket::Token, "client", 60))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    counts.sort_unstable();
    assert_eq!(counts, (1..=32).collect::<Vec<_>>());
    assert_eq!(
        block_on(provider.increment(RequestRateLimitBucket::Authentication, "client", 60)).unwrap(),
        1
    );
    database
        .execute_sql("UPDATE nazo_state SET expires_at=unixepoch()-1 WHERE kind='rate_token'")
        .unwrap();
    assert_eq!(
        block_on(provider.increment(RequestRateLimitBucket::Token, "client", 60)).unwrap(),
        1
    );
    block_on(provider.record_failure("email", "source", 60)).unwrap();
    assert_eq!(
        block_on(provider.failure_count("email", "source")).unwrap(),
        1
    );
    assert_eq!(
        block_on(provider.failure_count("email", "other")).unwrap(),
        0
    );
    block_on(provider.clear_failure("email", "source")).unwrap();
    assert_eq!(
        block_on(provider.failure_count("email", "source")).unwrap(),
        0
    );
}

#[test]
fn storage_failures_remain_errors_on_security_paths() {
    let (database, provider) = fixture();
    let nonce = Uuid::new_v4().to_string();
    database.execute_sql("DROP TABLE nazo_state").unwrap();
    assert!(block_on(provider.consume_replay("key", "proof", 60)).is_err());
    assert!(block_on(DpopStateStorePort::validate_nonce(&provider, &nonce)).is_err());
    assert!(block_on(provider.load(&SessionId::new("session"))).is_err());
    assert!(
        block_on(provider.increment(RequestRateLimitBucket::Authentication, "source", 60)).is_err()
    );
    assert!(block_on(provider.begin_authorization_code("code", Timestamp::now())).is_err());
}
