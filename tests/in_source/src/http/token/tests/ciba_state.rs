use super::*;
use crate::support::{ValkeyAtomicResult, valkey_atomic_snapshot, valkey_eval_string};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Client as ValkeyClient, Config as ValkeyConfig, ConnectionConfig,
    PerformanceConfig,
};
use std::time::Duration as StdDuration;

fn pending_state(now: i64) -> CibaRequestState {
    CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        binding_message: Some("Read the number".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
    }
}

async fn live_valkey() -> Option<ValkeyClient> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_secs(1);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_secs(1);
        connection.internal_command_timeout = StdDuration::from_secs(1);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("Valkey client should build");
    valkey.init().await.expect("Valkey should connect");
    Some(valkey)
}

async fn valkey_server_time(valkey: &ValkeyClient) -> i64 {
    valkey_eval_string(
        valkey,
        "return tostring(redis.call('TIME')[1])",
        Vec::new(),
        Vec::new(),
    )
    .await
    .expect("Valkey TIME should be readable")
    .parse()
    .expect("Valkey TIME should be an integer")
}

async fn stage_at_deadline(valkey: &ValkeyClient, key: &str, raw: &str, deadline: i64) {
    let reply = valkey_eval_string(
        valkey,
        "redis.call('SET', KEYS[1], ARGV[1]); redis.call('EXPIREAT', KEYS[1], ARGV[2]); return tostring(redis.call('EXPIRETIME', KEYS[1]))",
        vec![key.to_owned()],
        vec![raw.to_owned(), deadline.to_string()],
    )
    .await
    .expect("state should be staged");
    assert_eq!(reply.parse::<i64>().unwrap(), deadline);
}

#[test]
fn ciba_poll_transition_preserves_absolute_deadlines() {
    let state = pending_state(1_000);
    let CibaPollTransition::AuthorizationPending(next) = evaluate_ciba_poll(&state, 1_001) else {
        panic!("first pending poll must commit authorization_pending")
    };

    assert_eq!(next.expires_at, state.expires_at);
    assert_eq!(next.retention_expires_at, state.retention_expires_at);
    assert_eq!(next.last_poll_at, Some(1_001));
}

#[test]
fn every_committed_premature_poll_adds_exactly_five_seconds() {
    let mut state = pending_state(1_000);
    state.last_poll_at = Some(1_000);

    for expected in [10, 15, 20] {
        let CibaPollTransition::SlowDown(next) = evaluate_ciba_poll(&state, 1_001) else {
            panic!("premature poll must commit slow_down")
        };
        assert_eq!(next.interval_seconds, expected);
        assert_eq!(next.expires_at, 1_060);
        assert_eq!(next.retention_expires_at, 1_180);
        state = next;
    }
}

#[test]
fn ciba_poll_selects_terminal_states_before_protocol_success() {
    let mut state = pending_state(1_000);
    assert!(matches!(
        evaluate_ciba_poll(&state, state.expires_at),
        CibaPollTransition::Expired
    ));

    state.status = CibaStatus::Approved;
    assert!(matches!(
        evaluate_ciba_poll(&state, 1_001),
        CibaPollTransition::Approved
    ));

    state.status = CibaStatus::Denied;
    assert!(matches!(
        evaluate_ciba_poll(&state, 1_001),
        CibaPollTransition::Denied
    ));
}

#[test]
fn ciba_decision_rejects_mismatch_terminal_and_expired_states() {
    let state = pending_state(1_000);
    assert!(matches!(
        evaluate_ciba_decision(&state, Some(Uuid::now_v7()), CibaDecision::Approve, 1_001),
        CibaDecisionEvaluation::UserMismatch
    ));

    let mut terminal = state.clone();
    terminal.status = CibaStatus::Approved;
    assert!(matches!(
        evaluate_ciba_decision(&terminal, Some(terminal.user_id), CibaDecision::Deny, 1_001),
        CibaDecisionEvaluation::AlreadyHandled
    ));

    assert!(matches!(
        evaluate_ciba_decision(
            &state,
            Some(state.user_id),
            CibaDecision::Approve,
            state.expires_at
        ),
        CibaDecisionEvaluation::Expired
    ));
}

#[test]
fn ciba_decision_changes_only_status() {
    let state = pending_state(1_000);
    let CibaDecisionEvaluation::Commit(next) =
        evaluate_ciba_decision(&state, Some(state.user_id), CibaDecision::Approve, 1_001)
    else {
        panic!("valid decision should produce a terminal replacement")
    };

    assert_eq!(next.status, CibaStatus::Approved);
    assert_eq!(next.expires_at, state.expires_at);
    assert_eq!(next.retention_expires_at, state.retention_expires_at);
    assert_eq!(next.interval_seconds, state.interval_seconds);
    assert_eq!(next.last_poll_at, state.last_poll_at);
}

#[actix_web::test]
async fn legacy_ciba_state_migrates_from_actual_expiretime() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let auth_req_id = format!("legacy-{}", Uuid::now_v7());
    let key = ciba_request_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 180;
    let raw = serde_json::json!({
        "client_id": "client-1",
        "user_id": Uuid::now_v7(),
        "scopes": ["openid"],
        "audiences": ["resource://default"],
        "issued_at": now,
        "status": "pending",
        "interval_seconds": 5,
        "expires_at": now + 60,
        "last_poll_at": null
    })
    .to_string();
    stage_at_deadline(&valkey, &key, &raw, deadline).await;

    let stored = load_ciba_request_state(&valkey, &auth_req_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(stored.raw, raw);
    assert_eq!(stored.state.retention_expires_at, deadline);
    assert!(!stored.raw.contains("retention_expires_at"));
}

#[actix_web::test]
async fn ciba_state_rejects_deadline_that_disagrees_with_expiretime() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let auth_req_id = format!("mismatch-{}", Uuid::now_v7());
    let key = ciba_request_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 180;
    let mut state = pending_state(now);
    state.retention_expires_at = deadline - 1;
    stage_at_deadline(
        &valkey,
        &key,
        &serde_json::to_string(&state).unwrap(),
        deadline,
    )
    .await;

    let error = load_ciba_request_state(&valkey, &auth_req_id)
        .await
        .expect_err("mismatched deadline must fail closed");

    assert!(matches!(error, CibaStateError::Malformed(_)));
}

#[actix_web::test]
async fn ciba_compare_set_persists_legacy_deadline_without_refreshing_it() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let auth_req_id = format!("replace-{}", Uuid::now_v7());
    let key = ciba_request_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);

    assert_eq!(
        create_ciba_request_state(&valkey, &auth_req_id, &state)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    let stored = load_ciba_request_state(&valkey, &auth_req_id)
        .await
        .unwrap()
        .unwrap();
    let CibaPollTransition::AuthorizationPending(next) = evaluate_ciba_poll(&stored.state, now + 1)
    else {
        panic!("poll should remain pending")
    };

    assert_eq!(
        replace_ciba_request_state(&valkey, &auth_req_id, &stored.raw, &next)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    let snapshot = valkey_atomic_snapshot(&valkey, &key)
        .await
        .unwrap()
        .unwrap();
    let replaced: CibaRequestState = serde_json::from_str(&snapshot.raw).unwrap();
    assert_eq!(snapshot.expire_at, state.retention_expires_at);
    assert_eq!(replaced.expires_at, state.expires_at);
    assert_eq!(replaced.retention_expires_at, state.retention_expires_at);
}
