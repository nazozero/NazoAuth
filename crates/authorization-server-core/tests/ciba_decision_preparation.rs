use std::sync::{Arc, Mutex};

use futures_executor::block_on;
use nazo_auth::{
    CibaAtomicResult, CibaDecision, CibaDecisionFailure, CibaRequestState, CibaService,
    CibaStateFuture, CibaStatePortError, CibaStateStorePort, CibaStatus, CibaStoredRequest,
};
use uuid::Uuid;

struct Store {
    state: Mutex<Option<(CibaRequestState, u64)>>,
    calls: Mutex<Vec<&'static str>>,
    unknown_replace: bool,
}
impl Store {
    fn new(unknown_replace: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Some((
                CibaRequestState {
                    client_id: "client".into(),
                    user_id: Uuid::from_u128(7),
                    scopes: vec!["openid".into()],
                    audiences: vec!["resource".into()],
                    acr: None,
                    authentication_context: None,
                    binding_message: Some("binding".into()),
                    issued_at: 1_000,
                    status: CibaStatus::Pending,
                    interval_seconds: 5,
                    expires_at: 1_060,
                    retention_expires_at: 1_180,
                    last_poll_at: None,
                    ping_notification: None,
                },
                1,
            ))),
            calls: Mutex::new(vec![]),
            unknown_replace,
        })
    }
    fn change(&self, change: impl FnOnce(&mut CibaRequestState)) {
        let mut state = self.state.lock().unwrap();
        let (state, version) = state.as_mut().unwrap();
        change(state);
        *version += 1;
    }
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}
impl CibaStateStorePort for Store {
    type Version = u64;
    fn load<'a>(&'a self, id: &'a str) -> CibaStateFuture<'a, Option<CibaStoredRequest<u64>>> {
        assert_eq!(id, "prepared-request");
        self.calls.lock().unwrap().push("load");
        Box::pin(async {
            Ok(self
                .state
                .lock()
                .unwrap()
                .as_ref()
                .map(|(state, version)| CibaStoredRequest::new(state.clone(), *version)))
        })
    }
    fn create<'a>(
        &'a self,
        _: &'a str,
        _: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        panic!("decision tests must not create state")
    }
    fn replace<'a>(
        &'a self,
        id: &'a str,
        version: &'a u64,
        replacement: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        assert_eq!(id, "prepared-request");
        self.calls.lock().unwrap().push("replace");
        Box::pin(async move {
            let mut stored = self.state.lock().unwrap();
            let Some((state, current)) = stored.as_mut() else {
                return Ok(CibaAtomicResult::Conflict);
            };
            if *version != *current {
                return Ok(CibaAtomicResult::Conflict);
            }
            assert_eq!(state.retention_expires_at, replacement.retention_expires_at);
            *state = replacement.clone();
            *current += 1;
            if self.unknown_replace {
                return Err(CibaStatePortError::Unavailable);
            }
            Ok(CibaAtomicResult::Applied)
        })
    }
    fn delete<'a>(
        &'a self,
        id: &'a str,
        version: &'a u64,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        assert_eq!(id, "prepared-request");
        self.calls.lock().unwrap().push("delete");
        Box::pin(async move {
            let mut stored = self.state.lock().unwrap();
            if stored
                .as_ref()
                .is_none_or(|(_, current)| current != version)
            {
                return Ok(CibaAtomicResult::Conflict);
            }
            *stored = None;
            Ok(CibaAtomicResult::Applied)
        })
    }
}

#[test]
fn prepared_ciba_decision_reuses_validated_snapshot_and_bound_handle() {
    block_on(async {
        let store = Store::new(false);
        let service = CibaService::new(store.clone());
        let prepared = service
            .prepare_decision("prepared-request")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepared.state().client_id, "client");
        let committed = service
            .decide_prepared(
                prepared,
                CibaDecision::Deny,
                Some(Uuid::from_u128(7)),
                || 1_001,
            )
            .await
            .unwrap();
        assert_eq!(committed.state.status, CibaStatus::Denied);
        assert_eq!(store.calls(), ["load", "replace"]);
    });
}

#[test]
fn prepared_ciba_decision_rechecks_time_and_user_after_preparation() {
    block_on(async {
        for (now, user, expected) in [
            (1_060, Uuid::from_u128(7), CibaDecisionFailure::Expired),
            (1_001, Uuid::from_u128(8), CibaDecisionFailure::UserMismatch),
        ] {
            let store = Store::new(false);
            let service = CibaService::new(store.clone());
            let prepared = service
                .prepare_decision("prepared-request")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                service
                    .decide_prepared(prepared, CibaDecision::Deny, Some(user), || now)
                    .await
                    .unwrap_err(),
                expected
            );
            assert_eq!(
                store.calls(),
                if now == 1_060 {
                    vec!["load", "delete"]
                } else {
                    vec!["load"]
                }
            );
        }
    });
}

#[test]
fn prepared_ciba_conflict_reloads_poll_timing_but_rejects_changed_authorization() {
    block_on(async {
        for retarget in [false, true] {
            let store = Store::new(false);
            let service = CibaService::new(store.clone());
            let prepared = service
                .prepare_decision("prepared-request")
                .await
                .unwrap()
                .unwrap();
            store.change(|state| {
                state.last_poll_at = Some(1_001);
                state.interval_seconds = 10;
                if retarget {
                    state.client_id = "different-client".into();
                }
            });
            let result = service
                .decide_prepared(
                    prepared,
                    CibaDecision::Deny,
                    Some(Uuid::from_u128(7)),
                    || 1_002,
                )
                .await;
            if retarget {
                assert_eq!(
                    result.unwrap_err(),
                    CibaDecisionFailure::Storage(CibaStatePortError::CorruptData)
                );
                assert_eq!(store.calls(), ["load", "replace", "load"]);
                assert_eq!(
                    store.state.lock().unwrap().as_ref().unwrap().0.status,
                    CibaStatus::Pending
                );
            } else {
                let committed = result.unwrap();
                assert_eq!(committed.state.last_poll_at, Some(1_001));
                assert_eq!(committed.state.interval_seconds, 10);
                assert_eq!(committed.state.retention_expires_at, 1_180);
                assert_eq!(store.calls(), ["load", "replace", "load", "replace"]);
            }
        }
    });
}

#[test]
fn prepared_ciba_unknown_write_outcome_stops_without_retrying_or_claiming_commit() {
    block_on(async {
        let store = Store::new(true);
        let service = CibaService::new(store.clone());
        let prepared = service
            .prepare_decision("prepared-request")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            service
                .decide_prepared(prepared, CibaDecision::Deny, None, || 1_001)
                .await
                .unwrap_err(),
            CibaDecisionFailure::Storage(CibaStatePortError::Unavailable)
        );
        assert_eq!(store.calls(), ["load", "replace"]);
        assert_eq!(
            store.state.lock().unwrap().as_ref().unwrap().0.status,
            CibaStatus::Denied
        );
    });
}
