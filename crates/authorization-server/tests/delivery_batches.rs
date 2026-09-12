//! Exercise the production single-batch workers without a scheduler or network.
use chrono::{DateTime, Duration, Utc};
use futures_executor::block_on;
use http::StatusCode;
use nazo_auth::BackchannelLogoutDelivery;
use nazo_identity::ports::{RepositoryError, RepositoryFuture};
use nazo_oauth_server::{
    ports::transient_state::{
        CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
        TransientStateError, TransientStateFuture,
    },
    workers::{
        backchannel_logout::{BackchannelLogoutSender, BackchannelLogoutWorker},
        ciba_ping::{CibaPingDeliveryWorker, CibaPingSender},
    },
};
use nazo_persistence::BackchannelLogoutDeliveryStore;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use uuid::Uuid;

type SendFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<StatusCode>> + Send + 'a>>;

#[derive(Clone)]
enum Reply {
    Status(u16),
    Transport(String),
}
#[derive(Default)]
struct SendState {
    started: Vec<usize>,
    completed: Vec<usize>,
    active: usize,
    peak: usize,
    released: HashSet<usize>,
    release_all: bool,
    replies: HashMap<usize, Reply>,
    waiting: HashMap<usize, Waker>,
}
#[derive(Default)]
struct Sender(Mutex<SendState>);
impl Sender {
    fn ready(replies: impl IntoIterator<Item = (usize, Reply)>) -> Self {
        Self(Mutex::new(SendState {
            release_all: true,
            replies: replies.into_iter().collect(),
            ..SendState::default()
        }))
    }
    fn release(&self, id: usize) {
        let wake = {
            let mut state = self.0.lock().unwrap();
            state.released.insert(id);
            state.waiting.remove(&id)
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn release_all(&self) {
        let wakes = {
            let mut state = self.0.lock().unwrap();
            state.release_all = true;
            std::mem::take(&mut state.waiting)
        };
        for wake in wakes.into_values() {
            wake.wake();
        }
    }
    fn send_id(&self, id: usize) -> SendFuture<'_> {
        Box::pin(async move {
            {
                let mut state = self.0.lock().unwrap();
                state.started.push(id);
                state.active += 1;
                state.peak = state.peak.max(state.active);
            }
            poll_fn(|context| {
                let mut state = self.0.lock().unwrap();
                if state.release_all || state.released.contains(&id) {
                    Poll::Ready(())
                } else {
                    state.waiting.insert(id, context.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            let reply = {
                let mut state = self.0.lock().unwrap();
                state.active -= 1;
                state.completed.push(id);
                state
                    .replies
                    .get(&id)
                    .cloned()
                    .unwrap_or(Reply::Status(200))
            };
            match reply {
                Reply::Status(status) => Ok(StatusCode::from_u16(status).unwrap()),
                Reply::Transport(error) => Err(anyhow::Error::msg(error)),
            }
        })
    }
}
impl CibaPingSender for Sender {
    fn send<'a>(&'a self, delivery: &'a CibaPingDelivery) -> SendFuture<'a> {
        self.send_id(delivery.auth_req_id_hash.parse().unwrap())
    }
}
impl BackchannelLogoutSender for Sender {
    fn send<'a>(&'a self, delivery: &'a BackchannelLogoutDelivery) -> SendFuture<'a> {
        self.send_id(delivery.id.as_u128() as usize)
    }
}
fn assert_pending(future: Pin<&mut impl Future>) {
    let waker = Waker::noop();
    assert!(future.poll(&mut Context::from_waker(waker)).is_pending());
}

struct PingStore {
    pending: Mutex<VecDeque<CibaPingDelivery>>,
    claims: Mutex<Vec<(i64, i64, usize)>>,
    finished: Mutex<Vec<(CibaPingDelivery, CibaPingFinishOutcome)>>,
    results: HashMap<String, Result<CibaPingFinishResult, TransientStateError>>,
}
impl PingStore {
    fn new(deliveries: impl IntoIterator<Item = CibaPingDelivery>) -> Self {
        Self {
            pending: Mutex::new(deliveries.into_iter().collect()),
            claims: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
            results: HashMap::new(),
        }
    }
}
impl CibaPingDeliveryPort for PingStore {
    fn claim_due<'a>(
        &'a self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'a, Vec<CibaPingDelivery>> {
        Box::pin(async move {
            self.claims.lock().unwrap().push((now, lock_until, limit));
            let mut pending = self.pending.lock().unwrap();
            let count = limit.min(pending.len());
            Ok(pending.drain(..count).collect())
        })
    }
    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async move {
            self.finished
                .lock()
                .unwrap()
                .push((delivery.clone(), outcome));
            self.results
                .get(&delivery.auth_req_id_hash)
                .copied()
                .unwrap_or(Ok(CibaPingFinishResult::Applied))
        })
    }
}
fn ping(id: usize) -> CibaPingDelivery {
    CibaPingDelivery {
        auth_req_id_hash: id.to_string(),
        auth_req_id: format!("auth-request-{id}"),
        endpoint: "https://client.example/ping".into(),
        client_notification_token: format!("notification-{id}"),
        attempts: 1,
        expires_at: Utc::now().timestamp() + 300,
    }
}

#[test]
fn ciba_batch_bounds_claim_and_concurrency_and_drains_before_first_error() {
    let originals = (0..12).map(ping).collect::<Vec<_>>();
    let mut store = PingStore::new(originals.clone());
    store
        .results
        .insert("0".into(), Err(TransientStateError::CorruptData));
    store
        .results
        .insert("1".into(), Err(TransientStateError::Unavailable));
    let store = Arc::new(store);
    let sender = Arc::new(Sender::default());
    let worker = CibaPingDeliveryWorker::new(store.clone(), sender.clone());
    let mut batch = Box::pin(worker.process_due_batch());
    assert_pending(batch.as_mut());
    assert_eq!(sender.0.lock().unwrap().active, 8);
    assert_eq!(sender.0.lock().unwrap().started.len(), 8);
    let claims = store.claims.lock().unwrap().clone();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].1 - claims[0].0, 15);
    assert_eq!(claims[0].2, 8);
    sender.release(0);
    assert_pending(batch.as_mut());
    assert_eq!(store.finished.lock().unwrap().len(), 1);
    sender.release_all();
    let error =
        block_on(batch).expect_err("the first finish error must be returned after draining");
    assert!(format!("{error:#}").contains("transient state is corrupt"));
    let state = sender.0.lock().unwrap();
    assert_eq!((state.peak, state.active, state.completed.len()), (8, 0, 8));
    drop(state);
    let finished = store.finished.lock().unwrap();
    assert_eq!(finished.len(), 8);
    for (delivery, outcome) in finished.iter() {
        assert_eq!(
            delivery,
            &originals[delivery.auth_req_id_hash.parse::<usize>().unwrap()]
        );
        assert_eq!(*outcome, CibaPingFinishOutcome::Delivered);
    }
    assert_eq!(store.pending.lock().unwrap().len(), 4);
}

#[test]
fn ciba_finish_missing_and_conflict_preserve_fencing_and_are_nonfatal() {
    let mut deliveries = vec![ping(0), ping(1), ping(2)];
    deliveries[0].attempts = 7;
    deliveries[1].attempts = 11;
    let mut store = PingStore::new(deliveries.clone());
    store
        .results
        .insert("0".into(), Ok(CibaPingFinishResult::Missing));
    store
        .results
        .insert("1".into(), Ok(CibaPingFinishResult::Conflict));
    let store = Arc::new(store);
    let worker = CibaPingDeliveryWorker::new(store.clone(), Arc::new(Sender::ready([])));
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 3);
    let finished = store.finished.lock().unwrap();
    assert_eq!(finished.len(), deliveries.len());
    for original in &deliveries {
        assert_eq!(
            finished
                .iter()
                .filter(|(delivery, _)| delivery == original)
                .count(),
            1
        );
    }
    drop(finished);
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 0);
}

#[test]
fn ciba_sender_status_and_transport_errors_reach_retry_and_terminal_finishes() {
    for (reply, attempts, delay) in [
        (Reply::Status(200), 1, None),
        (Reply::Status(299), 1, None),
        (Reply::Status(302), 1, None),
        (Reply::Status(429), 1, None),
        (Reply::Status(500), 1, Some(1)),
        (Reply::Status(503), 2, Some(3)),
        (Reply::Transport("network unavailable".into()), 3, Some(9)),
        (Reply::Status(503), 4, None),
    ] {
        let delivered = matches!(&reply, Reply::Status(200..=299));
        let mut delivery = ping(0);
        delivery.attempts = attempts;
        let store = Arc::new(PingStore::new([delivery.clone()]));
        let sender = Arc::new(Sender::ready([(0, reply)]));
        let worker = CibaPingDeliveryWorker::new(store.clone(), sender);
        let before = Utc::now().timestamp();
        assert_eq!(block_on(worker.process_due_batch()).unwrap(), 1);
        let after = Utc::now().timestamp();
        let finished = store.finished.lock().unwrap();
        assert_eq!(finished[0].0, delivery);
        match (delay, finished[0].1) {
            (Some(delay), CibaPingFinishOutcome::RetryAt(next)) => {
                assert!((before + delay..=after + delay).contains(&next));
                assert!(next < delivery.expires_at);
            }
            (None, outcome) => assert_eq!(
                outcome,
                if delivered {
                    CibaPingFinishOutcome::Delivered
                } else {
                    CibaPingFinishOutcome::Failed
                }
            ),
            _ => panic!("retry classification must be preserved"),
        }
    }
    let mut delivery = ping(0);
    delivery.expires_at = Utc::now().timestamp() + 1;
    let store = Arc::new(PingStore::new([delivery]));
    let worker = CibaPingDeliveryWorker::new(
        store.clone(),
        Arc::new(Sender::ready([(0, Reply::Status(503))])),
    );
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 1);
    assert_eq!(
        store.finished.lock().unwrap()[0].1,
        CibaPingFinishOutcome::Failed,
        "retry at or after expiry is terminal"
    );
}

#[derive(Debug)]
enum LogoutFinish {
    Complete(Uuid, i32),
    Fail(Uuid, i32, Option<DateTime<Utc>>, String),
}
struct LogoutStore {
    pending: Mutex<VecDeque<BackchannelLogoutDelivery>>,
    claims: Mutex<Vec<(i64, i32)>>,
    finished: Mutex<Vec<LogoutFinish>>,
    errors: HashMap<Uuid, RepositoryError>,
}
impl LogoutStore {
    fn new(deliveries: impl IntoIterator<Item = BackchannelLogoutDelivery>) -> Self {
        Self {
            pending: Mutex::new(deliveries.into_iter().collect()),
            claims: Mutex::new(Vec::new()),
            finished: Mutex::new(Vec::new()),
            errors: HashMap::new(),
        }
    }
    fn result(&self, id: Uuid) -> Result<(), RepositoryError> {
        self.errors.get(&id).cloned().map_or(Ok(()), Err)
    }
}
impl BackchannelLogoutDeliveryStore for LogoutStore {
    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> RepositoryFuture<'_, Vec<BackchannelLogoutDelivery>> {
        Box::pin(async move {
            self.claims
                .lock()
                .unwrap()
                .push((limit, lock_timeout_seconds));
            let mut pending = self.pending.lock().unwrap();
            let count = usize::try_from(limit).unwrap().min(pending.len());
            Ok(pending.drain(..count).collect())
        })
    }
    fn complete(&self, delivery_id: Uuid, expected_attempts: i32) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.finished
                .lock()
                .unwrap()
                .push(LogoutFinish::Complete(delivery_id, expected_attempts));
            self.result(delivery_id)
        })
    }
    fn fail<'a>(
        &'a self,
        delivery_id: Uuid,
        expected_attempts: i32,
        next_attempt_at: Option<DateTime<Utc>>,
        last_error: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.finished.lock().unwrap().push(LogoutFinish::Fail(
                delivery_id,
                expected_attempts,
                next_attempt_at,
                last_error.to_owned(),
            ));
            self.result(delivery_id)
        })
    }
}
fn logout(id: usize) -> BackchannelLogoutDelivery {
    BackchannelLogoutDelivery {
        id: Uuid::from_u128(id as u128),
        logout_uri: "https://client.example/logout".into(),
        logout_token: format!("signed-logout-{id}"),
        attempts: 1,
        expires_at: Utc::now() + Duration::seconds(300),
    }
}

#[test]
fn logout_batch_keeps_twenty_claims_eight_senders_and_drains_before_first_error() {
    let mut deliveries = (0..25).map(logout).collect::<Vec<_>>();
    for (index, delivery) in deliveries.iter_mut().enumerate() {
        delivery.attempts = i32::try_from(index + 3).unwrap();
    }
    let mut store = LogoutStore::new(deliveries.clone());
    store.errors.insert(
        deliveries[0].id,
        RepositoryError::Unexpected("first-finish".into()),
    );
    store
        .errors
        .insert(deliveries[1].id, RepositoryError::Unavailable);
    let store = Arc::new(store);
    let sender = Arc::new(Sender::default());
    let worker = BackchannelLogoutWorker::from_port(store.clone(), sender.clone());
    let mut batch = Box::pin(worker.process_due_batch());
    assert_pending(batch.as_mut());
    assert_eq!(*store.claims.lock().unwrap(), vec![(20, 300)]);
    assert_eq!(sender.0.lock().unwrap().active, 8);
    sender.release(0);
    assert_pending(batch.as_mut());
    assert_eq!(store.finished.lock().unwrap().len(), 1);
    assert_eq!(sender.0.lock().unwrap().started.len(), 9);
    assert_eq!(sender.0.lock().unwrap().active, 8);
    sender.release_all();
    let error = block_on(batch).expect_err("finish failure survives after every item is processed");
    assert!(format!("{error:#}").contains("first-finish"));
    let state = sender.0.lock().unwrap();
    assert_eq!(
        (state.peak, state.active, state.completed.len()),
        (8, 0, 20)
    );
    drop(state);
    let finished = store.finished.lock().unwrap();
    assert_eq!(finished.len(), 20);
    for finish in finished.iter() {
        let LogoutFinish::Complete(id, attempts) = finish else {
            panic!("successful send must complete")
        };
        assert_eq!(
            *attempts,
            deliveries[id.as_u128() as usize].attempts,
            "the claimed attempt is the write fence"
        );
    }
    assert_eq!(store.pending.lock().unwrap().len(), 5);
}

#[test]
fn logout_worker_routes_statuses_and_preserves_retry_fences_and_error_bounds() {
    for (reply, attempts, delay) in [
        (Reply::Status(200), 1, None),
        (Reply::Status(204), 1, None),
        (Reply::Status(201), 1, None),
        (Reply::Status(400), 1, None),
        (Reply::Status(408), 1, Some(5)),
        (Reply::Status(425), 2, Some(15)),
        (Reply::Status(429), 3, Some(45)),
        (Reply::Status(503), 1, Some(5)),
        (Reply::Transport("界".repeat(600)), 2, Some(15)),
        (Reply::Status(503), 4, None),
    ] {
        let delivered = matches!(&reply, Reply::Status(200 | 204));
        let long_transport_error = matches!(&reply, Reply::Transport(_));
        let mut delivery = logout(0);
        delivery.attempts = attempts;
        let store = Arc::new(LogoutStore::new([delivery.clone()]));
        let worker = BackchannelLogoutWorker::from_port(
            store.clone(),
            Arc::new(Sender::ready([(0, reply)])),
        );
        let before = Utc::now();
        assert_eq!(block_on(worker.process_due_batch()).unwrap(), 1);
        let after = Utc::now();
        let finished = store.finished.lock().unwrap();
        assert_eq!(finished.len(), 1);
        match &finished[0] {
            LogoutFinish::Complete(id, fence) => {
                assert!(delivered);
                assert_eq!((*id, *fence), (delivery.id, attempts));
            }
            LogoutFinish::Fail(id, fence, next, error) => {
                assert!(!delivered);
                assert_eq!((*id, *fence), (delivery.id, attempts));
                assert!(error.chars().count() <= 512);
                if long_transport_error {
                    assert_eq!(error, &"界".repeat(512));
                }
                match (delay, next) {
                    (Some(delay), Some(next)) => {
                        assert!(*next >= before + Duration::seconds(delay));
                        assert!(*next <= after + Duration::seconds(delay));
                        assert!(*next < delivery.expires_at);
                    }
                    (None, None) => {}
                    _ => panic!("retry attempt indexing must be preserved"),
                }
            }
        }
    }
}

#[test]
fn logout_retry_cannot_be_scheduled_at_or_after_expiry() {
    let mut delivery = logout(0);
    delivery.expires_at = Utc::now() + Duration::seconds(5);
    let store = Arc::new(LogoutStore::new([delivery]));
    let worker = BackchannelLogoutWorker::from_port(
        store.clone(),
        Arc::new(Sender::ready([(0, Reply::Status(503))])),
    );
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 1);
    assert!(matches!(
        store.finished.lock().unwrap()[0],
        LogoutFinish::Fail(_, 1, None, _)
    ));
    assert_eq!(block_on(worker.process_due_batch()).unwrap(), 0);
}
