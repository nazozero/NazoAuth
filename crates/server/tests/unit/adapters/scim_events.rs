use std::{collections::BTreeMap, sync::Mutex};

use nazo_scim_events::{EventStoreError, SetError};
use uuid::Uuid;

use super::*;

struct Poller {
    requests: Mutex<Vec<ValidatedPollRequest>>,
    ready_on: usize,
    more_available: bool,
    error: Option<PollError>,
}

impl EventPollerPort for Poller {
    fn poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<PollResponse, PollError>> {
        Box::pin(async move {
            assert_eq!(receiver.token_id, Uuid::from_u128(1));
            let mut requests = self.requests.lock().unwrap();
            requests.push(request.clone());
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(PollResponse {
                sets: if requests.len() >= self.ready_on {
                    BTreeMap::from([("event".to_owned(), "signed-set".to_owned())])
                } else {
                    BTreeMap::new()
                },
                more_available: self.more_available,
            })
        })
    }
}

fn poller(ready_on: usize) -> ScimEventLongPoll<Poller> {
    ScimEventLongPoll::new(Poller {
        requests: Mutex::default(),
        ready_on,
        more_available: false,
        error: None,
    })
}

fn receiver() -> EventReceiver {
    EventReceiver {
        token_id: Uuid::from_u128(1),
        tenant_id: Uuid::from_u128(2),
        audience: "https://receiver.example".to_owned(),
    }
}

fn request() -> ValidatedPollRequest {
    ValidatedPollRequest {
        max_events: 10,
        return_immediately: false,
        ack: vec![Uuid::from_u128(3)],
        set_errors: BTreeMap::from([(
            Uuid::from_u128(4),
            SetError {
                err: "invalid_key".to_owned(),
                description: "The signing key is unavailable".to_owned(),
            },
        )]),
    }
}

#[tokio::test(start_paused = true)]
async fn long_poll_applies_dispositions_once_and_returns_arriving_events() {
    let poller = poller(3);
    let original = request();
    let started = tokio::time::Instant::now();
    let response = poller.poll(&receiver(), &original).await.unwrap();
    assert_eq!(response.sets["event"], "signed-set");
    assert_eq!(started.elapsed(), Duration::from_millis(500));
    let requests = poller.events.requests.lock().unwrap();
    assert_eq!(requests[0], original);
    assert!(requests[1..].iter().all(|request| {
        request.ack.is_empty()
            && request.set_errors.is_empty()
            && request.max_events == original.max_events
            && !request.return_immediately
    }));
}

#[tokio::test(start_paused = true)]
async fn empty_poll_finishes_at_the_existing_deadline() {
    let poller = poller(usize::MAX);
    let started = tokio::time::Instant::now();
    let response = poller.poll(&receiver(), &request()).await.unwrap();
    assert!(response.sets.is_empty());
    assert!(!response.more_available);
    assert_eq!(started.elapsed(), Duration::from_secs(30));
}

#[tokio::test(start_paused = true)]
async fn immediate_data_more_available_and_errors_do_not_wait() {
    let receiver = receiver();
    for case in 0..4 {
        let mut poller = poller(usize::MAX);
        let mut request = request();
        match case {
            0 => request.return_immediately = true,
            1 => poller.events.ready_on = 1,
            2 => poller.events.more_available = true,
            _ => poller.events.error = Some(EventStoreError::Unavailable.into()),
        }
        let started = tokio::time::Instant::now();
        let response = poller.poll(&receiver, &request).await;
        assert_eq!(response.is_err(), case == 3);
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(poller.events.requests.lock().unwrap().len(), 1);
    }
}
