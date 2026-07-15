use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use chrono::DateTime;
use nazo_scim_events::*;
use serde_json::json;
use uuid::Uuid;

#[derive(Clone)]
struct FakeStore {
    page: EventPage,
}

impl EventStorePort for FakeStore {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        _receiver: &'a EventReceiver,
        _request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<EventPage, EventStoreError>> {
        let page = self.page.clone();
        Box::pin(async move { Ok(page) })
    }
}

#[derive(Clone, Default)]
struct RecordingSigner {
    claims: Arc<Mutex<Vec<SecurityEventClaims>>>,
}

impl EventSignerPort for RecordingSigner {
    fn sign<'a>(
        &'a self,
        claims: &'a SecurityEventClaims,
    ) -> EventFuture<'a, Result<String, EventSigningError>> {
        self.claims.lock().unwrap().push(claims.clone());
        let token = format!("signed:{}", claims.jti);
        Box::pin(async move { Ok(token) })
    }
}

#[test]
fn notice_claims_use_sub_id_and_exactly_one_payload_mode() {
    let tenant_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let txn = Uuid::now_v7();
    let event = StoredEvent::patch_notice(
        tenant_id,
        user_id,
        txn,
        DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        &[
            "emails".to_owned(),
            "active".to_owned(),
            "emails".to_owned(),
        ],
        Some(false),
    );
    let claims = SecurityEventClaims::from_stored(
        event,
        "https://issuer.example",
        "https://receiver.example/events",
    );
    let encoded = serde_json::to_value(&claims).unwrap();

    assert!(encoded.get("sub").is_none());
    assert_eq!(encoded["txn"], txn.to_string());
    assert_eq!(encoded["sub_id"]["format"], "scim");
    assert_eq!(encoded["sub_id"]["uri"], format!("/Users/{user_id}"));
    assert_eq!(
        encoded["events"][PATCH_NOTICE_EVENT]["attributes"],
        json!(["active", "emails"])
    );
    assert_eq!(encoded["events"][DEACTIVATE_EVENT], json!({}));
    assert!(encoded["events"][PATCH_NOTICE_EVENT].get("data").is_none());
}

#[test]
fn poll_request_rejects_ambiguous_or_unbounded_dispositions() {
    let event_id = Uuid::now_v7().to_string();
    let request = PollRequest {
        max_events: Some(MAX_POLL_EVENTS + 1),
        ..PollRequest::default()
    };
    assert_eq!(request.validate(), Err(PollRequestError::TooManyEvents));

    let request = PollRequest {
        ack: vec![event_id.clone()],
        set_errors: BTreeMap::from([(
            event_id,
            SetError {
                err: "invalid_key".to_owned(),
                description: "key rejected".to_owned(),
            },
        )]),
        ..PollRequest::default()
    };
    assert_eq!(
        request.validate(),
        Err(PollRequestError::ConflictingDisposition)
    );
}

#[test]
fn mutation_context_is_default_closed_and_uses_uuidv7() {
    assert_eq!(MutationContext::default().transaction_id(), None);
    assert_eq!(
        MutationContext::enabled()
            .transaction_id()
            .unwrap()
            .get_version_num(),
        7
    );
}

#[tokio::test]
async fn publisher_binds_each_set_to_issuer_receiver_and_event_id() {
    let event = StoredEvent::create_notice(
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    );
    let event_id = event.id;
    let signer = RecordingSigner::default();
    let recorded = Arc::clone(&signer.claims);
    let publisher = EventPublisher::new(
        FakeStore {
            page: EventPage {
                events: vec![event],
                more_available: false,
            },
        },
        signer,
        "https://issuer.example".to_owned(),
    );
    let response = publisher
        .poll(
            &EventReceiver {
                token_id: Uuid::now_v7(),
                tenant_id: Uuid::now_v7(),
                audience: "https://receiver.example/events".to_owned(),
            },
            &PollRequest {
                return_immediately: true,
                ..PollRequest::default()
            }
            .validate()
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.sets.get(&event_id.to_string()),
        Some(&format!("signed:{event_id}"))
    );
    assert!(!response.more_available);
    let claims = recorded.lock().unwrap();
    assert_eq!(claims[0].iss, "https://issuer.example");
    assert_eq!(claims[0].aud, ["https://receiver.example/events"]);
    assert_eq!(claims[0].jti, event_id.to_string());
    assert_eq!(
        serde_json::to_value(&response).unwrap()["moreAvailable"],
        false
    );
}
