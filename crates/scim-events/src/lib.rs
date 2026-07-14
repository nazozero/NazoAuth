//! RFC 9967 SCIM Security Event Token domain model and RFC 8936 polling contract.
//!
//! This crate deliberately contains no HTTP, database, or key-management code.
//! Adapters persist [`StoredEvent`] records and sign [`SecurityEventClaims`].

use std::{collections::BTreeMap, future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub const CREATE_NOTICE_EVENT: &str = "urn:ietf:params:scim:event:prov:create:notice";
pub const PATCH_NOTICE_EVENT: &str = "urn:ietf:params:scim:event:prov:patch:notice";
pub const PUT_NOTICE_EVENT: &str = "urn:ietf:params:scim:event:prov:put:notice";
pub const DELETE_EVENT: &str = "urn:ietf:params:scim:event:prov:delete";
pub const ACTIVATE_EVENT: &str = "urn:ietf:params:scim:event:prov:activate";
pub const DEACTIVATE_EVENT: &str = "urn:ietf:params:scim:event:prov:deactivate";
pub const SECURITY_EVENT_MEDIA_TYPE: &str = "secevent+jwt";
pub const SCIM_EVENTS_SCOPE: &str = "scim:events";
pub const DEFAULT_POLL_EVENTS: u16 = 20;
pub const MAX_POLL_EVENTS: u16 = 100;

pub const SUPPORTED_EVENT_URIS: [&str; 5] = [
    CREATE_NOTICE_EVENT,
    PATCH_NOTICE_EVENT,
    PUT_NOTICE_EVENT,
    ACTIVATE_EVENT,
    DEACTIVATE_EVENT,
];

/// Per-write instruction passed through the identity persistence boundary.
///
/// Disabled operations never create outbox records. Enabled operations carry
/// one stable transaction identifier shared by every aspect of that mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationContext {
    transaction_id: Option<Uuid>,
}

impl MutationContext {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            transaction_id: None,
        }
    }

    #[must_use]
    pub fn enabled() -> Self {
        Self {
            transaction_id: Some(Uuid::now_v7()),
        }
    }

    #[must_use]
    pub const fn transaction_id(self) -> Option<Uuid> {
        self.transaction_id
    }
}

impl Default for MutationContext {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub transaction_id: Uuid,
    pub subject_uri: String,
    pub events: BTreeMap<String, Value>,
    pub occurred_at: DateTime<Utc>,
}

impl StoredEvent {
    #[must_use]
    pub fn create_notice(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self::notice(
            tenant_id,
            user_id,
            transaction_id,
            occurred_at,
            CREATE_NOTICE_EVENT,
            &["active", "emails", "id", "name", "userName"],
            None,
        )
    }

    #[must_use]
    pub fn put_notice(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
        active_transition: Option<bool>,
    ) -> Self {
        Self::notice(
            tenant_id,
            user_id,
            transaction_id,
            occurred_at,
            PUT_NOTICE_EVENT,
            &["active", "emails", "name", "userName"],
            active_transition,
        )
    }

    #[must_use]
    pub fn patch_notice(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
        attributes: &[String],
        active_transition: Option<bool>,
    ) -> Self {
        Self::notice(
            tenant_id,
            user_id,
            transaction_id,
            occurred_at,
            PATCH_NOTICE_EVENT,
            attributes,
            active_transition,
        )
    }

    #[must_use]
    pub fn deactivate(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        let mut events = BTreeMap::new();
        events.insert(DEACTIVATE_EVENT.to_owned(), json!({}));
        Self::new(tenant_id, user_id, transaction_id, occurred_at, events)
    }

    fn notice(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
        event_uri: &str,
        attributes: &[impl AsRef<str>],
        active_transition: Option<bool>,
    ) -> Self {
        let mut attributes = attributes
            .iter()
            .map(|value| value.as_ref().to_owned())
            .collect::<Vec<_>>();
        attributes.sort();
        attributes.dedup();
        let mut events = BTreeMap::new();
        events.insert(event_uri.to_owned(), json!({"attributes": attributes}));
        if let Some(active) = active_transition {
            events.insert(
                if active {
                    ACTIVATE_EVENT
                } else {
                    DEACTIVATE_EVENT
                }
                .to_owned(),
                json!({}),
            );
        }
        Self::new(tenant_id, user_id, transaction_id, occurred_at, events)
    }

    fn new(
        tenant_id: Uuid,
        user_id: Uuid,
        transaction_id: Uuid,
        occurred_at: DateTime<Utc>,
        events: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            tenant_id,
            transaction_id,
            subject_uri: format!("/Users/{user_id}"),
            events,
            occurred_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScimSubjectIdentifier {
    pub format: &'static str,
    pub uri: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SecurityEventClaims {
    pub iss: String,
    pub iat: i64,
    pub jti: String,
    pub txn: String,
    pub aud: Vec<String>,
    pub sub_id: ScimSubjectIdentifier,
    pub events: BTreeMap<String, Value>,
}

impl SecurityEventClaims {
    #[must_use]
    pub fn from_stored(event: StoredEvent, issuer: &str, audience: &str) -> Self {
        Self {
            iss: issuer.to_owned(),
            iat: event.occurred_at.timestamp(),
            jti: event.id.to_string(),
            txn: event.transaction_id.to_string(),
            aud: vec![audience.to_owned()],
            sub_id: ScimSubjectIdentifier {
                format: "scim",
                uri: event.subject_uri,
            },
            events: event.events,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PollRequest {
    #[serde(default, rename = "maxEvents")]
    pub max_events: Option<u16>,
    #[serde(default, rename = "returnImmediately")]
    pub return_immediately: bool,
    #[serde(default)]
    pub ack: Vec<String>,
    #[serde(default, rename = "setErrs")]
    pub set_errors: BTreeMap<String, SetError>,
}

impl PollRequest {
    pub fn validate(&self) -> Result<ValidatedPollRequest, PollRequestError> {
        let max_events = self.max_events.unwrap_or(DEFAULT_POLL_EVENTS);
        if max_events > MAX_POLL_EVENTS {
            return Err(PollRequestError::TooManyEvents);
        }
        if self.ack.len() > usize::from(MAX_POLL_EVENTS)
            || self.set_errors.len() > usize::from(MAX_POLL_EVENTS)
        {
            return Err(PollRequestError::TooManyAcknowledgements);
        }
        let ack = parse_event_ids(&self.ack)?;
        let mut set_errors = BTreeMap::new();
        for (event_id, error) in &self.set_errors {
            let event_id = parse_event_id(event_id)?;
            if ack.contains(&event_id) {
                return Err(PollRequestError::ConflictingDisposition);
            }
            error.validate()?;
            set_errors.insert(event_id, error.clone());
        }
        Ok(ValidatedPollRequest {
            max_events,
            return_immediately: self.return_immediately,
            ack,
            set_errors,
        })
    }
}

fn parse_event_ids(values: &[String]) -> Result<Vec<Uuid>, PollRequestError> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let event_id = parse_event_id(value)?;
        if parsed.contains(&event_id) {
            return Err(PollRequestError::DuplicateDisposition);
        }
        parsed.push(event_id);
    }
    Ok(parsed)
}

fn parse_event_id(value: &str) -> Result<Uuid, PollRequestError> {
    Uuid::parse_str(value).map_err(|_| PollRequestError::InvalidEventId)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetError {
    pub err: String,
    pub description: String,
}

impl SetError {
    fn validate(&self) -> Result<(), PollRequestError> {
        let code_is_valid = !self.err.is_empty()
            && self.err.len() <= 64
            && self
                .err
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
        if !code_is_valid {
            return Err(PollRequestError::InvalidErrorCode);
        }
        if self.description.trim().is_empty() || self.description.len() > 1024 {
            return Err(PollRequestError::InvalidErrorDescription);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPollRequest {
    pub max_events: u16,
    pub return_immediately: bool,
    pub ack: Vec<Uuid>,
    pub set_errors: BTreeMap<Uuid, SetError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PollRequestError {
    #[error("maxEvents exceeds the server limit")]
    TooManyEvents,
    #[error("too many SET dispositions")]
    TooManyAcknowledgements,
    #[error("SET identifier is invalid")]
    InvalidEventId,
    #[error("SET disposition is duplicated")]
    DuplicateDisposition,
    #[error("SET is both acknowledged and rejected")]
    ConflictingDisposition,
    #[error("SET error code is invalid")]
    InvalidErrorCode,
    #[error("SET error description is invalid")]
    InvalidErrorDescription,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventReceiver {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub audience: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EventPage {
    pub events: Vec<StoredEvent>,
    pub more_available: bool,
}

pub type EventFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EventStoreError {
    #[error("SCIM event store is unavailable")]
    Unavailable,
}

pub trait EventStorePort: Send + Sync {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<EventPage, EventStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EventSigningError {
    #[error("SCIM SET signing is unavailable")]
    Unavailable,
}

pub trait EventSignerPort: Send + Sync {
    fn sign<'a>(
        &'a self,
        claims: &'a SecurityEventClaims,
    ) -> EventFuture<'a, Result<String, EventSigningError>>;
}

pub trait EventPollerPort: Send + Sync {
    fn poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<PollResponse, PollError>>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PollResponse {
    pub sets: BTreeMap<String, String>,
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PollError {
    #[error(transparent)]
    Store(#[from] EventStoreError),
    #[error(transparent)]
    Signing(#[from] EventSigningError),
}

pub struct EventPublisher<S, K> {
    store: S,
    signer: K,
    issuer: String,
}

impl<S, K> EventPublisher<S, K>
where
    S: EventStorePort,
    K: EventSignerPort,
{
    pub fn new(store: S, signer: K, issuer: String) -> Self {
        Self {
            store,
            signer,
            issuer,
        }
    }

    pub async fn poll(
        &self,
        receiver: &EventReceiver,
        request: &ValidatedPollRequest,
    ) -> Result<PollResponse, PollError> {
        let page = self
            .store
            .apply_dispositions_and_poll(receiver, request)
            .await?;
        let mut sets = BTreeMap::new();
        for event in page.events {
            let claims = SecurityEventClaims::from_stored(event, &self.issuer, &receiver.audience);
            let jti = claims.jti.clone();
            sets.insert(jti, self.signer.sign(&claims).await?);
        }
        Ok(PollResponse {
            sets,
            more_available: page.more_available,
        })
    }
}

impl<S, K> EventPollerPort for EventPublisher<S, K>
where
    S: EventStorePort,
    K: EventSignerPort,
{
    fn poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<PollResponse, PollError>> {
        Box::pin(async move { EventPublisher::poll(self, receiver, request).await })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

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
}
