//! Receiver-scoped SCIM event dispositions and polling on primary D1.

use nazo_scim_events::{
    EventFuture, EventPage, EventReceiver, EventStoreError, EventStorePort, StoredEvent,
    ValidatedPollRequest,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, encode, timestamp},
};

#[derive(Deserialize)]
struct EventRow {
    id: Uuid,
    tenant_id: Uuid,
    transaction_id: Uuid,
    subject_uri: String,
    events: String,
    occurred_at: i64,
}

impl EventRow {
    fn into_event(self) -> Result<StoredEvent, DbError> {
        Ok(StoredEvent {
            id: self.id,
            tenant_id: self.tenant_id,
            transaction_id: self.transaction_id,
            subject_uri: self.subject_uri,
            events: serde_json::from_str(&self.events).map_err(|_| DbError::CorruptData)?,
            occurred_at: timestamp(self.occurred_at)?,
        })
    }
}

impl EventStorePort for D1Provider {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<EventPage, EventStoreError>> {
        Box::pin(async move {
            self.require_tenant(receiver.tenant_id)
                .map_err(|_| EventStoreError::Unavailable)?;
            let mut dispositions = Vec::with_capacity(request.ack.len() + request.set_errors.len());
            for id in &request.ack {
                dispositions.push(json!({"id":id,"disposition":"acknowledged"}));
            }
            for (id, error) in &request.set_errors {
                dispositions.push(json!({"id":id,"disposition":"error",
                    "code":error.err.as_str(),"description":error.description}));
            }
            let mut statements = Vec::with_capacity(2);
            if !dispositions.is_empty() {
                statements.push(Statement::new(format!(
                    "INSERT INTO nazo_scim_event_receipts(tenant_id,event_id,token_id,disposition,error_code,error_description,updated_at)
                     SELECT event.tenant_id,event.id,token.id,json_extract(item.value,'$.disposition'),
                         json_extract(item.value,'$.code'),json_extract(item.value,'$.description'),{NOW}
                     FROM json_each(?3) AS item JOIN nazo_scim_events AS event ON event.tenant_id=?1 AND event.id=json_extract(item.value,'$.id')
                     JOIN nazo_scim_tokens AS token ON token.tenant_id=event.tenant_id AND token.id=?2
                     WHERE event.occurred_at>=token.created_at AND event.expires_at>{NOW}
                         AND token.revoked_at IS NULL AND (token.expires_at IS NULL OR token.expires_at>{NOW})
                     ON CONFLICT(tenant_id,event_id,token_id) DO NOTHING"),
                    vec![json!(self.tenant_id),json!(receiver.token_id),json!(encode(&dispositions).map_err(|_|EventStoreError::Unavailable)?)]));
            }
            statements.push(Statement::new(format!(
                "SELECT event.id,event.tenant_id,event.transaction_id,event.subject_uri,event.events,event.occurred_at
                 FROM nazo_scim_events AS event JOIN nazo_scim_tokens AS token ON token.tenant_id=event.tenant_id AND token.id=?2
                 LEFT JOIN nazo_scim_event_receipts AS receipt ON receipt.tenant_id=event.tenant_id AND receipt.event_id=event.id AND receipt.token_id=token.id
                 WHERE event.tenant_id=?1 AND event.occurred_at>=token.created_at AND event.expires_at>{NOW}
                     AND token.revoked_at IS NULL AND (token.expires_at IS NULL OR token.expires_at>{NOW})
                     AND receipt.event_id IS NULL
                 ORDER BY event.occurred_at,event.id LIMIT ?3"),
                vec![json!(self.tenant_id),json!(receiver.token_id),json!(i64::from(request.max_events)+1)]));
            let mut results = self
                .database
                .batch(statements)
                .await
                .map_err(|_| EventStoreError::Unavailable)?;
            let rows = results.pop().ok_or(EventStoreError::Unavailable)?.rows;
            let more_available = rows.len() > usize::from(request.max_events);
            let events = rows
                .into_iter()
                .take(usize::from(request.max_events))
                .map(|row| {
                    serde_json::from_value::<EventRow>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .into_event()
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| EventStoreError::Unavailable)?;
            Ok(EventPage {
                events,
                more_available,
            })
        })
    }
}
