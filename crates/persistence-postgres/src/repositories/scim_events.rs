use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_scim_events::{
    EventFuture, EventPage, EventReceiver, EventStoreError, EventStorePort, SetError, StoredEvent,
    ValidatedPollRequest,
};
use uuid::Uuid;

use crate::DbPool;

#[derive(Clone)]
pub struct ScimEventRepository {
    pool: DbPool,
}

impl ScimEventRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn apply_disposition(
        connection: &mut diesel_async::AsyncPgConnection,
        receiver: &EventReceiver,
        event_id: Uuid,
        disposition: &str,
        error: Option<&SetError>,
    ) -> Result<(), diesel::result::Error> {
        let (error_code, error_description) = error
            .map(|error| (Some(error.err.as_str()), Some(error.description.as_str())))
            .unwrap_or((None, None));
        sql_query(
            "INSERT INTO scim_security_event_receipts \
             (event_id, scim_token_id, disposition, error_code, error_description, updated_at) \
             SELECT event.id, token.id, $3, $4, $5, CURRENT_TIMESTAMP \
             FROM scim_security_events event \
             JOIN scim_tokens token ON token.id = $2 AND token.tenant_id = event.tenant_id \
             WHERE event.id = $1 AND event.tenant_id = $6 \
               AND event.occurred_at >= token.created_at \
               AND event.expires_at > CURRENT_TIMESTAMP \
             ON CONFLICT (event_id, scim_token_id) DO NOTHING",
        )
        .bind::<sql_types::Uuid, _>(event_id)
        .bind::<sql_types::Uuid, _>(receiver.token_id)
        .bind::<sql_types::Text, _>(disposition)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(error_code)
        .bind::<sql_types::Nullable<sql_types::Text>, _>(error_description)
        .bind::<sql_types::Uuid, _>(receiver.tenant_id)
        .execute(connection)
        .await?;
        Ok(())
    }

    async fn page(
        connection: &mut diesel_async::AsyncPgConnection,
        receiver: &EventReceiver,
        max_events: u16,
    ) -> Result<EventPage, diesel::result::Error> {
        let requested = i64::from(max_events) + 1;
        let rows = sql_query(
            "SELECT event.id, event.tenant_id, event.transaction_id, event.subject_uri, \
             event.events, event.occurred_at \
             FROM scim_security_events event \
             JOIN scim_tokens token ON token.id = $1 AND token.tenant_id = event.tenant_id \
             LEFT JOIN scim_security_event_receipts receipt \
               ON receipt.event_id = event.id AND receipt.scim_token_id = token.id \
             WHERE event.tenant_id = $2 \
               AND event.occurred_at >= token.created_at \
               AND event.expires_at > CURRENT_TIMESTAMP \
               AND receipt.event_id IS NULL \
             ORDER BY event.occurred_at ASC, event.id ASC \
             LIMIT $3",
        )
        .bind::<sql_types::Uuid, _>(receiver.token_id)
        .bind::<sql_types::Uuid, _>(receiver.tenant_id)
        .bind::<sql_types::BigInt, _>(requested)
        .load::<EventRow>(connection)
        .await?;
        let more_available = rows.len() > usize::from(max_events);
        let events = rows
            .into_iter()
            .take(usize::from(max_events))
            .map(StoredEvent::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EventPage {
            events,
            more_available,
        })
    }
}

impl EventStorePort for ScimEventRepository {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        receiver: &'a EventReceiver,
        request: &'a ValidatedPollRequest,
    ) -> EventFuture<'a, Result<EventPage, EventStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| EventStoreError::Unavailable)?;
            connection
                .transaction::<EventPage, diesel::result::Error, _>(async move |connection| {
                    for event_id in &request.ack {
                        Self::apply_disposition(
                            connection,
                            receiver,
                            *event_id,
                            "acknowledged",
                            None,
                        )
                        .await?;
                    }
                    for (event_id, error) in &request.set_errors {
                        Self::apply_disposition(
                            connection,
                            receiver,
                            *event_id,
                            "error",
                            Some(error),
                        )
                        .await?;
                    }
                    Self::page(connection, receiver, request.max_events).await
                })
                .await
                .map_err(|_| EventStoreError::Unavailable)
        })
    }
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    subject_uri: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    events: serde_json::Value,
    #[diesel(sql_type = sql_types::Timestamptz)]
    occurred_at: DateTime<Utc>,
}

impl TryFrom<EventRow> for StoredEvent {
    type Error = diesel::result::Error;

    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let events = serde_json::from_value::<BTreeMap<String, serde_json::Value>>(row.events)
            .map_err(|error| diesel::result::Error::DeserializationError(Box::new(error)))?;
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            transaction_id: row.transaction_id,
            subject_uri: row.subject_uri,
            events,
            occurred_at: row.occurred_at,
        })
    }
}
