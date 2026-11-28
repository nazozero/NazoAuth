use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditEvent, SecurityAuditLedger};
use rocksdb::{Transaction, TransactionDB};
use serde::{Deserialize, Serialize};

use crate::{
    RocksDb,
    db::{key, map_error, put, read_tx},
};

pub(crate) const EVENTS: u8 = 0x70;

#[derive(Serialize, Deserialize, PartialEq)]
struct AuditRow {
    event_type: String,
    event_category: String,
    payload: serde_json::Value,
    occurred_at: jiff::Timestamp,
}

pub(crate) fn append_in_tx(
    tx: &Transaction<'_, TransactionDB>,
    event: &SecurityAuditEvent,
) -> Result<(), RepositoryError> {
    if !nazo_persistence::security_audit_payload_within_limit(&event.payload) {
        return Err(RepositoryError::Consistency(
            "security audit exceeds its size bound".into(),
        ));
    }
    let _tenant = event
        .payload
        .get("tenant_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|tenant| uuid::Uuid::parse_str(tenant).ok())
        .filter(|tenant| !tenant.is_nil())
        .ok_or_else(|| RepositoryError::Consistency("security audit requires a tenant".into()))?;
    if event
        .payload
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION)
        || event.event_id.is_nil()
        || !valid_identifier(&event.event_type)
        || !valid_identifier(&event.event_category)
    {
        return Err(RepositoryError::Consistency(
            "invalid security audit event".into(),
        ));
    }
    let event_key = key(EVENTS, uuid::Uuid::nil(), event.event_id.as_bytes());
    if let Some(existing) = read_tx::<AuditRow>(tx, &event_key, true)? {
        if existing.event_type != event.event_type
            || existing.event_category != event.event_category
            || existing.payload != event.payload
            || existing.occurred_at != event.occurred_at
        {
            return Err(RepositoryError::Consistency(
                "security audit event identity conflict".into(),
            ));
        }
        return Ok(());
    }
    #[derive(Serialize)]
    struct Event<'a> {
        event_type: &'a str,
        event_category: &'a str,
        payload: &'a serde_json::Value,
        occurred_at: jiff::Timestamp,
    }
    put(
        tx,
        &event_key,
        &Event {
            event_type: &event.event_type,
            event_category: &event.event_category,
            payload: &event.payload,
            occurred_at: event.occurred_at,
        },
    )
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 64
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

fn generic_event(event: &SecurityAuditEvent) -> Result<(), RepositoryError> {
    if event.event_type == "authorization_decision_committed" {
        return Err(RepositoryError::Consistency(
            "authorization decisions require their owner transaction".into(),
        ));
    }
    Ok(())
}

impl SecurityAuditLedger for RocksDb {
    fn check_available(
        &self,
        require_least_privilege: bool,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move {
            if require_least_privilege {
                return Err(RepositoryError::Consistency(
                    "RocksDB cannot enforce database role separation".into(),
                ));
            }
            self.run(|store| {
                crate::db::read::<u32>(&store.db, crate::db::SCHEMA_KEY)?
                    .filter(|version| *version == 1)
                    .ok_or(RepositoryError::Unavailable)?;
                Ok(())
            })
            .await
        })
    }

    fn anchor_health(&self) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn append(&self, event: SecurityAuditEvent) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(self.run(move |store| {
            generic_event(&event)?;
            let tx = store.transaction();
            append_in_tx(&tx, &event)?;
            tx.commit().map_err(map_error)
        }))
    }

    fn append_batch<'a>(
        &'a self,
        events: &'a [SecurityAuditEvent],
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(());
            }
            let events = events.to_vec();
            self.run(move |store| {
                let tx = store.transaction();
                for event in &events {
                    generic_event(event)?;
                    append_in_tx(&tx, event)?;
                }
                tx.commit().map_err(map_error)
            })
            .await
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/audit.rs"]
mod tests;
