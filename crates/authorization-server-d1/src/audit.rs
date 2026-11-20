use crate::{D1Provider, db::Statement, persistence::encode};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_oauth_server::ports::audit::{AuditFuture, SecurityAudit};
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditEvent, SecurityAuditLedger};
use serde_json::{Map, Value, json};

impl D1Provider {
    pub(super) fn audit_statement(
        &self,
        event: &SecurityAuditEvent,
    ) -> Result<Statement, RepositoryError> {
        if !nazo_persistence::security_audit_payload_within_limit(&event.payload) {
            return Err(RepositoryError::Consistency(
                "security audit exceeds its size bound".into(),
            ));
        }
        Ok(Statement::new(
            "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) VALUES(?1,?2,?3,?4,?5,?6)",
            vec![
                json!(self.tenant_id),
                json!(event.event_id),
                json!(event.event_type),
                json!(event.event_category),
                json!(event.occurred_at.as_microsecond()),
                json!(encode(&event.payload)?),
            ],
        ))
    }
}
impl SecurityAuditLedger for D1Provider {
    fn check_available(
        &self,
        require_least_privilege: bool,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move {
            if require_least_privilege {
                return Err(RepositoryError::Unavailable);
            }
            self.database
                .query::<Value>("SELECT sequence FROM nazo_audit LIMIT 1", vec![])
                .await?;
            Ok(())
        })
    }
    fn anchor_health(&self) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }
    fn append(&self, event: SecurityAuditEvent) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move { self.append_batch(std::slice::from_ref(&event)).await })
    }
    fn append_batch<'a>(
        &'a self,
        events: &'a [SecurityAuditEvent],
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            let mut writes = Vec::with_capacity(events.len() * 2);
            let mut checks = Vec::with_capacity(events.len());
            for event in events {
                let write = self.audit_statement(event)?;
                checks.push(Statement::new(
                    "SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type=?3 AND category=?4 AND occurred_at=?5 AND payload=?6)
                    THEN 1 ELSE json_extract('required audit was not accepted','$') END",
                    write.params.clone(),
                ));
                writes.push(write);
            }
            // Inspect the final stored evidence inside the same transaction.
            // A successful SQL statement alone is not a Required-audit ACK.
            writes.extend(checks);
            if !writes.is_empty() {
                self.database.batch(writes).await?;
            }
            Ok(())
        })
    }
}
impl SecurityAudit for D1Provider {
    fn ensure_storage(&self) -> AuditFuture<'_> {
        Box::pin(async move {
            SecurityAuditLedger::check_available(self, false).await?;
            Ok(())
        })
    }
    fn ensure_transactional_ready(&self) -> AuditFuture<'_> {
        Box::pin(async { Ok(()) })
    }
    fn record(&self, event: &str, _fields: Map<String, Value>) {
        tracing::info!(event_type = event, "security observation");
    }
    fn record_required<'a>(
        &'a self,
        event: &'a str,
        mut fields: Map<String, Value>,
    ) -> AuditFuture<'a> {
        Box::pin(async move {
            fields.insert(
                "schema_version".into(),
                json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION),
            );
            fields.insert("tenant_id".into(), json!(self.tenant_id));
            SecurityAuditLedger::append(
                self,
                SecurityAuditEvent {
                    event_id: uuid::Uuid::new_v4(),
                    event_type: event.to_owned(),
                    event_category: "security".into(),
                    payload: Value::Object(fields),
                    occurred_at: jiff::Timestamp::now(),
                },
            )
            .await?;
            Ok(())
        })
    }
}
