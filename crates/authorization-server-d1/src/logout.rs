//! Durable outbox and fenced scheduled delivery. Shared workers own retry policy.
use futures_util::future::BoxFuture;
use nazo_auth::{
    BackchannelLogoutDelivery, BackchannelLogoutOutboxPort, IdempotentBackchannelLogoutDelivery,
    LogoutFuture,
};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::BackchannelLogoutDeliveryStore;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    D1Provider,
    db::Statement,
    persistence::{NOW, timestamp},
};

impl BackchannelLogoutOutboxPort for D1Provider {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        deliveries: &'a [IdempotentBackchannelLogoutDelivery],
    ) -> LogoutFuture<'a, ()> {
        Box::pin(async move {
            let mut statements = Vec::with_capacity(deliveries.len());
            for delivery in deliveries {
                self.require_tenant(delivery.tenant_id)?;
                statements.push(Statement::new(format!(
                    "INSERT INTO nazo_logout_outbox(tenant_id,id,operation_key,client_id,client_public_id,logout_uri,logout_token,expires_at,available_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,{NOW}) ON CONFLICT(tenant_id,operation_key,client_id) DO NOTHING"),
                    vec![json!(self.tenant_id),json!(Uuid::new_v4()),json!(delivery.operation_key),json!(delivery.client_id),json!(delivery.client_public_id),json!(delivery.logout_uri),json!(delivery.logout_token),json!(delivery.expires_at.as_microsecond())]));
            }
            if !statements.is_empty() {
                self.database.batch(statements).await?;
            }
            Ok(())
        })
    }
}

#[derive(Deserialize)]
struct DeliveryRow {
    id: Uuid,
    logout_uri: String,
    logout_token: String,
    attempts: i32,
    expires_at: i64,
}

impl BackchannelLogoutDeliveryStore for D1Provider {
    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> BoxFuture<'_, Result<Vec<BackchannelLogoutDelivery>, RepositoryError>> {
        Box::pin(async move {
            if !(1..=100).contains(&limit) || !(1..=600).contains(&lock_timeout_seconds) {
                return Err(RepositoryError::Unavailable);
            }
            let rows = self.database.query::<DeliveryRow>(&format!(
                "UPDATE nazo_logout_outbox SET attempts=attempts+1,lease_until={NOW}+?3*1000000
                 WHERE tenant_id=?1 AND id IN(SELECT id FROM nazo_logout_outbox WHERE tenant_id=?1 AND state='pending'
                    AND available_at<={NOW} AND expires_at>{NOW} AND (lease_until IS NULL OR lease_until<={NOW})
                    ORDER BY available_at,id LIMIT ?2)
                 RETURNING id,logout_uri,logout_token,attempts,expires_at"),
                vec![json!(self.tenant_id),json!(limit.min(4)),json!(lock_timeout_seconds)]).await?;
            rows.into_iter()
                .map(|row| {
                    Ok(BackchannelLogoutDelivery {
                        id: row.id,
                        logout_uri: row.logout_uri,
                        logout_token: row.logout_token,
                        attempts: row.attempts,
                        expires_at: timestamp(row.expires_at)?,
                    })
                })
                .collect()
        })
    }

    fn complete(
        &self,
        id: Uuid,
        expected_attempts: i32,
    ) -> BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move {
            self.database.query::<serde_json::Value>(&format!(
                "UPDATE nazo_logout_outbox SET state='delivered',logout_token='',lease_until=NULL
                 WHERE tenant_id=?1 AND id=?2 AND state='pending' AND attempts=?3 AND lease_until>{NOW}"),
                vec![json!(self.tenant_id),json!(id),json!(expected_attempts)]).await?;
            Ok(())
        })
    }

    fn fail<'a>(
        &'a self,
        id: Uuid,
        expected_attempts: i32,
        next_attempt_at: Option<jiff::Timestamp>,
        last_error: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            // The shared worker supplies a bounded, credential-free failure.
            let message: String = last_error.chars().take(512).collect();
            self.database.query::<serde_json::Value>(&format!(
                "UPDATE nazo_logout_outbox SET state=CASE WHEN ?4 IS NULL THEN 'failed' ELSE 'pending' END,
                    available_at=COALESCE(?4,available_at),lease_until=NULL,last_error=?5,
                    logout_token=CASE WHEN ?4 IS NULL THEN '' ELSE logout_token END
                 WHERE tenant_id=?1 AND id=?2 AND state='pending' AND attempts=?3 AND lease_until>{NOW}"),
                vec![json!(self.tenant_id),json!(id),json!(expected_attempts),json!(next_attempt_at.map(|time|time.as_microsecond())),json!(message)]).await?;
            Ok(())
        })
    }
}
