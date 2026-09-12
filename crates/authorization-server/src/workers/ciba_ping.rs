use crate::ports::transient_state::{
    CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
};
use anyhow::Context as _;
use chrono::Utc;
use futures_util::{StreamExt as _, stream};
use nazo_auth::{
    CibaPingResponseAction, classify_ciba_ping_status, next_ciba_ping_retry_at,
    validate_ciba_notification_endpoint,
};
use std::sync::Arc;

pub trait CibaPingSender: Send + Sync {
    fn send<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<http::StatusCode>> + Send + 'a>,
    >;
}
const DELIVERY_CONCURRENCY: usize = 8;
// One concurrency wave keeps the whole batch within the existing claim lease.
const DELIVERY_BATCH_SIZE: usize = DELIVERY_CONCURRENCY;
const DELIVERY_LOCK_SECONDS: i64 = 15;

pub struct CibaPingDeliveryWorker {
    store: Arc<dyn CibaPingDeliveryPort>,
    sender: Arc<dyn CibaPingSender>,
}
impl CibaPingDeliveryWorker {
    pub fn new(store: Arc<dyn CibaPingDeliveryPort>, sender: Arc<dyn CibaPingSender>) -> Self {
        Self { store, sender }
    }
    pub async fn process_due_batch(&self) -> anyhow::Result<usize> {
        let now = Utc::now().timestamp();
        let deliveries = self
            .store
            .claim_due(
                now,
                now.saturating_add(DELIVERY_LOCK_SECONDS),
                DELIVERY_BATCH_SIZE,
            )
            .await
            .context("failed to claim CIBA ping deliveries")?;
        let count = deliveries.len();
        let outcomes = stream::iter(deliveries)
            .map(|delivery| async move { self.process_delivery(delivery).await })
            .buffer_unordered(DELIVERY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        if let Some(error) = outcomes.into_iter().find_map(Result::err) {
            return Err(error);
        }
        Ok(count)
    }

    async fn process_delivery(&self, delivery: CibaPingDelivery) -> anyhow::Result<()> {
        let sent = self
            .sender
            .send(&delivery)
            .await
            .map(|status| (classify_ciba_ping_status(status.as_u16()), status));
        let outcome = match sent {
            Ok((CibaPingResponseAction::Delivered, _)) => CibaPingFinishOutcome::Delivered,
            Ok((CibaPingResponseAction::TerminalFailure, status)) => {
                tracing::warn!(
                    %status,
                    endpoint_origin = %endpoint_origin_for_log(&delivery.endpoint),
                    "CIBA ping endpoint rejected the notification; delivery is terminal"
                );
                CibaPingFinishOutcome::Failed
            }
            Ok((CibaPingResponseAction::Retry, _)) | Err(_) => {
                tracing::warn!(
                    endpoint_origin = %endpoint_origin_for_log(&delivery.endpoint),
                    attempts = delivery.attempts,
                    "CIBA ping notification transport failed"
                );
                next_ciba_ping_retry_at(
                    delivery.attempts,
                    Utc::now().timestamp(),
                    delivery.expires_at,
                )
                .map_or(
                    CibaPingFinishOutcome::Failed,
                    CibaPingFinishOutcome::RetryAt,
                )
            }
        };
        let finish_result = self
            .store
            .finish(&delivery, outcome)
            .await
            .context("failed to record CIBA ping delivery outcome")?;
        match finish_result {
            CibaPingFinishResult::Applied => {}
            CibaPingFinishResult::Missing | CibaPingFinishResult::Conflict => {
                tracing::debug!(
                    attempts = delivery.attempts,
                    "CIBA ping finish skipped because the delivery claim is stale"
                );
            }
        }
        Ok(())
    }
}
fn endpoint_origin_for_log(raw: &str) -> String {
    validate_ciba_notification_endpoint(raw)
        .map(|endpoint| endpoint.origin().ascii_serialization())
        .unwrap_or_else(|_| "<invalid>".to_owned())
}
