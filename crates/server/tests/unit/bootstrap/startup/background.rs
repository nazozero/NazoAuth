use super::*;
use crate::config::ConfigSource;
use nazo_oauth_server::ports::transient_state::{
    CibaPingClaimBatch, CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome,
    CibaPingFinishResult, TransientStateFuture,
};

struct EmptyDeliveries;

impl CibaPingDeliveryPort for EmptyDeliveries {
    fn claim_due(
        &self,
        _now: i64,
        _lock_until: i64,
        _limit: usize,
    ) -> TransientStateFuture<'_, CibaPingClaimBatch> {
        Box::pin(async {
            Ok(CibaPingClaimBatch {
                scanned: 0,
                deliveries: Vec::new(),
            })
        })
    }

    fn finish<'a>(
        &'a self,
        _delivery: &'a CibaPingDelivery,
        _outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult> {
        Box::pin(async { Ok(CibaPingFinishResult::Missing) })
    }
}

#[tokio::test]
async fn worker_uses_the_delivery_queue_without_a_module_snapshot() {
    let settings = Settings::from_config(&ConfigSource::from_pairs_for_test([]))
        .expect("default settings load");
    let worker = ciba_ping_worker(Arc::new(EmptyDeliveries), &settings)
        .expect("worker construction should succeed");
    assert_eq!(worker.process_due_batch().await.unwrap(), 0);
}
