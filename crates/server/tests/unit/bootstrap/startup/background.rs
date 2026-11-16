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
async fn worker_starts_and_stops_without_a_module_snapshot() {
    let settings = Settings::from_config(&ConfigSource::default()).expect("default settings load");
    let worker = spawn_ciba_ping_worker(Arc::new(EmptyDeliveries), &settings)
        .expect("worker construction should succeed");
    worker.abort();
    assert!(
        worker
            .await
            .expect_err("aborted worker should stop")
            .is_cancelled()
    );
}
