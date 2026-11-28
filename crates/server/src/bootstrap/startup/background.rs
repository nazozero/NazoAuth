//! Native outbound clients supplied to the shared runtime scheduler.
use super::*;
use crate::adapters::{
    backchannel_logout_sender::NativeBackchannelLogoutSender, ciba_ping_sender::CibaPingHttpSender,
};
use nazo_oauth_server::workers::{
    backchannel_logout::BackchannelLogoutWorker, ciba_ping::CibaPingDeliveryWorker,
};

pub(super) fn ciba_ping_worker(
    deliveries: Arc<dyn nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort>,
    settings: &Settings,
) -> anyhow::Result<Arc<CibaPingDeliveryWorker>> {
    let sender = Arc::new(CibaPingHttpSender::new(
        &settings.ciba.ciba_notification_private_origins,
    )?);
    Ok(Arc::new(CibaPingDeliveryWorker::new(deliveries, sender)))
}

pub(super) fn process_workers(
    persistence: &nazo_oauth_server::ports::persistence::ServerPersistenceBindings,
    settings: &Settings,
) -> anyhow::Result<nazo_runtime_tokio::ProcessWorkers> {
    let sender = Arc::new(NativeBackchannelLogoutSender::new(
        &settings.modules.backchannel_logout_private_origins,
    )?);
    Ok(nazo_runtime_tokio::ProcessWorkers {
        backchannel_logout: Arc::new(BackchannelLogoutWorker::from_port(
            persistence.provider().logout_delivery_store(),
            sender,
        )),
        security_state: persistence.provider().security_state_maintenance(),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/bootstrap/startup/background.rs"]
mod tests;
