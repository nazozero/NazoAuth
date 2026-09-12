use super::*;
use crate::adapters::{
    backchannel_logout_sender::NativeBackchannelLogoutSender, ciba_ping_sender::CibaPingHttpSender,
};
use crate::jobs::{
    backchannel_logout::spawn_backchannel_logout_delivery_worker,
    ciba_ping::spawn_ciba_ping_delivery_worker,
};
use nazo_oauth_server::workers::{
    backchannel_logout::BackchannelLogoutWorker, ciba_ping::CibaPingDeliveryWorker,
};

/// Start tasks whose ownership is the process lifetime rather than an HTTP
/// worker.  Keeping these calls here prevents the server factory from
/// accidentally starting one copy per Actix worker.
pub(super) fn spawn_key_lifecycle(
    keyset: nazo_key_management::KeyManager,
    prepublish_window: chrono::Duration,
) -> crate::jobs::key_lifecycle::KeyLifecycleTask {
    crate::jobs::key_lifecycle::KeyLifecycleTask::start(keyset, prepublish_window)
}

pub(super) fn spawn_ciba_ping_worker(
    deliveries: Arc<dyn nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort>,
    settings: &Settings,
    _runtime_modules: &RuntimeModules,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    // Tenant capabilities can change after this runtime starts; the delivery
    // queue, rather than the startup snapshot, determines whether work exists.
    let sender = Arc::new(CibaPingHttpSender::new(
        &settings.ciba.ciba_notification_private_origins,
    )?);
    Ok(Some(spawn_ciba_ping_delivery_worker(Arc::new(
        CibaPingDeliveryWorker::new(deliveries, sender),
    ))))
}

pub(super) fn spawn_backchannel_logout_worker(
    logout_deliveries: Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore>,
    settings: &Settings,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let sender = Arc::new(NativeBackchannelLogoutSender::new(
        &settings.modules.backchannel_logout_private_origins,
    )?);
    Ok(spawn_backchannel_logout_delivery_worker(Arc::new(
        BackchannelLogoutWorker::from_port(logout_deliveries, sender),
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/bootstrap/startup/background.rs"]
mod tests;
