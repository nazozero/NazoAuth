use super::*;

mod background;
mod configuration;
pub(super) mod services;
pub(crate) mod tenant_runtime;

/// Public bootstrap contract retained for the binary entry point.  The
/// configuration phase owns process-wide resources before service assembly;
/// the service phase owns the Actix server factory and all request handles.
pub async fn run(
    config: ConfigSource,
    persistence: ServerPersistence,
    transient_state: &dyn crate::cli::TransientStateLauncher,
    avatar_object_store: &dyn crate::cli::AvatarObjectStoreLauncher,
) -> anyhow::Result<()> {
    let _observability = observability::init(&config)?;
    let startup =
        configuration::load(config, persistence, transient_state, avatar_object_store).await?;
    startup
        .runtime
        .run(services::factory::run(startup.process, startup.registry))
        .await
}
