use crate::{
    cli::{LauncherFuture, TransientStateLauncher},
    config::{ConfigSource, ServerConfigExtension},
};
use nazo_oauth_server::ports::transient_state::ServerStateBackendBindings;

/// Single-process state with an exclusively owned, durable replay directory.
#[derive(Clone, Copy, Debug, Default)]
pub struct KevyTransientStateLauncher;

impl TransientStateLauncher for KevyTransientStateLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::new(
            "KEVY_REPLAY_DIR: \"runtime/kevy-replay\"\n".to_owned(),
            vec!["KEVY_REPLAY_DIR", "KEVY_STATE_EPOCH"],
            "KEVY_STATE_EPOCH",
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerStateBackendBindings> {
        Box::pin(async move {
            // The recovery command uses this identity. Rotating it must not
            // forget already consumed external proofs in the replay directory.
            source.transient_state_epoch()?;
            let directory =
                source.persistent_path("KEVY_REPLAY_DIR", Some("runtime/kevy-replay"))?;
            let deployment_id = deployment_id.to_owned();
            let backend = tokio::task::spawn_blocking(move || {
                nazo_kevy::KevyBackend::open(directory, &deployment_id)
            })
            .await??;
            Ok(nazo_kevy::server_state_bindings(backend))
        })
    }
}
