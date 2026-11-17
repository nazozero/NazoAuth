use crate::{
    cli::{LauncherFuture, TransientStateLauncher},
    config::{ConfigSource, ServerConfigExtension},
};
use nazo_oauth_server::ports::transient_state::ServerStateBackendBindings;

/// Selects Valkey as the server's transient-state backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct ValkeyTransientStateLauncher;

impl TransientStateLauncher for ValkeyTransientStateLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::new(
            "VALKEY_URL: \"redis://127.0.0.1:6379/0\"\n".to_owned(),
            vec![
                "VALKEY_COMMAND_TIMEOUT_MS",
                "VALKEY_STATE_EPOCH",
                "VALKEY_URL",
            ],
            "VALKEY_STATE_EPOCH",
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerStateBackendBindings> {
        Box::pin(async move {
            let state_epoch = source.transient_state_epoch()?;
            let url = source.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
            let command_timeout_ms = source.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
            if command_timeout_ms == 0 {
                anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
            }
            let client = nazo_valkey::ValkeyClient::connect(
                &url,
                std::time::Duration::from_millis(command_timeout_ms),
                deployment_id,
                state_epoch,
            )
            .await?;
            Ok(nazo_oauth_server_valkey::server_state_bindings(client))
        })
    }
}
