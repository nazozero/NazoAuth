use std::time::Duration;

use fred::{
    interfaces::ClientLike,
    prelude::{Builder, Config, ConnectionConfig, PerformanceConfig},
};

use crate::Error;

/// Cloneable connection handle used only to construct focused stores.
#[derive(Clone)]
pub struct ValkeyConnection {
    pub(crate) client: fred::prelude::Client,
}

impl ValkeyConnection {
    pub async fn connect(url: &str, command_timeout: Duration) -> Result<Self, Error> {
        let mut builder = Builder::from_config(Config::from_url(url).map_err(Error::from_fred)?);
        builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = command_timeout;
        });
        builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = command_timeout;
            connection.internal_command_timeout = command_timeout;
            connection.max_command_attempts = 1;
        });
        let client = builder.build().map_err(Error::from_fred)?;
        client.init().await.map_err(Error::from_fred)?;
        Ok(Self { client })
    }
}

impl std::fmt::Debug for ValkeyConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyConnection { .. }")
    }
}
