//! Raw Valkey harness for application contract tests.
//!
//! Production code must use focused stores rather than these raw inspection
//! primitives.

pub use fred::interfaces::{ClientLike, KeysInterface};
pub use fred::prelude::{
    Builder, Client, Config, ConnectionConfig, Error, Expiration, LuaInterface, PerformanceConfig,
};

use std::time::Duration;

/// Returns the actual storage key used for a PAR request URI.
///
/// This is intentionally exposed only through the raw test harness so
/// corruption and atomic-consumption contract tests do not duplicate key
/// derivation logic.
#[must_use]
pub fn par_storage_key(request_uri: &str) -> String {
    crate::keys::par(request_uri)
}

pub async fn connect(url: &str, timeout: Duration) -> Result<Client, Error> {
    let mut builder = Builder::from_config(Config::from_url(url)?);
    builder.with_performance_config(|config: &mut PerformanceConfig| {
        config.default_command_timeout = timeout;
    });
    builder.with_connection_config(|config: &mut ConnectionConfig| {
        config.connection_timeout = timeout;
        config.internal_command_timeout = timeout;
        config.max_command_attempts = 1;
    });
    let client = builder.build()?;
    client.init().await?;
    Ok(client)
}
