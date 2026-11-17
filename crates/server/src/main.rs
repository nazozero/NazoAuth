#![forbid(unsafe_code)]

use std::sync::Arc;

use nazo_server::launchers::object_store::AvatarObjectStoreLauncher;
use nazo_server::launchers::postgres::PostgresLauncher;
use nazo_server::launchers::valkey::ValkeyTransientStateLauncher;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_server::cli::run(
        std::env::args(),
        Arc::new(PostgresLauncher),
        Arc::new(ValkeyTransientStateLauncher),
        Arc::new(AvatarObjectStoreLauncher),
    )
    .await
}
