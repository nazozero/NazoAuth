#![forbid(unsafe_code)]

use std::sync::Arc;

use nazoauth::launchers::object_store::AvatarObjectStoreLauncher;
use nazoauth::launchers::postgres::PostgresLauncher;
use nazoauth::launchers::valkey::ValkeyTransientStateLauncher;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazoauth::cli::run(
        std::env::args(),
        Arc::new(PostgresLauncher),
        Arc::new(ValkeyTransientStateLauncher),
        Arc::new(AvatarObjectStoreLauncher),
    )
    .await
}
