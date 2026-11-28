#![forbid(unsafe_code)]

use std::sync::Arc;

use nazo_server::launchers::{
    kevy::KevyTransientStateLauncher, object_store::AvatarObjectStoreLauncher,
    postgres::PostgresLauncher,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_server::cli::run(
        std::env::args(),
        Arc::new(PostgresLauncher),
        Arc::new(KevyTransientStateLauncher),
        Arc::new(AvatarObjectStoreLauncher),
    )
    .await
}
