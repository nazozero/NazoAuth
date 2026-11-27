#![forbid(unsafe_code)]

use std::sync::Arc;

use nazo_server::launchers::{
    object_store::AvatarObjectStoreLauncher, rocksdb::RocksDbLauncher,
    valkey::ValkeyTransientStateLauncher,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nazo_server::cli::run(
        std::env::args(),
        Arc::new(RocksDbLauncher),
        Arc::new(ValkeyTransientStateLauncher),
        Arc::new(AvatarObjectStoreLauncher),
    )
    .await
}
