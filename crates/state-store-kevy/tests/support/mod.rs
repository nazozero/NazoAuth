use std::{fs::File, sync::Arc};

use kevy_embedded::{Config, Store};
use nazo_identity::TenantId;
use tokio::sync::Mutex;

use crate::{TenantState, storage::ReplayState};

pub(crate) fn test_state() -> TenantState {
    let path = std::env::temp_dir().join(format!("nazo-kevy-test-{}", uuid::Uuid::new_v4()));
    let aof = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    TenantState {
        volatile: Store::open(Config::default()).unwrap(),
        replay: Arc::new(Mutex::new(ReplayState {
            store: Store::open(Config::default()).unwrap(),
            failed: false,
            directory: File::open(std::env::temp_dir()).unwrap(),
            aof,
            next_rewrite_bytes: crate::storage::REWRITE_MIN_BYTES,
        })),
        tenant_id: TenantId::new(uuid::Uuid::from_u128(1)).unwrap(),
    }
}
