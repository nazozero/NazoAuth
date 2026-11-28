use std::sync::Arc;

use kevy_embedded::{Config, Store};
use nazo_identity::TenantId;
use tokio::sync::Mutex;

use crate::{TenantState, storage::ReplayState};

pub(crate) fn test_state() -> TenantState {
    TenantState {
        volatile: Store::open(Config::default()).unwrap(),
        replay: Arc::new(Mutex::new(ReplayState {
            store: Store::open(Config::default()).unwrap(),
            failed: false,
            directory: std::fs::File::open(std::env::temp_dir()).unwrap(),
            next_rewrite_bytes: crate::storage::REWRITE_MIN_BYTES,
        })),
        tenant_id: TenantId::new(uuid::Uuid::from_u128(1)).unwrap(),
    }
}
