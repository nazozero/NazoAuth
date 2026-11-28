use crate::RocksDb;
use std::path::PathBuf;
use uuid::Uuid;

pub(crate) struct Database {
    store: Option<RocksDb>,
    path: PathBuf,
}

impl Database {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!("nazo-rocksdb-contract-{}", Uuid::new_v4()));
        Self {
            store: Some(RocksDb::open(&path).unwrap()),
            path,
        }
    }

    pub(crate) fn store(&self) -> &RocksDb {
        self.store.as_ref().unwrap()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
