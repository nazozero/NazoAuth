use std::{io::Write, path::PathBuf};

use super::*;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("nazo-kevy-open-{}", uuid::Uuid::new_v4())))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn damaged_log_is_rejected_without_repair_or_truncation() {
    let directory = Directory::new();
    drop(KevyBackend::open(&directory.0, "deployment").unwrap());
    let path = directory.0.join("aof-0.aof");
    let mut log = File::options().append(true).open(&path).unwrap();
    log.write_all(&[4, 0, 0, 0, 0, 0, 0, 0, b'b', b'a', b'd', b'!'])
        .unwrap();
    log.sync_all().unwrap();
    drop(log);
    let damaged = std::fs::read(&path).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            KevyBackend::open(&directory.0, "deployment"),
            Err(Error::CorruptData)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
        assert!(std::fs::read_dir(&directory.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".corrupt-quarantine.")
        }));
    }
}

#[test]
fn directory_lock_precedes_log_inspection() {
    let directory = Directory::new();
    std::fs::create_dir_all(&directory.0).unwrap();
    let owner = File::open(&directory.0).unwrap();
    owner.try_lock().unwrap();
    let path = directory.0.join("aof-0.aof");
    let damaged = b"not an AOF";
    std::fs::write(&path, damaged).unwrap();
    assert!(matches!(
        KevyBackend::open(&directory.0, "deployment"),
        Err(Error::Unavailable)
    ));
    assert!(!directory.0.join("LOCK").exists());
    assert_eq!(std::fs::read(&path).unwrap(), damaged);
    drop(owner);
    assert!(matches!(
        KevyBackend::open(&directory.0, "deployment"),
        Err(Error::CorruptData)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), damaged);
}

#[test]
fn tenant_handles_retain_directory_ownership() {
    let directory = Directory::new();
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let state = backend.for_tenant(TenantId::new(uuid::Uuid::from_u128(1)).unwrap());
    drop(backend);
    assert!(matches!(
        KevyBackend::open(&directory.0, "deployment"),
        Err(Error::Unavailable)
    ));
    drop(state);
    assert!(KevyBackend::open(&directory.0, "deployment").is_ok());
}
