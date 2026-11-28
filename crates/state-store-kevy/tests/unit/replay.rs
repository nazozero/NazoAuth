use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use nazo_auth::{AuthorizationStateStorePort, TokenStateStorePort};

use super::*;
use crate::KevyBackend;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("nazo-kevy-{}", uuid::Uuid::new_v4())))
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tenant() -> nazo_identity::TenantId {
    nazo_identity::TenantId::new(uuid::Uuid::from_u128(1)).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_replay_has_one_race_winner_and_survives_reopen() {
    let directory = Directory::new();
    {
        let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
        let state = backend.for_tenant(tenant());
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                state
                    .consume_replay("dpop", &[b"key", b"proof"], 60)
                    .await
                    .unwrap()
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        assert_eq!(accepted, 1);
        assert!(KevyBackend::open(&directory.0, "deployment").is_err());
        assert!(
            state
                .consume_replay("jar", &[b"key", b"proof"], 60)
                .await
                .unwrap()
        );
        let other =
            backend.for_tenant(nazo_identity::TenantId::new(uuid::Uuid::from_u128(2)).unwrap());
        assert!(
            other
                .consume_replay("dpop", &[b"key", b"proof"], 60)
                .await
                .unwrap()
        );
        assert!(
            state
                .consume_replay("dpop", &[b"a:b", b"c"], 60)
                .await
                .unwrap()
        );
        assert!(
            state
                .consume_replay("dpop", &[b"a", b"b:c"], 60)
                .await
                .unwrap()
        );
    }
    assert!(matches!(
        KevyBackend::open(&directory.0, "other-deployment"),
        Err(Error::Unexpected)
    ));
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    assert!(
        !backend
            .for_tenant(tenant())
            .consume_replay("dpop", &[b"key", b"proof"], 60)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn absolute_replay_window_does_not_slide_and_unknown_state_latches_closed() {
    let state = crate::test_support::test_state();
    let now = jiff::Timestamp::now().as_second();
    assert!(
        !state
            .consume_replay_until("jar", &[b"key"], now, None)
            .await
            .unwrap()
    );
    assert!(
        !state
            .consume_replay_until("jar", &[b"key"], now + 60, Some(now + 30))
            .await
            .unwrap()
    );
    assert!(
        state
            .consume_jar("client", "proof", now + 60)
            .await
            .unwrap()
    );
    assert!(
        !state
            .consume_jar("client", "proof", now + 120)
            .await
            .unwrap()
    );
    let key = state.key("broken", &[b"marker"]);
    state
        .replay
        .lock()
        .await
        .store
        .set(&key, b"invalid")
        .unwrap();
    assert_eq!(
        state.consume_replay("broken", &[b"marker"], 60).await,
        Err(Error::CorruptData)
    );
    assert_eq!(
        state.consume_replay("fresh", &[b"marker"], 60).await,
        Err(Error::Unavailable)
    );
    assert_eq!(state.replay_check().await, Err(Error::Unavailable));
}

#[tokio::test]
async fn damaged_replay_log_blocks_this_and_later_opens() {
    let directory = Directory::new();
    {
        let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
        assert!(
            backend
                .for_tenant(tenant())
                .consume_replay("jar", &[b"proof"], 60)
                .await
                .unwrap()
        );
    }
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(directory.0.join("aof-0.aof"))
        .unwrap();
    log.write_all(&[4, 0, 0, 0, 0, 0, 0, 0, b'b', b'a', b'd', b'!'])
        .unwrap();
    log.sync_all().unwrap();
    drop(log);
    for _ in 0..2 {
        assert!(matches!(
            KevyBackend::open(&directory.0, "deployment"),
            Err(Error::CorruptData)
        ));
    }
}

#[test]
fn foreign_staging_ring_blocks_open_without_discarding_it() {
    let directory = Directory::new();
    drop(KevyBackend::open(&directory.0, "deployment").unwrap());
    let staging = directory.0.join("aof-0.aof.stage");
    std::fs::write(&staging, b"unknown buffered writes").unwrap();
    for _ in 0..2 {
        assert!(matches!(
            KevyBackend::open(&directory.0, "deployment"),
            Err(Error::CorruptData)
        ));
        assert!(staging.exists());
    }
}

#[tokio::test]
async fn native_rewrite_retains_consumptions_across_reopen() {
    let directory = Directory::new();
    let path = directory.0.join("nested/replay");
    {
        let backend = KevyBackend::open(&path, "deployment").unwrap();
        let state = backend.for_tenant(tenant());
        assert!(state.consume_replay("jar", &[b"first"], 600).await.unwrap());
        let before = {
            let mut replay = state.replay.lock().await;
            // Native history that compaction can remove, without waiting for
            // the production 64 MiB threshold in a regression test.
            let key = state.key("jar", &[b"first"]);
            for _ in 0..32 {
                replay
                    .store
                    .set_with_ttl(
                        &key,
                        &(now_ms() + 600_000).to_be_bytes(),
                        Duration::from_secs(600),
                    )
                    .unwrap();
            }
            replay.next_rewrite_bytes = 1;
            replay.store.info().aof_bytes
        };
        assert!(
            state
                .consume_replay("jar", &[b"second"], 600)
                .await
                .unwrap()
        );
        let replay = state.replay.lock().await;
        assert!(replay.store.info().aof_bytes < before);
        assert_eq!(replay.next_rewrite_bytes, REWRITE_MIN_BYTES);
    }
    let backend = KevyBackend::open(&path, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    assert!(!state.consume_replay("jar", &[b"first"], 600).await.unwrap());
    assert!(
        !state
            .consume_replay("jar", &[b"second"], 600)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn native_rewrite_failure_latches_consumption_and_health_closed() {
    let directory = Directory::new();
    let rewrite = directory.0.join("aof-0.aof.rewrite");
    {
        let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
        let state = backend.for_tenant(tenant());
        // The native rewrite must return this real filesystem error.
        std::fs::create_dir(&rewrite).unwrap();
        state.replay.lock().await.next_rewrite_bytes = 1;
        assert_eq!(
            state.consume_replay("jar", &[b"uncertain"], 600).await,
            Err(Error::Unavailable)
        );
        std::fs::remove_dir(&rewrite).unwrap();
        assert_eq!(
            state.consume_replay("jar", &[b"new"], 600).await,
            Err(Error::Unavailable)
        );
        assert_eq!(state.replay_check().await, Err(Error::Unavailable));
    }
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    assert!(
        !state
            .consume_replay("jar", &[b"uncertain"], 600)
            .await
            .unwrap()
    );
    assert!(state.consume_replay("jar", &[b"new"], 600).await.unwrap());
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("NAZO_KEVY_CRASH_CHILD") else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let backend = KevyBackend::open(PathBuf::from(path), "crash-test").unwrap();
    let state = backend.for_tenant(tenant());
    runtime.block_on(async {
        assert!(
            state
                .consume_replay("dpop", &[b"proof-before-kill"], 600)
                .await
                .unwrap()
        );
        state
            .store_native_sso("pending", &serde_json::json!({"user":"pending"}), 600)
            .await
            .unwrap();
    });
    println!("KEVY_ACKNOWLEDGED");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[tokio::test]
async fn acknowledged_consumption_survives_forced_process_termination() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = Directory::new();
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "replay::tests::crash_child", "--nocapture"])
            .env("NAZO_KEVY_CRASH_CHILD", &directory.0)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = BufReader::new(child.0.stdout.take().unwrap());
    let acknowledged = output
        .lines()
        .any(|line| line.unwrap().contains("KEVY_ACKNOWLEDGED"));
    assert!(
        acknowledged,
        "child must acknowledge its durable write before termination"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let backend = KevyBackend::open(&directory.0, "crash-test").unwrap();
    let state = backend.for_tenant(tenant());
    assert!(
        !state
            .consume_replay("dpop", &[b"proof-before-kill"], 600)
            .await
            .unwrap()
    );
    assert!(state.load_native_sso("pending").await.unwrap().is_none());
}
