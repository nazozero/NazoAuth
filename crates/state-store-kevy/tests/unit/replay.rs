use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
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

async fn enqueue(
    state: &TenantState,
    key: Vec<u8>,
    deadline: Deadline,
    not_before: Option<i64>,
) -> tokio::sync::oneshot::Receiver<Result<bool, Error>> {
    let (reply, receiver) = tokio::sync::oneshot::channel();
    state
        .replay
        .sender
        .as_ref()
        .unwrap()
        .send(ReplayRequest {
            key,
            deadline,
            not_before,
            reply,
        })
        .await
        .unwrap();
    receiver
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
async fn batch_orders_duplicates_and_persists_distinct_claims() {
    let directory = Directory::new();
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    let guard = state.replay.state.lock().await;
    let mut first = enqueue(
        &state,
        state.key("dpop", &[b"same"]),
        Deadline::Relative(60),
        None,
    )
    .await;
    let duplicate = enqueue(
        &state,
        state.key("dpop", &[b"same"]),
        Deadline::Relative(60),
        None,
    )
    .await;
    let invalid = enqueue(
        &state,
        state.key("dpop", &[b"overflow"]),
        Deadline::Relative(u64::MAX),
        None,
    )
    .await;
    let mut distinct = Vec::new();
    for index in 0..16_u64 {
        distinct.push(
            enqueue(
                &state,
                state.key("dpop", &[b"distinct", &index.to_be_bytes()]),
                Deadline::Relative(60),
                None,
            )
            .await,
        );
    }
    assert!(matches!(
        first.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drop(guard);
    assert_eq!(first.await.unwrap(), Ok(true));
    assert_eq!(duplicate.await.unwrap(), Ok(false));
    assert_eq!(invalid.await.unwrap(), Err(Error::Unexpected));
    for reply in distinct {
        assert_eq!(reply.await.unwrap(), Ok(true));
    }
    assert_eq!(state.replay_check().await, Ok(()));
    // The real, flushed AOF contains the binding and one SET per new claim.
    let report = kevy_persist::replay_aof_in_place(
        &directory.0.join("aof-0.aof"),
        kevy_persist::ReplayMode::Strict,
        kevy_persist::ReplaySummary::Quiet,
        |_| {},
    )
    .unwrap();
    assert_eq!(report.commands, 18);
    assert!(!report.corrupt);
    assert_eq!(report.dropped_bytes, 0);
}

#[tokio::test]
async fn cancelled_waiter_does_not_release_its_queued_claim() {
    let directory = Directory::new();
    {
        let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
        let state = backend.for_tenant(tenant());
        let guard = state.replay.state.lock().await;
        let cancelled = enqueue(
            &state,
            state.key("jar", &[b"cancelled"]),
            Deadline::Relative(60),
            None,
        )
        .await;
        drop(cancelled);
        let duplicate = enqueue(
            &state,
            state.key("jar", &[b"cancelled"]),
            Deadline::Relative(60),
            None,
        )
        .await;
        let live = enqueue(
            &state,
            state.key("jar", &[b"live"]),
            Deadline::Relative(60),
            None,
        )
        .await;
        drop(guard);
        assert_eq!(duplicate.await.unwrap(), Ok(false));
        assert_eq!(live.await.unwrap(), Ok(true));
    }
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    assert!(
        !backend
            .for_tenant(tenant())
            .consume_replay("jar", &[b"cancelled"], 60)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn queued_absolute_windows_use_the_owner_processing_time() {
    let state = crate::test_support::test_state();
    let guard = state.replay.state.lock().await;
    let boundary = jiff::Timestamp::now().as_second() + 2;
    let expired = enqueue(
        &state,
        state.key("jar", &[b"expires-in-queue"]),
        Deadline::Absolute(boundary),
        None,
    )
    .await;
    let starts = enqueue(
        &state,
        state.key("client-attestation", &[b"starts-in-queue"]),
        Deadline::Absolute(boundary + 60),
        Some(boundary),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(
        (boundary as u64 * 1_000).saturating_sub(now_ms()) + 2,
    ))
    .await;
    drop(guard);
    assert_eq!(expired.await.unwrap(), Ok(false));
    assert_eq!(starts.await.unwrap(), Ok(true));
    assert_eq!(state.replay_check().await, Ok(()));
}

#[tokio::test]
async fn panicked_worker_fails_closed_and_retains_directory_ownership() {
    let directory = Directory::new();
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let mut state = backend.for_tenant(tenant());
    drop(backend);
    let owner = Arc::clone(&state.replay.state);
    let thread_owner = Arc::clone(&owner);
    let (sender, receiver) = tokio::sync::mpsc::channel(REPLAY_BATCH_LIMIT);
    let thread = std::thread::spawn(move || {
        let _receiver = receiver;
        let _owner = thread_owner;
        panic!("replay owner terminated before setting its failure latch");
    });
    // Exercise the real handle's closed-channel and ownership behavior;
    // the panicking thread has no testing command in the production worker.
    state.replay = Arc::new(ReplayWorker {
        state: owner,
        sender: Some(sender),
        thread: Some(thread),
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.replay.sender.as_ref().unwrap().is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!state.replay.state.lock().await.failed);
    assert_eq!(state.replay_check().await, Err(Error::Unavailable));
    assert_eq!(
        state.consume_replay("jar", &[b"after-panic"], 60).await,
        Err(Error::Unavailable)
    );
    assert!(matches!(
        KevyBackend::open(&directory.0, "deployment"),
        Err(Error::Unavailable)
    ));
    drop(state);
    assert!(KevyBackend::open(&directory.0, "deployment").is_ok());
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
        .state
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
async fn native_rewrite_prunes_only_logically_expired_markers_across_reopen() {
    let directory = Directory::new();
    let path = directory.0.join("nested/replay");
    let expires_at = jiff::Timestamp::now().as_second() + 600;
    let deadline = ((expires_at as u64) * 1_000).to_be_bytes();
    for cycle in 0..3_u64 {
        let backend = KevyBackend::open(&path, "deployment").unwrap();
        let state = backend.for_tenant(tenant());
        assert_eq!(
            state
                .consume_replay_until("jar", &[b"first"], expires_at, None)
                .await
                .unwrap(),
            cycle == 0
        );
        let live = state.key("jar", &[b"first"]);
        let expired = state.key("jar", &[b"expired"]);
        let (before, old_aof) = {
            let mut replay = state.replay.state.lock().await;
            assert_eq!(
                replay.store.get(&live).unwrap().as_deref(),
                Some(deadline.as_slice())
            );
            assert_eq!(replay.store.with(|store| store.pttl(&live)), -1);
            // Native history that compaction can remove, without waiting for
            // the production 64 MiB threshold in a regression test.
            for _ in 0..32 {
                replay.store.set(&live, &deadline).unwrap();
            }
            replay
                .store
                .set(&expired, &(now_ms() - 1).to_be_bytes())
                .unwrap();
            replay.store.fsync_aof().unwrap();
            assert!(replay.store.get(&expired).unwrap().is_some());
            replay.next_rewrite_bytes = 1;
            (
                replay.aof.metadata().unwrap().len(),
                replay.aof.try_clone().unwrap(),
            )
        };
        assert!(
            state
                .consume_replay("jar", &[b"rewrite-trigger", &cycle.to_be_bytes()], 600)
                .await
                .unwrap()
        );
        let replay = state.replay.state.lock().await;
        let after = replay.aof.metadata().unwrap().len();
        assert!(after < before);
        assert_eq!(
            after,
            std::fs::metadata(path.join("aof-0.aof")).unwrap().len()
        );
        // The old descriptor still sees the replaced inode. Future threshold
        // checks must follow the new AOF, including after the next reopen.
        assert!(old_aof.metadata().unwrap().len() >= before);
        assert_eq!(replay.next_rewrite_bytes, REWRITE_MIN_BYTES);
        assert!(replay.store.get(&expired).unwrap().is_none());
        assert_eq!(
            replay.store.get(&live).unwrap().as_deref(),
            Some(deadline.as_slice())
        );
        assert_eq!(replay.store.with(|store| store.pttl(&live)), -1);
    }
    let backend = KevyBackend::open(&path, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    assert!(!state.consume_replay("jar", &[b"first"], 600).await.unwrap());
}

#[tokio::test]
async fn logical_expiry_allows_reuse_before_physical_cleanup() {
    let state = crate::test_support::test_state();
    let key = state.key("jar", &[b"expired"]);
    state
        .replay
        .state
        .lock()
        .await
        .store
        .set(&key, &(now_ms() - 1).to_be_bytes())
        .unwrap();
    assert!(
        state
            .consume_replay("jar", &[b"expired"], 600)
            .await
            .unwrap()
    );
    assert!(
        !state
            .consume_replay("jar", &[b"expired"], 600)
            .await
            .unwrap()
    );
    assert_eq!(
        state
            .replay
            .state
            .lock()
            .await
            .store
            .with(|store| store.pttl(&key)),
        -1
    );
}

#[tokio::test]
async fn native_rewrite_rejects_unknown_marker_data() {
    let directory = Directory::new();
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    {
        let mut replay = state.replay.state.lock().await;
        replay.store.set(b"unknown-marker", b"invalid").unwrap();
        replay.next_rewrite_bytes = 1;
    }
    assert_eq!(
        state.consume_replay("jar", &[b"fresh"], 600).await,
        Err(Error::CorruptData)
    );
    assert_eq!(state.replay_check().await, Err(Error::Unavailable));
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
        let mut guard = state.replay.state.lock().await;
        guard.next_rewrite_bytes = 1;
        let mut replies = Vec::new();
        for index in 0..8_u64 {
            replies.push(
                enqueue(
                    &state,
                    state.key("jar", &[b"uncertain", &index.to_be_bytes()]),
                    Deadline::Relative(600),
                    None,
                )
                .await,
            );
        }
        drop(guard);
        for reply in replies {
            assert_eq!(reply.await.unwrap(), Err(Error::Unavailable));
        }
        std::fs::remove_dir(&rewrite).unwrap();
        assert_eq!(
            state.consume_replay("jar", &[b"new"], 600).await,
            Err(Error::Unavailable)
        );
        assert_eq!(state.replay_check().await, Err(Error::Unavailable));
    }
    let backend = KevyBackend::open(&directory.0, "deployment").unwrap();
    let state = backend.for_tenant(tenant());
    for index in 0..8_u64 {
        assert!(
            !state
                .consume_replay("jar", &[b"uncertain", &index.to_be_bytes()], 600)
                .await
                .unwrap()
        );
    }
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
        let guard = state.replay.state.lock().await;
        let mut replies = Vec::new();
        for index in 0..16_u64 {
            replies.push(
                enqueue(
                    &state,
                    state.key("dpop", &[b"proof-before-kill", &index.to_be_bytes()]),
                    Deadline::Relative(600),
                    None,
                )
                .await,
            );
        }
        drop(guard);
        for reply in replies {
            assert_eq!(reply.await.unwrap(), Ok(true));
        }
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
async fn acknowledged_batch_survives_forced_process_termination() {
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
    for index in 0..16_u64 {
        assert!(
            !state
                .consume_replay("dpop", &[b"proof-before-kill", &index.to_be_bytes()], 600)
                .await
                .unwrap()
        );
    }
    assert!(state.load_native_sso("pending").await.unwrap().is_none());
}
