//! Temporary, opt-in current-candidate timing evidence. No SQL or bind data.
use diesel::connection::{Instrumentation, InstrumentationEvent};
use diesel_async::{AsyncConnection, AsyncPgConnection};
use serde::Serialize;
use std::{
    future::Future,
    io::Write,
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicU64, Ordering}, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
struct Record {
    ts: f64,
    event: &'static str,
    backend_pid: u32,
    bridge_id: u64,
    elapsed_us: u64,
}

static WRITER: OnceLock<Option<mpsc::SyncSender<Record>>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
static NEXT_BRIDGE: AtomicU64 = AtomicU64::new(1);

fn writer() -> Option<&'static mpsc::SyncSender<Record>> {
    WRITER.get_or_init(|| {
        if std::env::var("NAZO_PG_TIMING").as_deref() != Ok("1") { return None; }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open("/tmp/nazo-pg-timing.jsonl").ok()?;
        let (sender, receiver) = mpsc::sync_channel::<Record>(100_000);
        std::thread::Builder::new().name("pg-timing-writer".into()).spawn(move || {
            let mut output = std::io::BufWriter::new(file);
            let mut last_flush = Instant::now();
            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(record) => {
                        if serde_json::to_writer(&mut output, &record).is_err() || output.write_all(b"\n").is_err() { break; }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if last_flush.elapsed() >= Duration::from_millis(100) {
                    let dropped = DROPPED.swap(0, Ordering::Relaxed);
                    if dropped > 0 {
                        let health = Record { ts: now(), event: "buffer_dropped", backend_pid: 0, bridge_id: 0, elapsed_us: dropped };
                        let _ = serde_json::to_writer(&mut output, &health);
                        let _ = output.write_all(b"\n");
                    }
                    if output.flush().is_err() { break; }
                    last_flush = Instant::now();
                }
            }
            let _ = output.flush();
        }).ok()?;
        Some(sender)
    }).as_ref()
}

fn now() -> f64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64() }
fn emit(event: &'static str, backend_pid: u32, bridge_id: u64, duration: Duration) {
    if let Some(sender) = writer() {
        let record = Record { ts: now(), event, backend_pid, bridge_id, elapsed_us: duration.as_micros().min(u128::from(u64::MAX)) as u64 };
        if sender.try_send(record).is_err() { DROPPED.fetch_add(1, Ordering::Relaxed); }
    }
}

struct ConnectionTiming {
    pid: u32,
    query_start: Option<Instant>,
    previous_end: Option<Instant>,
    held_since: Option<Instant>,
    next_kind: &'static str,
    current_kind: &'static str,
}

impl Instrumentation for ConnectionTiming {
    fn on_connection_event(&mut self, event: InstrumentationEvent<'_>) {
        match event {
            InstrumentationEvent::BeginTransaction { .. } => self.next_kind = "begin",
            InstrumentationEvent::CommitTransaction { .. } => self.next_kind = "commit",
            InstrumentationEvent::RollbackTransaction { .. } => self.next_kind = "rollback",
            InstrumentationEvent::StartQuery { .. } => {
                if let Some(last) = self.previous_end { emit("between_sql", self.pid, 0, last.elapsed()); }
                self.query_start = Some(Instant::now());
                self.current_kind = self.next_kind;
                self.next_kind = "sql";
            },
            InstrumentationEvent::FinishQuery { .. } => {
                if let Some(start) = self.query_start.take() { emit(self.current_kind, self.pid, 0, start.elapsed()); }
                self.previous_end = Some(Instant::now());
            },
            _ => {},
        }
    }
}

pub(crate) fn attach(connection: &mut AsyncPgConnection, pid: u32) {
    if writer().is_none() { return; }
    connection.set_instrumentation(ConnectionTiming { pid, query_start: None, previous_end: None, held_since: None, next_kind: "sql", current_kind: "sql" });
    emit("connection_attached", pid, 0, Duration::ZERO);
}

pub(crate) fn checkout(connection: &mut AsyncPgConnection, duration: Duration) {
    if writer().is_none() { return; }
    if let Some(timing) = connection.instrumentation().downcast_mut::<ConnectionTiming>() {
        timing.held_since = Some(Instant::now());
        // A pool idle interval is not an application interval between statements.
        timing.previous_end = None;
        emit("pool_acquire", timing.pid, 0, duration);
    }
}

pub(crate) fn confirmed_return(connection: &mut AsyncPgConnection) {
    if writer().is_none() { return; }
    if let Some(timing) = connection.instrumentation().downcast_mut::<ConnectionTiming>() {
        if let Some(start) = timing.held_since.take() { emit("confirmed_guard_hold", timing.pid, 0, start.elapsed()); }
    }
}

#[derive(Clone)]
pub(crate) struct Bridge(Arc<BridgeState>);
struct BridgeState { id: u64, submitted: Instant, finished: Mutex<Option<Instant>> }
impl Bridge {
    pub(crate) fn new() -> Self {
        Self(Arc::new(BridgeState { id: NEXT_BRIDGE.fetch_add(1, Ordering::Relaxed), submitted: Instant::now(), finished: Mutex::new(None) }))
    }
    pub(crate) async fn run<F: Future>(self, future: F) -> F::Output {
        emit("spawn_to_poll", 0, self.0.id, self.0.submitted.elapsed());
        let start = Instant::now();
        let value = future.await;
        *self.0.finished.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        emit("spawned_operation", 0, self.0.id, start.elapsed());
        value
    }
    pub(crate) fn resumed(&self) {
        if let Some(finished) = *self.0.finished.lock().unwrap_or_else(|e| e.into_inner()) {
            emit("finish_to_join_resume", 0, self.0.id, finished.elapsed());
        }
    }
}
