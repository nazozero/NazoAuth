//! Independent, opt-in diagnostic branch. No SQL text, values or identities.
//! FinishQuery is deliberately ignored: Diesel loads can finish their event
//! before the result stream/implicit transaction has actually completed.
use diesel::connection::{Instrumentation, InstrumentationEvent};
use diesel_async::{AsyncConnection, AsyncPgConnection};
use serde::Serialize;
use std::{
    future::Future,
    io::Write,
    panic::Location,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STAGES: [&str; 8] = [
    "checkout_wait",
    "connection_hold",
    "bridge_queue",
    "bridge_run",
    "bridge_join",
    "sql_await",
    "transaction_after_body",
    "phase_await",
];
const BOUNDS_US: [u64; 12] = [
    10,
    50,
    100,
    500,
    1000,
    5000,
    10000,
    20000,
    50000,
    100000,
    500000,
    u64::MAX,
];
const SLOW_US: u64 = 10_000;
const PER_STAGE_SECOND: u64 = 128;
const FILE_CAP: u64 = 64 * 1024 * 1024;
static RECORDER: OnceLock<Option<Recorder>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
static RATE_DROPPED: AtomicU64 = AtomicU64::new(0);
static FILE_DROPPED: AtomicU64 = AtomicU64::new(0);
static PID_FAILURES: AtomicU64 = AtomicU64::new(0);
static OVERHEAD_NS: AtomicU64 = AtomicU64::new(0);
static OVERHEAD_MAX_NS: AtomicU64 = AtomicU64::new(0);
static WRITER_BUSY_NS: AtomicU64 = AtomicU64::new(0);
static METRICS: [Metric; 8] = [const { Metric::new() }; 8];
struct Metric {
    count: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    buckets: [AtomicU64; 12],
    rate: AtomicU64,
}
impl Metric {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
            buckets: [const { AtomicU64::new(0) }; 12],
            rate: AtomicU64::new(0),
        }
    }
}
struct Recorder {
    tx: mpsc::SyncSender<Record>,
    started: Instant,
    epoch: f64,
}
fn recorder() -> Option<&'static Recorder> {
    RECORDER
        .get_or_init(|| {
            if std::env::var("NAZO_CONNECTION_DIAG").as_deref() != Ok("1") {
                return None;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open("/diagnostic/connection-holds.jsonl").ok()?;
            let health = options
                .open("/diagnostic/connection-holds-health.json")
                .ok()?;
            let (tx, rx) = mpsc::sync_channel::<Record>(8192);
            std::thread::Builder::new()
                .name("connection-diag".into())
                .spawn(move || {
                    use std::io::{Seek, SeekFrom};
                    let mut output = std::io::BufWriter::new(file);
                    let mut health = health;
                    let mut bytes = 0u64;
                    let mut last_health = Instant::now();
                    let mut write_errors = 0u64;
                    loop {
                        let record = match rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(row) => Some(row),
                            Err(mpsc::RecvTimeoutError::Timeout) => None,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        };
                        let work = Instant::now();
                        if let Some(record) = record {
                            match serde_json::to_vec(&record) {
                                Ok(mut data) => {
                                    data.push(b'\n');
                                    if bytes + data.len() as u64 <= FILE_CAP {
                                        if output.write_all(&data).is_err() {
                                            write_errors += 1;
                                        } else {
                                            bytes += data.len() as u64;
                                        }
                                    } else {
                                        FILE_DROPPED.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => write_errors += 1,
                            }
                        }
                        if last_health.elapsed() >= Duration::from_secs(1) {
                            if output.flush().is_err() {
                                write_errors += 1;
                            }
                            let stats = health_snapshot(bytes, write_errors);
                            if let Ok(mut data) = serde_json::to_vec(&stats) {
                                data.push(b'\n');
                                if health.seek(SeekFrom::Start(0)).is_err()
                                    || health.write_all(&data).is_err()
                                    || health.set_len(data.len() as u64).is_err()
                                    || health.flush().is_err()
                                {
                                    write_errors += 1;
                                }
                            }
                            last_health = Instant::now();
                        }
                        WRITER_BUSY_NS.fetch_add(ns(work.elapsed()), Ordering::Relaxed);
                    }
                    let _ = output.flush();
                })
                .ok()?;
            Some(Recorder {
                tx,
                started: Instant::now(),
                epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
            })
        })
        .as_ref()
}
fn ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}
fn clock() -> u64 {
    recorder().map_or(0, |r| ns(r.started.elapsed()) + 1)
}
fn health_snapshot(bytes: u64, write_errors: u64) -> serde_json::Value {
    let stages:Vec<_>=METRICS.iter().enumerate().map(|(i,m)|serde_json::json!({"stage":STAGES[i],"count":m.count.load(Ordering::Relaxed),"total_us":m.total_us.load(Ordering::Relaxed),"max_us":m.max_us.load(Ordering::Relaxed),"buckets":m.buckets.iter().map(|b|b.load(Ordering::Relaxed)).collect::<Vec<_>>()})).collect();
    serde_json::json!({"ts":recorder().map_or(0.0,|r|r.epoch+r.started.elapsed().as_secs_f64()),"stages":stages,"hist_upper_us":BOUNDS_US,"slow_threshold_us":SLOW_US,"rate_cap_per_stage_per_second":PER_STAGE_SECOND,"queue_capacity":8192,"file_cap_bytes":FILE_CAP,"file_bytes":bytes,"queue_dropped":QUEUE_DROPPED.load(Ordering::Relaxed),"rate_dropped":RATE_DROPPED.load(Ordering::Relaxed),"file_cap_dropped":FILE_DROPPED.load(Ordering::Relaxed),"write_errors":write_errors,"pid_failures":PID_FAILURES.load(Ordering::Relaxed),"producer_ns_total":OVERHEAD_NS.load(Ordering::Relaxed),"producer_ns_max":OVERHEAD_MAX_NS.load(Ordering::Relaxed),"writer_busy_ns":WRITER_BUSY_NS.load(Ordering::Relaxed),"sql_completion":"actual awaited futures; never FinishQuery","transaction_after_body":"commit/rollback plus runtime resumption; not pure COMMIT","overwrites":0})
}
#[derive(Serialize)]
struct Record {
    ts: f64,
    stage: &'static str,
    op: &'static str,
    outcome: &'static str,
    start_ns: u64,
    end_ns: u64,
    elapsed_us: u64,
    pid: u32,
    checkout_id: u64,
    bridge_id: u64,
    owner_file: &'static str,
    owner_line: u32,
    requested_ns: u64,
    acquire_polled_ns: u64,
    acquired_ns: u64,
    sql_count: u64,
    sql_total_us: u64,
    last_sql_end_ns: u64,
}
pub(crate) struct Checkout {
    id: u64,
    pid: u32,
    bridge_id: u64,
    file: &'static str,
    line: u32,
    requested: u64,
    polled: u64,
    acquired: u64,
    sql_count: AtomicU64,
    sql_ns: AtomicU64,
    last_sql_end: AtomicU64,
}
fn emit(
    stage: usize,
    op: &'static str,
    start: u64,
    end: u64,
    outcome: &'static str,
    checkout: Option<&Checkout>,
    bridge: Option<&BridgeState>,
) {
    let Some(r) = recorder() else {
        return;
    };
    let work = Instant::now();
    let elapsed_us = end.saturating_sub(start) / 1000;
    let m = &METRICS[stage];
    m.count.fetch_add(1, Ordering::Relaxed);
    m.total_us.fetch_add(elapsed_us, Ordering::Relaxed);
    m.max_us.fetch_max(elapsed_us, Ordering::Relaxed);
    let bucket = BOUNDS_US
        .iter()
        .position(|&upper| elapsed_us <= upper)
        .unwrap_or(11);
    m.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    if elapsed_us >= SLOW_US || matches!(outcome, "error" | "cancelled" | "discard") {
        let sec = end / 1_000_000_000;
        let mut permitted = false;
        let _ = m
            .rate
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                let count = if old >> 16 == sec { old & 0xffff } else { 0 };
                if count < PER_STAGE_SECOND {
                    permitted = true;
                    Some((sec << 16) | (count + 1))
                } else {
                    permitted = false;
                    None
                }
            });
        if permitted {
            let row = Record {
                ts: r.epoch + end as f64 / 1e9,
                stage: STAGES[stage],
                op,
                outcome,
                start_ns: start,
                end_ns: end,
                elapsed_us,
                pid: checkout.map_or(0, |c| c.pid),
                checkout_id: checkout.map_or(0, |c| c.id),
                bridge_id: checkout.map_or_else(|| bridge.map_or(0, |b| b.id), |c| c.bridge_id),
                owner_file: checkout.map_or("", |c| c.file),
                owner_line: checkout.map_or(0, |c| c.line),
                requested_ns: checkout.map_or(0, |c| c.requested),
                acquire_polled_ns: checkout.map_or(0, |c| c.polled),
                acquired_ns: checkout.map_or(0, |c| c.acquired),
                sql_count: checkout.map_or(0, |c| c.sql_count.load(Ordering::Relaxed)),
                sql_total_us: checkout.map_or(0, |c| c.sql_ns.load(Ordering::Relaxed) / 1000),
                last_sql_end_ns: checkout.map_or(0, |c| c.last_sql_end.load(Ordering::Relaxed)),
            };
            if r.tx.try_send(row).is_err() {
                QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            RATE_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
    let cost = ns(work.elapsed());
    OVERHEAD_NS.fetch_add(cost, Ordering::Relaxed);
    OVERHEAD_MAX_NS.fetch_max(cost, Ordering::Relaxed);
}
struct Identity {
    pid: u32,
    current: Option<Arc<Checkout>>,
}
impl Instrumentation for Identity {
    fn on_connection_event(&mut self, _event: InstrumentationEvent<'_>) {}
}
pub(crate) async fn attach(connection: &mut AsyncPgConnection) {
    use diesel_async::RunQueryDsl as _;
    if recorder().is_none() {
        return;
    }
    #[derive(diesel::QueryableByName)]
    struct BackendPid {
        #[diesel(sql_type=diesel::sql_types::Integer)]
        pid: i32,
    }
    // The caller has already created the connection driver. Exactly one query
    // per physical connection; no per-checkout SQL, no error values recorded.
    let pid = diesel::sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<BackendPid>(connection)
        .await
        .map(|row| row.pid as u32)
        .unwrap_or_else(|_| {
            PID_FAILURES.fetch_add(1, Ordering::Relaxed);
            0
        });
    connection.set_instrumentation(Identity { pid, current: None });
}
pub(crate) fn requested() -> u64 {
    clock()
}
pub(crate) struct Acquire {
    file: &'static str,
    line: u32,
    requested: u64,
    polled: u64,
    finished: bool,
}
impl Acquire {
    pub(crate) fn new(location: &'static Location<'static>, requested: u64) -> Self {
        Self {
            file: location.file(),
            line: location.line(),
            requested,
            polled: clock(),
            finished: false,
        }
    }
    pub(crate) fn acquired(&mut self, connection: &mut AsyncPgConnection) -> Option<Arc<Checkout>> {
        if recorder().is_none() {
            self.finished = true;
            return None;
        }
        let bridge_id = CONTEXT.try_with(|b| b.id).unwrap_or(0);
        let pid = connection
            .instrumentation()
            .downcast_mut::<Identity>()
            .map_or(0, |i| i.pid);
        let c = Arc::new(Checkout {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            pid,
            bridge_id,
            file: self.file,
            line: self.line,
            requested: self.requested,
            polled: self.polled,
            acquired: clock(),
            sql_count: AtomicU64::new(0),
            sql_ns: AtomicU64::new(0),
            last_sql_end: AtomicU64::new(0),
        });
        if let Some(identity) = connection.instrumentation().downcast_mut::<Identity>() {
            identity.current = Some(c.clone());
        }
        emit(0, "pool_get", self.polled, c.acquired, "ok", Some(&c), None);
        self.finished = true;
        Some(c)
    }
    pub(crate) fn failed(&mut self) {
        emit(0, "pool_get", self.polled, clock(), "error", None, None);
        self.finished = true;
    }
}
impl Drop for Acquire {
    fn drop(&mut self) {
        if !self.finished {
            emit(0, "pool_get", self.polled, clock(), "cancelled", None, None);
        }
    }
}
pub(crate) fn returned(checkout: Option<&Checkout>, outcome: &'static str) {
    if let Some(c) = checkout {
        emit(
            1,
            "physical_connection",
            c.acquired,
            clock(),
            outcome,
            Some(c),
            None,
        );
    }
}

pub(crate) struct Span {
    stage: usize,
    op: &'static str,
    started: u64,
    checkout: Option<Arc<Checkout>>,
    finished: bool,
}
impl Span {
    pub(crate) fn sql(connection: &mut AsyncPgConnection, op: &'static str) -> Self {
        Self::connection(connection, op, 5)
    }
    pub(crate) fn phase(connection: &mut AsyncPgConnection, op: &'static str) -> Self {
        Self::connection(connection, op, 7)
    }
    fn connection(connection: &mut AsyncPgConnection, op: &'static str, stage: usize) -> Self {
        let checkout = if recorder().is_some() {
            connection
                .instrumentation()
                .downcast_mut::<Identity>()
                .and_then(|i| i.current.clone())
        } else {
            None
        };
        Self {
            stage,
            op,
            started: clock(),
            checkout,
            finished: false,
        }
    }
    fn finish(&mut self, outcome: &'static str) {
        let end = clock();
        if self.stage == 5 {
            if let Some(c) = &self.checkout {
                c.sql_count.fetch_add(1, Ordering::Relaxed);
                c.sql_ns
                    .fetch_add(end.saturating_sub(self.started), Ordering::Relaxed);
                c.last_sql_end.store(end, Ordering::Relaxed);
            }
        }
        emit(
            self.stage,
            self.op,
            self.started,
            end,
            outcome,
            self.checkout.as_deref(),
            None,
        );
        self.finished = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("cancelled");
        }
    }
}
pub(crate) async fn awaited<T, E>(
    mut span: Span,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let result = future.await;
    span.finish(if result.is_ok() { "ok" } else { "error" });
    result
}
// Body completion is recorded through Drop on every return/error/cancellation.
// The outer transaction await must complete before after_body() is recorded.
pub(crate) struct Transaction {
    body_end: Arc<AtomicU64>,
    checkout: Option<Arc<Checkout>>,
}
pub(crate) struct BodyGuard(Arc<AtomicU64>);
impl Transaction {
    pub(crate) fn new(connection: &mut AsyncPgConnection) -> Self {
        let mut span = Span::connection(connection, "transaction", 6);
        span.finished = true;
        Self {
            body_end: Arc::new(AtomicU64::new(0)),
            checkout: span.checkout.take(),
        }
    }
    pub(crate) fn body(&self) -> BodyGuard {
        BodyGuard(self.body_end.clone())
    }
    pub(crate) fn after_body(&self, ok: bool) {
        let start = self.body_end.load(Ordering::Relaxed);
        if start != 0 {
            emit(
                6,
                "token_transaction_completion",
                start,
                clock(),
                if ok { "ok" } else { "error" },
                self.checkout.as_deref(),
                None,
            );
        }
    }
}
impl Drop for BodyGuard {
    fn drop(&mut self) {
        self.0.store(clock(), Ordering::Relaxed);
    }
}
tokio::task_local! {static CONTEXT:Arc<BridgeState>;}
#[derive(Clone)]
pub(crate) struct Bridge(Arc<BridgeState>);
struct BridgeState {
    id: u64,
    op: &'static str,
    submitted: u64,
    finished: AtomicU64,
}
struct RunGuard {
    bridge: Arc<BridgeState>,
    start: u64,
    done: bool,
}
impl Drop for RunGuard {
    fn drop(&mut self) {
        let end = clock();
        self.bridge.finished.store(end, Ordering::Relaxed);
        emit(
            3,
            self.bridge.op,
            self.start,
            end,
            if self.done { "ok" } else { "cancelled" },
            None,
            Some(&self.bridge),
        );
    }
}
impl Bridge {
    pub(crate) fn new(op: &'static str) -> Self {
        Self(Arc::new(BridgeState {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            op,
            submitted: clock(),
            finished: AtomicU64::new(0),
        }))
    }
    pub(crate) async fn run<F: Future>(self, future: F) -> F::Output {
        let start = clock();
        emit(
            2,
            self.0.op,
            self.0.submitted,
            start,
            "ok",
            None,
            Some(&self.0),
        );
        let mut guard = RunGuard {
            bridge: self.0.clone(),
            start,
            done: false,
        };
        let value = CONTEXT.scope(self.0.clone(), future).await;
        guard.done = true;
        value
    }
    pub(crate) fn resumed(&self) {
        let end = self.0.finished.load(Ordering::Relaxed);
        if end != 0 {
            emit(4, self.0.op, end, clock(), "ok", None, Some(&self.0));
        }
    }
}
