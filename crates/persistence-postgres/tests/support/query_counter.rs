//! Shared Diesel instrumentation counter used by remediation query-count
//! evidence. It only records event categories; it never stores SQL text, bind
//! values, connection URLs, or secrets.
//!
//! Not every test binary that mounts `support` uses this helper.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use diesel::connection::{Instrumentation, InstrumentationEvent};

/// Point-in-time statement/transaction counters for one instrumented
/// connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuerySnapshot {
    /// `FinishQuery` events that are not BEGIN/COMMIT/ROLLBACK and did not
    /// fail. Multi-statement batches still count once per driver call.
    pub data_queries: u64,
    /// `FinishQuery` events that reported an error.
    pub failed_queries: u64,
    /// `BeginTransaction` events at any depth.
    pub begins: u64,
    /// `CommitTransaction` events at any depth.
    pub commits: u64,
    /// `RollbackTransaction` events at any depth.
    pub rollbacks: u64,
    /// Every other event variant (start/cache/establish/unknown). Kept so the
    /// non-exhaustive enum never silently drops information.
    pub other_events: u64,
}

impl QuerySnapshot {
    pub fn checked_add(self, other: Self) -> Self {
        Self {
            data_queries: self.data_queries + other.data_queries,
            failed_queries: self.failed_queries + other.failed_queries,
            begins: self.begins + other.begins,
            commits: self.commits + other.commits,
            rollbacks: self.rollbacks + other.rollbacks,
            other_events: self.other_events + other.other_events,
        }
    }
}

impl std::ops::Sub for QuerySnapshot {
    type Output = Self;

    fn sub(self, earlier: Self) -> Self {
        Self {
            data_queries: self.data_queries - earlier.data_queries,
            failed_queries: self.failed_queries - earlier.failed_queries,
            begins: self.begins - earlier.begins,
            commits: self.commits - earlier.commits,
            rollbacks: self.rollbacks - earlier.rollbacks,
            other_events: self.other_events - earlier.other_events,
        }
    }
}

/// Shared counter installed through `AsyncConnection::set_instrumentation`.
/// Clone it to keep a reading handle after the connection owns one clone.
#[derive(Clone, Default)]
pub struct QueryCounter {
    counts: Arc<Mutex<QuerySnapshot>>,
}

impl QueryCounter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn snapshot(&self) -> QuerySnapshot {
        *self.counts.lock().expect("query counter lock is poisoned")
    }

    /// Counter values accumulated since `baseline` was captured.
    #[must_use]
    pub fn since(&self, baseline: QuerySnapshot) -> QuerySnapshot {
        self.snapshot() - baseline
    }
}

impl Instrumentation for QueryCounter {
    fn on_connection_event(&mut self, event: InstrumentationEvent<'_>) {
        let mut counts = self.counts.lock().expect("query counter lock is poisoned");
        match event {
            InstrumentationEvent::FinishQuery { query, error, .. } => {
                if error.is_some() {
                    counts.failed_queries += 1;
                    return;
                }
                // Transaction statements also surface as FinishQuery. They are
                // classified, not data queries, and are already reported via
                // the dedicated transaction events below.
                let sql = query.to_string();
                let statement = sql.trim_start().to_ascii_uppercase();
                if statement.starts_with("BEGIN")
                    || statement.starts_with("COMMIT")
                    || statement.starts_with("ROLLBACK")
                    || statement.starts_with("START TRANSACTION")
                {
                    return;
                }
                counts.data_queries += 1;
            }
            InstrumentationEvent::BeginTransaction { .. } => counts.begins += 1,
            InstrumentationEvent::CommitTransaction { .. } => counts.commits += 1,
            InstrumentationEvent::RollbackTransaction { .. } => counts.rollbacks += 1,
            _ => counts.other_events += 1,
        }
    }
}
