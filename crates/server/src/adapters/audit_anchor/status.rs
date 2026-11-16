use std::time::Duration;

use chrono::{DateTime, Utc};
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditBatch};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnchorCheckpoint {
    pub(super) sequence: i64,
    pub(super) hash: Vec<u8>,
}

impl AnchorCheckpoint {
    pub(super) fn from_snapshot(snapshot: &SecurityAuditAnchorHealth) -> Option<Self> {
        // Completeness is checked here; local checkpoint identity needs no timestamp copy.
        snapshot.last_exported_occurred_at?;
        snapshot.last_exported_at?;
        Some(Self {
            sequence: snapshot.last_exported_sequence?,
            hash: snapshot.last_exported_hash.as_ref()?.clone(),
        })
    }

    pub(super) fn from_batch(batch: &SecurityAuditBatch) -> Self {
        Self {
            sequence: batch.last_sequence,
            hash: batch.last_hash.clone(),
        }
    }

    pub(super) fn genesis(hash: Vec<u8>) -> Self {
        Self { sequence: 0, hash }
    }
}

pub(super) fn age_seconds(now: DateTime<Utc>, value: DateTime<Utc>) -> anyhow::Result<i64> {
    let age = (now - value).num_seconds();
    if age < 0 {
        anyhow::bail!("audit anchor timestamp is in the future");
    }
    Ok(age)
}

pub(super) fn duration_seconds(value: Duration) -> i64 {
    i64::try_from(value.as_secs()).unwrap_or(i64::MAX)
}
