use std::time::Duration;

use chrono::{DateTime, Utc};
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditBatch};

use super::protocol::encode_hash;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnchorCheckpoint {
    pub(super) sequence: i64,
    pub(super) hash: String,
}

impl AnchorCheckpoint {
    pub(super) fn from_snapshot(snapshot: &SecurityAuditAnchorHealth) -> Option<Self> {
        // Completeness is checked here; local checkpoint identity needs no timestamp copy.
        snapshot.last_exported_occurred_at?;
        snapshot.last_exported_at?;
        Some(Self {
            sequence: snapshot.last_exported_sequence?,
            hash: encode_hash(snapshot.last_exported_hash.as_deref()?),
        })
    }

    pub(super) fn from_batch(batch: &SecurityAuditBatch) -> Self {
        Self {
            sequence: batch.last_sequence,
            hash: encode_hash(&batch.last_hash),
        }
    }

    pub(super) fn genesis(hash: String) -> Self {
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
