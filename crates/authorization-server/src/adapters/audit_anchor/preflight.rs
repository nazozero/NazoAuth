use chrono::{DateTime, Utc};
use nazo_persistence::SecurityAuditAnchorHealth;

use super::{
    AuditAnchorPreflightConfig,
    status::{age_seconds, duration_seconds},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditAnchorPreflight {
    config: AuditAnchorPreflightConfig,
}

impl AuditAnchorPreflight {
    pub(crate) fn new(config: AuditAnchorPreflightConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub(crate) fn is_required(&self) -> bool {
        self.config.mode.is_required()
    }

    pub(crate) fn ensure_fresh(&self, status: &SecurityAuditAnchorHealth) -> anyhow::Result<()> {
        if !self.is_required() {
            return Ok(());
        }
        validate_health(&self.config, status, Utc::now())
    }
}

pub(super) fn validate_health(
    config: &AuditAnchorPreflightConfig,
    status: &SecurityAuditAnchorHealth,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    if status.deployment_id.as_deref() != Some(config.deployment_id.as_str()) {
        anyhow::bail!("audit anchor deployment identity does not match this runtime");
    }
    let observed_at = status
        .observed_at
        .ok_or_else(|| anyhow::anyhow!("audit anchor has not been observed by a worker"))?;
    let observed_age = age_seconds(now, observed_at)?;
    if observed_age > duration_seconds(config.freshness) {
        anyhow::bail!(
            "audit anchor health is stale: observed {observed_age}s ago (limit {}s)",
            duration_seconds(config.freshness)
        );
    }
    let sequence = status
        .last_exported_sequence
        .ok_or_else(|| anyhow::anyhow!("audit anchor has not completed its first checkpoint"))?;
    let hash = status
        .last_exported_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("audit anchor status has no last checkpoint hash"))?;
    if sequence > status.head_sequence
        || (sequence == status.head_sequence && hash != status.head_hash)
        || (status.pending_count == 0 && sequence != status.head_sequence)
    {
        anyhow::bail!("audit anchor checkpoint does not match the ledger state");
    }
    if status.pending_count == 0 {
        return Ok(());
    }
    let oldest = status
        .oldest_pending_occurred_at
        .ok_or_else(|| anyhow::anyhow!("audit anchor backlog has no oldest pending event"))?;
    let pending_lag = age_seconds(now, oldest)?;
    if pending_lag > duration_seconds(config.max_lag) {
        anyhow::bail!(
            "audit anchor pending lag is {pending_lag}s (limit {}s)",
            duration_seconds(config.max_lag)
        );
    }
    Ok(())
}
