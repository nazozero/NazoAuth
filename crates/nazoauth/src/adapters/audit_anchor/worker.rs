use std::time::Duration;

use anyhow::Context as _;
use chrono::{Duration as ChronoDuration, Utc};
use nazo_persistence::{SecurityAuditBatch, SecurityAuditBatchAck, SecurityAuditBatchClaim, SecurityAuditExporter};

use super::{
    AuditAnchorWorkerConfig,
    status::AnchorCheckpoint,
    transport::{PushOutcome, send_batch, send_genesis_checkpoint},
};

const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);

pub(super) use nazo_persistence::SecurityAuditExporter as AuditAnchorRepository;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum IterationOutcome {
    Retry(Duration),
    Poll(Duration),
    Continue,
}

/// Run the exporter until cancellation. The repository must use the
/// independent exporter database role and the config must be worker-only.
pub(crate) async fn run_worker<R>(
    repository: R,
    config: AuditAnchorWorkerConfig,
) -> anyhow::Result<()>
where
    R: SecurityAuditExporter,
{
    config.validate()?;
    repository
        .check_available()
        .await
        .map_err(|_| anyhow::anyhow!("audit anchor exporter capability preflight failed"))?;
    let mut client_builder = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = &config.ca_bundle_pem {
        for certificate in reqwest::Certificate::from_pem_bundle(pem)
            .context("AUDIT_ANCHOR_CA_BUNDLE is not a valid PEM bundle")?
        {
            client_builder = client_builder.add_root_certificate(certificate);
        }
    }
    let client = client_builder
        .build()
        .context("failed to build audit anchor HTTP client")?;
    tracing::info!(
        target: "audit.anchor",
        endpoint_host = config.endpoint.host_str().unwrap_or("unknown"),
        deployment_id = %config.preflight.deployment_id,
        mode = ?config.preflight.mode,
        "starting independent audit anchor worker"
    );

    let mut last_anchored = None;
    let mut last_blocked = None;

    loop {
        match run_iteration(&repository, &client, &config, &mut last_anchored, &mut last_blocked)
            .await
        {
            IterationOutcome::Retry(delay) | IterationOutcome::Poll(delay) => {
                tokio::time::sleep(delay).await;
            }
            IterationOutcome::Continue => {}
        }
    }
}

/// Execute one exporter iteration. The caller owns the loop and decides when
/// to sleep from the returned outcome; this function owns only the checkpoint
/// state transition and durable delivery decisions.
pub(super) async fn run_iteration<R: AuditAnchorRepository + ?Sized>(
    repository: &R,
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    last_anchored: &mut Option<AnchorCheckpoint>,
    last_blocked: &mut Option<String>,
) -> IterationOutcome {
    let snapshot = match repository.anchor_health().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "audit anchor ledger health query failed"
            );
            return IterationOutcome::Retry(retry_delay(1));
        }
    };

    if let Some(exported) = AnchorCheckpoint::from_snapshot(&snapshot) {
        if let Err(error) = repository
            .observe_anchor(&config.preflight.deployment_id)
            .await
        {
            tracing::warn!(target: "audit.anchor", error_kind = %error_kind(&error), "audit anchor observation could not be persisted");
            return IterationOutcome::Retry(retry_delay(1));
        }
        *last_anchored = Some(exported);
    } else if snapshot.head_sequence == 0 {
        let expected_hash = super::protocol::encode_hash(&snapshot.head_hash);
        let genesis_is_current = last_anchored
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.sequence == 0 && checkpoint.hash == expected_hash);
        if !genesis_is_current {
            match send_genesis_checkpoint(client, config, &snapshot.head_hash).await {
                Ok(PushOutcome::Accepted { .. }) => {
                    if let Err(error) = repository
                        .record_genesis(&config.preflight.deployment_id, &snapshot.head_hash)
                        .await
                    {
                        tracing::warn!(target: "audit.anchor", error_kind = %error_kind(&error), "audit anchor genesis acknowledgement could not be persisted");
                        return IterationOutcome::Retry(retry_delay(1));
                    }
                    *last_anchored = Some(AnchorCheckpoint::genesis(expected_hash));
                }
                Ok(PushOutcome::Rejected { reason, .. }) => {
                    tracing::warn!(
                        target: "audit.anchor",
                        reject_reason = %reason,
                        "audit anchor genesis checkpoint was rejected by the receiver"
                    );
                    return IterationOutcome::Retry(retry_delay(1));
                }
                Err(error) => {
                    tracing::warn!(
                        target: "audit.anchor",
                        error_kind = error.code(),
                        "audit anchor genesis checkpoint failed"
                    );
                    return IterationOutcome::Retry(retry_delay(1));
                }
            }
        }
    }

    let batch = match repository
        .claim_batch(
            &config.preflight.deployment_id,
            config.batch_size,
            config.max_envelope_bytes,
            config.lock_timeout_seconds,
        )
        .await
    {
        Ok(SecurityAuditBatchClaim::Empty) | Ok(SecurityAuditBatchClaim::Busy) => {
            return IterationOutcome::Poll(config.poll_interval);
        }
        Ok(SecurityAuditBatchClaim::Blocked { reason }) => {
            if last_blocked.as_deref() != Some(reason.as_str()) {
                tracing::error!(
                    target: "audit.anchor",
                    reject_reason = %reason,
                    "audit batch is blocked on a permanent receiver rejection; operator reconciliation required"
                );
                *last_blocked = Some(reason);
            }
            return IterationOutcome::Poll(config.poll_interval);
        }
        Ok(SecurityAuditBatchClaim::Claimed(batch)) => {
            *last_blocked = None;
            batch
        }
        Err(error) => {
            tracing::warn!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "audit anchor batch claim failed"
            );
            return IterationOutcome::Retry(retry_delay(1));
        }
    };

    let attempt = batch.attempts;
    match send_batch(client, config, &batch).await {
        Ok(PushOutcome::Accepted { duplicate }) => {
            let ack = SecurityAuditBatchAck {
                generation: batch.generation,
                deployment_id: config.preflight.deployment_id.clone(),
                first_sequence: batch.first_sequence,
                last_sequence: batch.last_sequence,
                event_count: batch.event_count(),
                last_hash: batch.last_hash.clone(),
                batch_digest: batch.digest.clone(),
            };
            match repository.ack_batch(ack).await {
                Ok(()) => {
                    *last_anchored = Some(AnchorCheckpoint::from_batch(&batch));
                    tracing::info!(
                        target: "audit.anchor",
                        first_sequence = batch.first_sequence,
                        last_sequence = batch.last_sequence,
                        event_count = batch.event_count(),
                        duplicate,
                        attempts = batch.attempts,
                        anchor_lag_seconds = batch_lag_seconds(&batch),
                        "audit batch anchored by independent receiver"
                    );
                    IterationOutcome::Continue
                }
                Err(error) => {
                    let delay = retry_delay(attempt);
                    release_lease(repository, &batch, delay, "ack_database_error", false).await;
                    tracing::warn!(
                        target: "audit.anchor",
                        last_sequence = batch.last_sequence,
                        error_kind = %error_kind(&error),
                        "audit batch acknowledgement failed; batch will be redelivered idempotently"
                    );
                    IterationOutcome::Retry(delay)
                }
            }
        }
        Ok(PushOutcome::Rejected { reason, permanent }) => {
            if permanent {
                release_lease(repository, &batch, Duration::ZERO, &reason, true).await;
                tracing::error!(
                    target: "audit.anchor",
                    first_sequence = batch.first_sequence,
                    last_sequence = batch.last_sequence,
                    reject_reason = %reason,
                    "audit batch permanently rejected; operator reconciliation required"
                );
                *last_blocked = Some(reason);
                IterationOutcome::Poll(config.poll_interval)
            } else {
                let delay = retry_delay(attempt);
                release_lease(repository, &batch, delay, &reason, false).await;
                tracing::warn!(
                    target: "audit.anchor",
                    first_sequence = batch.first_sequence,
                    last_sequence = batch.last_sequence,
                    reject_reason = %reason,
                    retry_after_seconds = delay.as_secs(),
                    "audit batch rejected; durable retry scheduled"
                );
                IterationOutcome::Retry(delay)
            }
        }
        Err(error) => {
            let delay = retry_delay(attempt);
            release_lease(repository, &batch, delay, error.code(), false).await;
            tracing::warn!(
                target: "audit.anchor",
                first_sequence = batch.first_sequence,
                last_sequence = batch.last_sequence,
                error_kind = error.code(),
                retry_after_seconds = delay.as_secs(),
                "audit batch push failed; durable retry scheduled"
            );
            IterationOutcome::Retry(delay)
        }
    }
}

/// Release the committed batch lease so the identical range is re-claimed
/// after the backoff. A stale generation means another exporter owns the
/// batch now, which is safe to ignore.
async fn release_lease<R: AuditAnchorRepository + ?Sized>(
    repository: &R,
    batch: &SecurityAuditBatch,
    delay: Duration,
    reason: &str,
    blocked: bool,
) {
    let available_at = Utc::now()
        + ChronoDuration::from_std(delay).unwrap_or_else(|_| ChronoDuration::seconds(300));
    let bounded_reason: String = reason.chars().take(128).collect();
    if let Err(error) = repository
        .fail_batch(batch.generation, available_at, &bounded_reason, blocked)
        .await
    {
        tracing::warn!(
            target: "audit.anchor",
            last_sequence = batch.last_sequence,
            error_kind = %error_kind(&error),
            "failed to release audit batch lease"
        );
    }
}

pub(super) fn retry_delay(attempts: i32) -> Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 63) as u32;
    let seconds = 2_u64
        .saturating_pow(exponent)
        .min(MAX_RETRY_DELAY.as_secs());
    Duration::from_secs(seconds.max(1))
}

pub(super) fn batch_lag_seconds(batch: &SecurityAuditBatch) -> i64 {
    batch
        .deliveries
        .first()
        .map(|delivery| (Utc::now() - delivery.occurred_at).num_seconds().max(0))
        .unwrap_or(0)
}

fn error_kind<T>(_error: &T) -> &'static str {
    "external_error"
}
