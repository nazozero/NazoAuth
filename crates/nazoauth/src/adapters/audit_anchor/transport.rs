use chrono::Utc;
use nazo_persistence::SecurityAuditBatch;

use super::{
    AuditAnchorWorkerConfig,
    protocol::{
        CHECKPOINT_SCHEMA_VERSION, ReceiptExpectation, ReceiptVerdict, batch_body,
        batch_expectation, encode_hash, genesis_body, genesis_expectation, sign_body,
        verify_receipt,
    },
};

#[derive(Debug)]
pub(super) enum AnchorPushError {
    Transport,
    Serialize,
    Http(u16),
    /// The response was not a verifiable signed receipt bound to the
    /// committed batch. Retried like a transport failure: the receiver may be
    /// mid-upgrade or misconfigured, but nothing was acknowledged.
    InvalidReceipt,
}

impl AnchorPushError {
    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::Transport => "transport_error",
            Self::Serialize => "serialization_error",
            Self::Http(429) => "http_429",
            Self::Http(400..=499) => "http_4xx",
            Self::Http(500..=599) => "http_5xx",
            Self::Http(_) => "http_other",
            Self::InvalidReceipt => "invalid_receipt",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum PushOutcome {
    /// Signed receipt verified and bound: durable acknowledgement is allowed.
    Accepted { duplicate: bool },
    /// Signed receipt verified and bound, but the receiver rejected the
    /// batch. `permanent` rejections block the batch for an operator.
    Rejected { reason: String, permanent: bool },
}

pub(super) async fn send_batch(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    batch: &SecurityAuditBatch,
) -> Result<PushOutcome, AnchorPushError> {
    let deployment_id = &config.preflight.deployment_id;
    let body = batch_body(deployment_id, batch).map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let sent_at = Utc::now().to_rfc3339();
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            format!(
                "batch:{deployment_id}:{}:{}:{}",
                batch.first_sequence,
                batch.last_sequence,
                encode_hash(&batch.digest)
            ),
        )
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", deployment_id)
        .header("X-Nazo-Audit-Sent-At", sent_at)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(AnchorPushError::Http(status.as_u16()));
    }
    let response_body = response
        .bytes()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let expectation = batch_expectation(deployment_id, batch);
    decode_outcome(&response_body, config, &expectation)
}

pub(super) async fn send_genesis_checkpoint(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    head_hash: &[u8],
) -> Result<PushOutcome, AnchorPushError> {
    let deployment_id = &config.preflight.deployment_id;
    let body = genesis_body(deployment_id, head_hash).map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let sent_at = Utc::now().to_rfc3339();
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            format!("genesis:{deployment_id}:{}", encode_hash(head_hash)),
        )
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", deployment_id)
        .header("X-Nazo-Audit-Sent-At", sent_at)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(AnchorPushError::Http(status.as_u16()));
    }
    let response_body = response
        .bytes()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let expectation = genesis_expectation(deployment_id, head_hash);
    decode_outcome(&response_body, config, &expectation)
}

fn decode_outcome(
    response_body: &[u8],
    config: &AuditAnchorWorkerConfig,
    expectation: &ReceiptExpectation<'_>,
) -> Result<PushOutcome, AnchorPushError> {
    match verify_receipt(response_body, &config.receipt_verify_key, expectation) {
        Ok(ReceiptVerdict::Accepted { duplicate }) => Ok(PushOutcome::Accepted { duplicate }),
        Ok(ReceiptVerdict::Rejected { reason, permanent }) => {
            Ok(PushOutcome::Rejected { reason, permanent })
        }
        Err(_) => Err(AnchorPushError::InvalidReceipt),
    }
}
