use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use nazo_crypto::ed25519::VerifyingKey;
use nazo_persistence::SecurityAuditBatch;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub(super) const CHECKPOINT_SCHEMA_VERSION: &str = "nazo.audit.anchor.v2";
pub(super) const RECEIPT_SCHEMA_VERSION: &str = "nazo.audit.anchor.receipt.v1";
pub(super) const GENESIS_EVENT_ID: Uuid = Uuid::from_u128(0);
pub(super) const MAX_REJECT_REASON_BYTES: usize = 128;

type HmacSha256 = Hmac<Sha256>;

/// Wire identity of one committed batch. The receiver recomputes every event
/// hash from `payload_canonical` and the batch digest from the ordered event
/// hashes, so nothing in this envelope is trusted until it verifies.
#[derive(Serialize)]
pub(super) struct AnchorBatchEnvelope<'a> {
    pub(super) schema_version: &'static str,
    pub(super) checkpoint_kind: &'static str,
    pub(super) deployment_id: &'a str,
    pub(super) first_sequence: i64,
    pub(super) last_sequence: i64,
    pub(super) event_count: i64,
    pub(super) previous_hash: String,
    pub(super) last_hash: String,
    pub(super) batch_digest: String,
    pub(super) events: Vec<AnchorBatchEvent<'a>>,
}

#[derive(Serialize)]
pub(super) struct AnchorBatchEvent<'a> {
    pub(super) event_id: Uuid,
    pub(super) sequence: i64,
    pub(super) previous_hash: String,
    pub(super) event_hash: String,
    pub(super) event_type: &'a str,
    pub(super) event_category: &'a str,
    pub(super) occurred_at: DateTime<Utc>,
    pub(super) payload_canonical: &'a str,
}

#[derive(Serialize)]
pub(super) struct GenesisCheckpointEnvelope<'a> {
    pub(super) schema_version: &'static str,
    pub(super) checkpoint_kind: &'static str,
    pub(super) event_id: Uuid,
    pub(super) deployment_id: &'a str,
    pub(super) sequence: i64,
    pub(super) previous_hash: String,
    pub(super) event_hash: String,
    pub(super) occurred_at: DateTime<Utc>,
}

/// Signed receiver acknowledgement. The exporter only accepts a receipt whose
/// Ed25519 signature verifies and whose bound fields equal the committed
/// batch: an arbitrary 2xx without this proof is never an acknowledgement.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct AnchorReceipt {
    pub(super) schema_version: String,
    pub(super) checkpoint_kind: String,
    pub(super) status: String,
    pub(super) deployment_id: String,
    pub(super) first_sequence: i64,
    pub(super) last_sequence: i64,
    pub(super) event_count: i64,
    pub(super) last_hash: String,
    pub(super) batch_digest: String,
    pub(super) received_at: DateTime<Utc>,
    #[serde(default)]
    pub(super) reject_reason: Option<String>,
    #[serde(default)]
    pub(super) permanent: bool,
    pub(super) signature: String,
}

/// Everything the signature must bind to. Serialized in declaration order so
/// both sides sign byte-identical content.
#[derive(Serialize)]
struct ReceiptSigningView<'a> {
    schema_version: &'a str,
    checkpoint_kind: &'a str,
    status: &'a str,
    deployment_id: &'a str,
    first_sequence: i64,
    last_sequence: i64,
    event_count: i64,
    last_hash: &'a str,
    batch_digest: &'a str,
    received_at: DateTime<Utc>,
    reject_reason: Option<&'a str>,
    permanent: bool,
}

/// The batch/genesis identity a receipt must bind to before it counts.
pub(super) struct ReceiptExpectation<'a> {
    pub(super) checkpoint_kind: &'static str,
    pub(super) deployment_id: &'a str,
    pub(super) first_sequence: i64,
    pub(super) last_sequence: i64,
    pub(super) event_count: i64,
    pub(super) last_hash: String,
    pub(super) batch_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptVerdict {
    Accepted { duplicate: bool },
    Rejected { reason: String, permanent: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReceiptError {
    Malformed,
    BadSignature,
    SchemaMismatch,
    BindingMismatch,
}

pub(super) fn batch_body(
    deployment_id: &str,
    batch: &SecurityAuditBatch,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&AnchorBatchEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        checkpoint_kind: "batch",
        deployment_id,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        event_count: batch.event_count(),
        previous_hash: encode_hash(&batch.previous_hash),
        last_hash: encode_hash(&batch.last_hash),
        batch_digest: encode_hash(&batch.digest),
        events: batch
            .deliveries
            .iter()
            .map(|delivery| AnchorBatchEvent {
                event_id: delivery.event_id,
                sequence: delivery.sequence,
                previous_hash: encode_hash(&delivery.previous_hash),
                event_hash: encode_hash(&delivery.event_hash),
                event_type: &delivery.event_type,
                event_category: &delivery.event_category,
                occurred_at: delivery.occurred_at,
                payload_canonical: &delivery.payload_canonical,
            })
            .collect(),
    })
}

pub(super) fn genesis_body(
    deployment_id: &str,
    head_hash: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    let hash = encode_hash(head_hash);
    serde_json::to_vec(&GenesisCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        checkpoint_kind: "genesis",
        event_id: GENESIS_EVENT_ID,
        deployment_id,
        sequence: 0,
        previous_hash: hash.clone(),
        event_hash: hash,
        occurred_at: DateTime::<Utc>::UNIX_EPOCH,
    })
}

pub(super) fn batch_expectation<'a>(
    deployment_id: &'a str,
    batch: &'a SecurityAuditBatch,
) -> ReceiptExpectation<'a> {
    ReceiptExpectation {
        checkpoint_kind: "batch",
        deployment_id,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        event_count: batch.event_count(),
        last_hash: encode_hash(&batch.last_hash),
        batch_digest: encode_hash(&batch.digest),
    }
}

pub(super) fn genesis_expectation<'a>(
    deployment_id: &'a str,
    head_hash: &[u8],
) -> ReceiptExpectation<'a> {
    let digest = nazo_persistence::audit_chain::security_audit_batch_digest(
        deployment_id,
        0,
        0,
        0,
        head_hash,
        head_hash,
        &[],
    );
    ReceiptExpectation {
        checkpoint_kind: "genesis",
        deployment_id,
        first_sequence: 0,
        last_sequence: 0,
        event_count: 0,
        last_hash: encode_hash(head_hash),
        batch_digest: encode_hash(&digest),
    }
}

pub(super) fn receipt_signing_body(receipt: &AnchorReceipt) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&ReceiptSigningView {
        schema_version: &receipt.schema_version,
        checkpoint_kind: &receipt.checkpoint_kind,
        status: &receipt.status,
        deployment_id: &receipt.deployment_id,
        first_sequence: receipt.first_sequence,
        last_sequence: receipt.last_sequence,
        event_count: receipt.event_count,
        last_hash: &receipt.last_hash,
        batch_digest: &receipt.batch_digest,
        received_at: receipt.received_at,
        reject_reason: receipt.reject_reason.as_deref(),
        permanent: receipt.permanent,
    })
}

/// Verify a receiver receipt: Ed25519 signature over the canonical body, the
/// receipt schema, and full binding to the committed batch identity. Only
/// then is the status word meaningful.
pub(super) fn verify_receipt(
    body: &[u8],
    verify_key: &VerifyingKey,
    expected: &ReceiptExpectation<'_>,
) -> Result<ReceiptVerdict, ReceiptError> {
    let receipt: AnchorReceipt =
        serde_json::from_slice(body).map_err(|_| ReceiptError::Malformed)?;
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err(ReceiptError::SchemaMismatch);
    }
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(receipt.signature.as_bytes())
        .map_err(|_| ReceiptError::Malformed)?
        .try_into()
        .map_err(|_| ReceiptError::Malformed)?;
    let signing_body = receipt_signing_body(&receipt).map_err(|_| ReceiptError::Malformed)?;
    verify_key
        .verify_strict(&signing_body, &signature)
        .map_err(|_| ReceiptError::BadSignature)?;
    if receipt.checkpoint_kind != expected.checkpoint_kind
        || receipt.deployment_id != expected.deployment_id
        || receipt.first_sequence != expected.first_sequence
        || receipt.last_sequence != expected.last_sequence
        || receipt.event_count != expected.event_count
        || receipt.last_hash != expected.last_hash
        || receipt.batch_digest != expected.batch_digest
    {
        return Err(ReceiptError::BindingMismatch);
    }
    match receipt.status.as_str() {
        "accepted" => Ok(ReceiptVerdict::Accepted { duplicate: false }),
        "duplicate" => Ok(ReceiptVerdict::Accepted { duplicate: true }),
        "rejected" => Ok(ReceiptVerdict::Rejected {
            reason: receipt
                .reject_reason
                .unwrap_or_else(|| "rejected".to_owned())
                .chars()
                .take(MAX_REJECT_REASON_BYTES)
                .collect(),
            permanent: receipt.permanent,
        }),
        _ => Err(ReceiptError::Malformed),
    }
}

pub(super) fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(super) fn encode_hash(hash: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}
