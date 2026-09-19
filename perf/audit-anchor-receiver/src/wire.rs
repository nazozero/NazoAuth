//! Wire contract shared with the NazoAuth audit-anchor exporter (protocol v2).
//! This receiver is an independent implementation: it recomputes every event
//! hash and the batch digest from the envelope content, so nothing is trusted
//! until it verifies.

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub const CHECKPOINT_SCHEMA_VERSION: &str = "nazo.audit.anchor.v2";
pub const RECEIPT_SCHEMA_VERSION: &str = "nazo.audit.anchor.receipt.v1";
pub const GENESIS_EVENT_ID: Uuid = Uuid::nil();
const EVENT_DOMAIN: &[u8] = b"nazo.audit.v1\0";
const BATCH_DOMAIN: &[u8] = b"nazo.audit.batch.v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
pub struct BatchEnvelope {
    pub schema_version: String,
    pub checkpoint_kind: String,
    pub deployment_id: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub event_count: i64,
    pub previous_hash: String,
    pub last_hash: String,
    pub batch_digest: String,
    pub events: Vec<EnvelopeEvent>,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeEvent {
    pub event_id: Uuid,
    pub sequence: i64,
    pub previous_hash: String,
    pub event_hash: String,
    pub event_type: String,
    pub event_category: String,
    pub occurred_at: DateTime<Utc>,
    pub payload_canonical: String,
}

#[derive(Debug, Deserialize)]
pub struct GenesisEnvelope {
    pub schema_version: String,
    pub checkpoint_kind: String,
    pub event_id: Uuid,
    pub deployment_id: String,
    pub sequence: i64,
    pub previous_hash: String,
    pub event_hash: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnchorReceipt {
    pub schema_version: String,
    pub checkpoint_kind: String,
    pub status: String,
    pub deployment_id: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub event_count: i64,
    pub last_hash: String,
    pub batch_digest: String,
    pub received_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    #[serde(default)]
    pub permanent: bool,
    pub signature: String,
}

/// Signing view mirrors the exporter's `ReceiptSigningView` declaration order
/// so both sides sign byte-identical content.
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

pub fn encode_hash(hash: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}

pub fn decode_hash(encoded: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| anyhow!("hash is not base64url"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("hash must be 32 bytes"))
}

/// Recompute the event hash exactly as the ledger chain defines it.
pub fn event_hash(
    sequence: i64,
    previous_hash: &[u8],
    event_id: Uuid,
    event_type: &str,
    event_category: &str,
    occurred_at: DateTime<Utc>,
    payload_canonical: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(event_id.as_bytes());
    len_prefixed(&mut hasher, event_type.as_bytes());
    len_prefixed(&mut hasher, event_category.as_bytes());
    hasher.update(&occurred_at.timestamp_micros().to_be_bytes());
    len_prefixed(&mut hasher, payload_canonical);
    *hasher.finalize().as_bytes()
}

pub fn batch_digest(
    deployment_id: &str,
    first_sequence: i64,
    last_sequence: i64,
    event_count: i64,
    previous_hash: &[u8],
    last_hash: &[u8],
    event_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BATCH_DOMAIN);
    len_prefixed(&mut hasher, deployment_id.as_bytes());
    hasher.update(&first_sequence.to_be_bytes());
    hasher.update(&last_sequence.to_be_bytes());
    hasher.update(&event_count.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(last_hash);
    for hash in event_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

fn len_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

/// Verify every declared event hash and the batch digest against the envelope
/// content. Returns the recomputed digest on success.
pub fn verify_batch_content(envelope: &BatchEnvelope) -> Result<[u8; 32]> {
    if envelope.events.len() as i64 != envelope.event_count
        || envelope.last_sequence - envelope.first_sequence + 1 != envelope.event_count
        || envelope.event_count < 1
    {
        bail!("batch range does not match its event list");
    }
    let previous = decode_hash(&envelope.previous_hash)?;
    let mut expected_previous = previous;
    let mut hashes = Vec::with_capacity(envelope.events.len());
    for (index, event) in envelope.events.iter().enumerate() {
        if event.sequence != envelope.first_sequence + index as i64 {
            bail!("batch events are not a contiguous sequence");
        }
        if decode_hash(&event.previous_hash)? != expected_previous {
            bail!("event previous_hash does not continue the chain");
        }
        let hash = event_hash(
            event.sequence,
            &expected_previous,
            event.event_id,
            &event.event_type,
            &event.event_category,
            event.occurred_at,
            event.payload_canonical.as_bytes(),
        );
        if decode_hash(&event.event_hash)? != hash {
            bail!("event_hash does not match recomputed content");
        }
        expected_previous = hash;
        hashes.push(hash);
    }
    if decode_hash(&envelope.last_hash)? != expected_previous {
        bail!("batch last_hash does not match recomputed content");
    }
    let digest = batch_digest(
        &envelope.deployment_id,
        envelope.first_sequence,
        envelope.last_sequence,
        envelope.event_count,
        &previous,
        &expected_previous,
        &hashes,
    );
    if decode_hash(&envelope.batch_digest)? != digest {
        bail!("batch_digest does not match recomputed content");
    }
    Ok(digest)
}

/// HMAC `sha256=` body signature verification with a constant-time compare.
pub fn verify_body_signature(secret: &[u8], presented: &str, body: &[u8]) -> bool {
    let Some(encoded) = presented.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded.as_bytes()) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&bytes).is_ok()
}

pub fn sign_receipt(mut receipt: AnchorReceipt, key: &SigningKey) -> Result<Vec<u8>> {
    receipt.signature.clear();
    let body = serde_json::to_vec(&ReceiptSigningView {
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
    })?;
    receipt.signature = encode_hash(&key.sign(&body).to_bytes());
    Ok(serde_json::to_vec(&receipt)?)
}

/// The exporter-facing receipt for one envelope's declared identity.
pub fn receipt_for(
    kind: &str,
    status: &str,
    deployment_id: &str,
    first_sequence: i64,
    last_sequence: i64,
    event_count: i64,
    last_hash: &str,
    batch_digest: &str,
    reject_reason: Option<String>,
    permanent: bool,
) -> AnchorReceipt {
    AnchorReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
        checkpoint_kind: kind.to_owned(),
        status: status.to_owned(),
        deployment_id: deployment_id.to_owned(),
        first_sequence,
        last_sequence,
        event_count,
        last_hash: last_hash.to_owned(),
        batch_digest: batch_digest.to_owned(),
        received_at: Utc::now(),
        reject_reason,
        permanent,
        signature: String::new(),
    }
}

pub fn parse_signing_key(encoded: &str) -> Result<SigningKey> {
    let trimmed = encoded.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| hex_decode(trimmed))
        .map_err(|_| anyhow!("signing key must be base64url or hex"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn verifying_key_b64(key: &SigningKey) -> String {
    let verify: VerifyingKey = key.verifying_key();
    encode_hash(&verify.to_bytes())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| ()))
        .collect()
}
