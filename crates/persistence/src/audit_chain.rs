//! BLAKE3 hash chain shared by the ledger writer, the anchor exporter and
//! the independent anchor receiver. The event hash binds the sequence, its
//! predecessor, the event identity and the canonical PostgreSQL JSON text;
//! the batch digest binds one committed delivery range so a receiver can
//! verify content identity across retries.

const EVENT_DOMAIN: &[u8] = b"nazo.audit.v1\0";
const BATCH_DOMAIN: &[u8] = b"nazo.audit.batch.v1\0";

pub fn security_audit_event_hash(
    sequence: i64,
    previous_hash: &[u8],
    event_id: uuid::Uuid,
    event_type: &str,
    event_category: &str,
    occurred_at: chrono::DateTime<chrono::Utc>,
    payload_canonical: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(event_id.as_bytes());
    update_len_prefixed(&mut hasher, event_type.as_bytes());
    update_len_prefixed(&mut hasher, event_category.as_bytes());
    hasher.update(&occurred_at.timestamp_micros().to_be_bytes());
    update_len_prefixed(&mut hasher, payload_canonical);
    *hasher.finalize().as_bytes()
}

/// Content identity of one committed batch. Every event hash already binds
/// the event identity, chain position and canonical payload, so folding the
/// ordered hashes into the digest covers the full batch content.
pub fn security_audit_batch_digest(
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
    update_len_prefixed(&mut hasher, deployment_id.as_bytes());
    hasher.update(&first_sequence.to_be_bytes());
    hasher.update(&last_sequence.to_be_bytes());
    hasher.update(&event_count.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(last_hash);
    for event_hash in event_hashes {
        hasher.update(event_hash);
    }
    *hasher.finalize().as_bytes()
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}
