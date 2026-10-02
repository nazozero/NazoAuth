//! Borrowed audit anchor JSON shared by new-batch sizing and delivery.
use std::io::{self, Write};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use crate::{SecurityAuditBatch, SecurityAuditPendingDelivery};

pub const AUDIT_ANCHOR_SCHEMA_VERSION: &str = "nazo.audit.anchor.v2";
/// A legal maximum-size event may exceed the normal minimum batch budget.
pub const MAX_SECURITY_AUDIT_SINGLETON_ENVELOPE_BYTES: usize = 135_168;

#[derive(Serialize)]
struct BatchEnvelope<'a> {
    schema_version: &'static str,
    checkpoint_kind: &'static str,
    deployment_id: &'a str,
    first_sequence: i64,
    last_sequence: i64,
    event_count: i64,
    previous_hash: String,
    last_hash: String,
    batch_digest: String,
    events: Events<'a>,
}
#[derive(Serialize)]
struct Event<'a> {
    event_id: uuid::Uuid,
    sequence: i64,
    previous_hash: String,
    event_hash: String,
    event_type: &'a str,
    event_category: &'a str,
    occurred_at: chrono::DateTime<chrono::Utc>,
    payload_canonical: &'a str,
}
impl<'a> From<&'a SecurityAuditPendingDelivery> for Event<'a> {
    fn from(delivery: &'a SecurityAuditPendingDelivery) -> Self {
        Self { event_id:delivery.event_id,sequence:delivery.sequence,previous_hash:URL_SAFE_NO_PAD.encode(&delivery.previous_hash),event_hash:URL_SAFE_NO_PAD.encode(&delivery.event_hash),event_type:&delivery.event_type,event_category:&delivery.event_category,occurred_at:delivery.occurred_at,payload_canonical:&delivery.payload_canonical }
    }
}
struct Events<'a>(&'a [SecurityAuditPendingDelivery]);
impl Serialize for Events<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok,S::Error> {
        let mut sequence=serializer.serialize_seq(Some(self.0.len()))?;
        for event in self.0 { sequence.serialize_element(&Event::from(event))?; }
        sequence.end()
    }
}
#[derive(Default)]
struct ByteCount(usize);
impl Write for ByteCount {
    fn write(&mut self, bytes:&[u8]) -> io::Result<usize> {
        self.0=self.0.checked_add(bytes.len()).ok_or_else(|| io::Error::other("audit envelope byte count overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
/// Count one event's exact serialized bytes without cloning its payload.
pub fn security_audit_event_wire_length(event:&SecurityAuditPendingDelivery)->Result<usize,serde_json::Error> {
    let mut count=ByteCount::default(); serde_json::to_writer(&mut count,&Event::from(event))?;Ok(count.0)
}
/// Count the final range header with an empty array and a fixed-width digest.
/// Add each event's count and one comma between events to obtain exact bytes.
pub fn security_audit_empty_envelope_wire_length(deployment_id:&str,first:&SecurityAuditPendingDelivery,last:&SecurityAuditPendingDelivery,event_count:i64)->Result<usize,serde_json::Error> {
    let mut count=ByteCount::default();
    serde_json::to_writer(&mut count,&BatchEnvelope { schema_version:AUDIT_ANCHOR_SCHEMA_VERSION,checkpoint_kind:"batch",deployment_id,first_sequence:first.sequence,last_sequence:last.sequence,event_count,previous_hash:URL_SAFE_NO_PAD.encode(&first.previous_hash),last_hash:URL_SAFE_NO_PAD.encode(&last.event_hash),batch_digest:URL_SAFE_NO_PAD.encode([0_u8;32]),events:Events(&[]) })?;
    Ok(count.0)
}
/// Encode a committed batch exactly as stored, including historical membership.
pub fn security_audit_batch_body(deployment_id:&str,batch:&SecurityAuditBatch)->Result<Vec<u8>,serde_json::Error> {
    serde_json::to_vec(&BatchEnvelope { schema_version:AUDIT_ANCHOR_SCHEMA_VERSION,checkpoint_kind:"batch",deployment_id,first_sequence:batch.first_sequence,last_sequence:batch.last_sequence,event_count:batch.event_count(),previous_hash:URL_SAFE_NO_PAD.encode(&batch.previous_hash),last_hash:URL_SAFE_NO_PAD.encode(&batch.last_hash),batch_digest:URL_SAFE_NO_PAD.encode(&batch.digest),events:Events(&batch.deliveries) })
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaped_payload_counts_match_final_json_and_maximum_singleton_bound() {
        for payload in ["plain".to_owned(), "\\\"\n\t".repeat(5_000), "雪".repeat(10_000)] {
            let event=SecurityAuditPendingDelivery { event_id:uuid::Uuid::now_v7(),sequence:999_999,event_type:"event\"name".into(),event_category:"security".into(),payload_canonical:serde_json::json!({"value":payload}).to_string(),occurred_at:chrono::Utc::now(),previous_hash:vec![1;32],event_hash:vec![2;32] };
            let count=security_audit_event_wire_length(&event).unwrap();
            let mut second=event.clone(); second.sequence+=1;
            let batch=SecurityAuditBatch {generation:1,first_sequence:event.sequence,last_sequence:second.sequence,previous_hash:event.previous_hash.clone(),last_hash:second.event_hash.clone(),digest:vec![3;32],attempts:0,deliveries:vec![event,second]};
            let expected=security_audit_empty_envelope_wire_length("deployment\"name",&batch.deliveries[0],&batch.deliveries[1],2).unwrap()+count+security_audit_event_wire_length(&batch.deliveries[1]).unwrap()+1;
            assert_eq!(security_audit_batch_body("deployment\"name",&batch).unwrap().len(),expected);
        }
        let event=SecurityAuditPendingDelivery {event_id:uuid::Uuid::now_v7(),sequence:i64::MAX,event_type:"e".repeat(128),event_category:"c".repeat(64),payload_canonical:"\\".repeat(crate::MAX_SECURITY_AUDIT_PAYLOAD_BYTES),occurred_at:chrono::Utc::now(),previous_hash:vec![1;32],event_hash:vec![2;32]};
        let bytes=security_audit_empty_envelope_wire_length(&"d".repeat(128),&event,&event,1).unwrap()+security_audit_event_wire_length(&event).unwrap();
        assert!(bytes<=MAX_SECURITY_AUDIT_SINGLETON_ENVELOPE_BYTES);
    }
}
