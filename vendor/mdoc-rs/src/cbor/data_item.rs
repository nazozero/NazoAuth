//! CBOR Tag 24 — Encoded CBOR Data Item (RFC 8949 §3.4.5.1).
//!
//! Used in mdoc for:
//! - IssuerSignedItem encoding (each item is independently verifiable)
//! - MSO payload inside COSE_Sign1

use crate::error::MdocError;
use ciborium::Value;

/// CBOR Tag number for encoded CBOR data items.
pub const TAG_ENCODED_CBOR: u64 = 24;

/// Encode a value to CBOR bytes.
///
/// This preserves the map element order as given. For issuance output that must
/// be reproducible and interoperable with strict verifiers, use
/// [`encode_cbor_canonical`] instead.
pub fn encode_cbor(value: &Value) -> Result<Vec<u8>, MdocError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Encode a value to **deterministic (canonical) CBOR** bytes.
///
/// ISO/IEC 18013-5 §9.1.2.5 requires the CBOR deterministic encoding for
/// issuance output (the MSO, each `IssuerSignedItem`, and `valueDigests`).
/// `ciborium` already emits definite-length items and shortest-form integers,
/// but it does **not** sort map keys. This wrapper recursively reorders every
/// map's entries into the RFC 8949 §4.2.1 canonical order (by the bytewise
/// lexicographic order of the *encoded* keys), so the output is stable across
/// runs regardless of the source `HashMap` iteration order.
pub fn encode_cbor_canonical(value: &Value) -> Result<Vec<u8>, MdocError> {
    let canonical = canonicalize(value)?;
    encode_cbor(&canonical)
}

/// Recursively rewrite a CBOR value into canonical form: every map's entries are
/// sorted by the encoded bytes of their (already-canonicalized) keys, per
/// RFC 8949 §4.2.1. Arrays and tag contents are canonicalized in place; scalars
/// are returned unchanged.
fn canonicalize(value: &Value) -> Result<Value, MdocError> {
    Ok(match value {
        Value::Map(entries) => {
            // Canonicalize each key/value, encode the key, and sort by key bytes.
            let mut keyed: Vec<(Vec<u8>, Value, Value)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let ck = canonicalize(k)?;
                let cv = canonicalize(v)?;
                let key_bytes = encode_cbor(&ck)?;
                keyed.push((key_bytes, ck, cv));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalize(item)?);
            }
            Value::Array(out)
        }
        Value::Tag(tag, inner) => Value::Tag(*tag, Box::new(canonicalize(inner)?)),
        other => other.clone(),
    })
}

/// Decode CBOR bytes to a value.
pub fn decode_cbor(bytes: &[u8]) -> Result<Value, MdocError> {
    ciborium::from_reader(bytes).map_err(|e| MdocError::Cbor(e.to_string()))
}

/// Wrap bytes in CBOR Tag 24 (encoded CBOR data item).
pub fn wrap_tag24(data: &[u8]) -> Value {
    Value::Tag(TAG_ENCODED_CBOR, Box::new(Value::Bytes(data.to_vec())))
}

/// Unwrap CBOR Tag 24 to get the inner bytes.
pub fn unwrap_tag24(value: &Value) -> Result<Vec<u8>, MdocError> {
    match value {
        Value::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            Value::Bytes(bytes) => Ok(bytes.clone()),
            _ => Err(MdocError::Cbor(
                "Tag 24 inner value is not bytes".to_string(),
            )),
        },
        Value::Bytes(bytes) => {
            // Some implementations omit the tag and just use raw bytes
            Ok(bytes.clone())
        }
        _ => Err(MdocError::Cbor(format!(
            "expected Tag 24 or bytes, got {:?}",
            value
        ))),
    }
}

/// Encode a value and wrap it in Tag 24.
pub fn encode_as_tag24(value: &Value) -> Result<Value, MdocError> {
    let encoded = encode_cbor(value)?;
    Ok(wrap_tag24(&encoded))
}

/// Unwrap Tag 24 and decode the inner CBOR.
pub fn decode_tag24(value: &Value) -> Result<Value, MdocError> {
    let bytes = unwrap_tag24(value)?;
    decode_cbor(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag24_round_trip() {
        let original = Value::Text("hello".to_string());
        let wrapped = encode_as_tag24(&original).unwrap();
        let decoded = decode_tag24(&wrapped).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tag24_bytes_round_trip() {
        let data = b"test data";
        let tagged = wrap_tag24(data);
        let unwrapped = unwrap_tag24(&tagged).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn unwrap_plain_bytes() {
        // Some impls omit tag 24 and just use raw bytes
        let val = Value::Bytes(b"raw bytes".to_vec());
        let result = unwrap_tag24(&val).unwrap();
        assert_eq!(result, b"raw bytes");
    }

    #[test]
    fn canonical_sorts_map_keys_by_encoded_bytes() {
        // RFC 8949 §4.2.1: keys sort by encoded length first, then lexicographically.
        // Text-key encoding is major-type-3 + length, so shorter keys sort first.
        let map = Value::Map(vec![
            (
                Value::Text("elementValue".into()),
                Value::Text("Doe".into()),
            ),
            (Value::Text("digestID".into()), Value::Integer(0u8.into())),
            (Value::Text("random".into()), Value::Bytes(vec![1, 2, 3])),
            (
                Value::Text("elementIdentifier".into()),
                Value::Text("family_name".into()),
            ),
        ]);
        let bytes = encode_cbor_canonical(&map).unwrap();
        // Decode and confirm the key order is: random(6) < digestID(8)
        // < elementValue(12) < elementIdentifier(17).
        let decoded = decode_cbor(&bytes).unwrap();
        let keys: Vec<String> = decoded
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(
            keys,
            vec!["random", "digestID", "elementValue", "elementIdentifier"]
        );
    }

    #[test]
    fn canonical_is_order_independent() {
        // Two maps with the same entries in different orders must encode identically.
        let a = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(2u8.into())),
            (Value::Text("a".into()), Value::Integer(1u8.into())),
        ]);
        let b = Value::Map(vec![
            (Value::Text("a".into()), Value::Integer(1u8.into())),
            (Value::Text("b".into()), Value::Integer(2u8.into())),
        ]);
        assert_eq!(
            encode_cbor_canonical(&a).unwrap(),
            encode_cbor_canonical(&b).unwrap()
        );
    }

    #[test]
    fn canonical_recurses_into_nested_maps() {
        let nested = Value::Map(vec![(
            Value::Text("outer".into()),
            Value::Map(vec![
                (Value::Text("zz".into()), Value::Integer(1u8.into())),
                (Value::Text("a".into()), Value::Integer(2u8.into())),
            ]),
        )]);
        let bytes = encode_cbor_canonical(&nested).unwrap();
        let decoded = decode_cbor(&bytes).unwrap();
        let inner = decoded.as_map().unwrap()[0].1.as_map().unwrap();
        let keys: Vec<String> = inner
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect();
        assert_eq!(keys, vec!["a", "zz"]);
    }
}
