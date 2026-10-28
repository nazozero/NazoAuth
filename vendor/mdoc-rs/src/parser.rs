//! Parse CBOR-encoded DeviceResponse → MDoc.

use std::collections::HashMap;

use coset::CborSerializable;

use crate::cbor::data_item;
use crate::error::MdocError;
use crate::model::*;

/// Parse a hex-encoded DeviceResponse into an MDoc.
///
/// Convenience over [`parse`] for the common case of credentials handed around
/// as hex strings (test vectors, logs, QR payloads). ASCII whitespace is
/// ignored, so multi-line/pretty-printed hex is accepted (improvement #11).
pub fn parse_hex(hex_str: &str) -> Result<MDoc, MdocError> {
    let bytes = decode_hex(hex_str)?;
    parse(&bytes)
}

/// Minimal, dependency-free hex decoder that skips ASCII whitespace.
fn decode_hex(s: &str) -> Result<Vec<u8>, MdocError> {
    let nibble = |c: u8| -> Result<u8, MdocError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(MdocError::Parse(format!(
                "invalid hex character: {:?}",
                c as char
            ))),
        }
    };

    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = nibble(c)?;
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push((h << 4) | v),
        }
    }
    if hi.is_some() {
        return Err(MdocError::Parse(
            "hex string has an odd number of digits".to_string(),
        ));
    }
    Ok(out)
}

/// Parse a CBOR-encoded DeviceResponse into an MDoc.
pub fn parse(cbor_bytes: &[u8]) -> Result<MDoc, MdocError> {
    let value: ciborium::Value = ciborium::from_reader(cbor_bytes)
        .map_err(|e| MdocError::Parse(format!("CBOR decode: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Parse("DeviceResponse is not a CBOR map".to_string()))?;

    let mut version = None;
    let mut status = 0u8;
    let mut documents = Vec::new();

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("DeviceResponse key is not text".to_string()))?;

        match key {
            "version" => {
                version = v.as_text().map(|s| s.to_string());
            }
            "status" => {
                // Fail closed: a status that cannot be decoded as a small
                // integer is treated as a general error, not silently as Ok(0)
                // (INFO-3). The verifier additionally asserts status == Ok.
                status = v
                    .as_integer()
                    .and_then(|i| {
                        u8::try_from({
                            let v: i128 = i.into();
                            v
                        })
                        .ok()
                    })
                    .unwrap_or(10);
            }
            "documents" => {
                if let Some(arr) = v.as_array() {
                    for doc_val in arr {
                        documents.push(parse_document(doc_val)?);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(MDoc {
        version: version.ok_or_else(|| MdocError::Parse("missing version".to_string()))?,
        status: MDocStatus::from_u8(status),
        documents,
    })
}

fn parse_document(value: &ciborium::Value) -> Result<IssuerSignedDocument, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Parse("document is not a CBOR map".to_string()))?;

    let mut doc_type = None;
    let mut issuer_signed = None;
    let mut device_signed = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("document key is not text".to_string()))?;

        match key {
            "docType" => {
                doc_type = v.as_text().map(|s| s.to_string());
            }
            "issuerSigned" => {
                issuer_signed = Some(parse_issuer_signed(v)?);
            }
            "deviceSigned" => {
                device_signed = Some(parse_device_signed(v)?);
            }
            _ => {}
        }
    }

    Ok(IssuerSignedDocument {
        doc_type: doc_type.ok_or_else(|| MdocError::Parse("missing docType".to_string()))?,
        issuer_signed: issuer_signed
            .ok_or_else(|| MdocError::Parse("missing issuerSigned".to_string()))?,
        device_signed,
    })
}

fn parse_issuer_signed(value: &ciborium::Value) -> Result<IssuerSigned, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Parse("issuerSigned is not a CBOR map".to_string()))?;

    let mut issuer_auth = None;
    let mut name_spaces: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("issuerSigned key is not text".to_string()))?;

        match key {
            "issuerAuth" => {
                // issuerAuth is a COSE_Sign1 (CBOR array of 4 elements)
                let cose_bytes = data_item::encode_cbor(v)?;
                let cose_sign1 = coset::CoseSign1::from_slice(&cose_bytes)
                    .map_err(|e| MdocError::Parse(format!("parse issuerAuth COSE_Sign1: {e}")))?;
                issuer_auth = Some(IssuerAuth::new(cose_sign1));
            }
            "nameSpaces" => {
                if let Some(ns_map) = v.as_map() {
                    for (ns_key, ns_val) in ns_map {
                        let ns = ns_key
                            .as_text()
                            .ok_or_else(|| {
                                MdocError::Parse("namespace key is not text".to_string())
                            })?
                            .to_string();

                        let mut items = Vec::new();
                        if let Some(arr) = ns_val.as_array() {
                            for item_val in arr {
                                items.push(parse_issuer_signed_item(item_val)?);
                            }
                        }
                        name_spaces.insert(ns, items);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(IssuerSigned {
        issuer_auth: issuer_auth
            .ok_or_else(|| MdocError::Parse("missing issuerAuth".to_string()))?,
        name_spaces,
    })
}

fn parse_issuer_signed_item(value: &ciborium::Value) -> Result<IssuerSignedItem, MdocError> {
    // Items may be wrapped in Tag 24
    let (inner, encoded) = match value {
        ciborium::Value::Tag(24, inner) => {
            let bytes = inner
                .as_bytes()
                .ok_or_else(|| MdocError::Parse("Tag 24 content is not bytes".to_string()))?;
            let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice())
                .map_err(|e| MdocError::Parse(format!("decode Tag 24 item: {e}")))?;
            (decoded, bytes.clone())
        }
        _ => {
            let encoded = data_item::encode_cbor(value)?;
            (value.clone(), encoded)
        }
    };

    let map = inner
        .as_map()
        .ok_or_else(|| MdocError::Parse("IssuerSignedItem is not a CBOR map".to_string()))?;

    let mut digest_id = None;
    let mut random = None;
    let mut element_identifier = None;
    let mut element_value = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("item key is not text".to_string()))?;

        match key {
            "digestID" => {
                digest_id = v.as_integer().and_then(|i| {
                    u32::try_from({
                        let v: i128 = i.into();
                        v
                    })
                    .ok()
                });
            }
            "random" => {
                random = v.as_bytes().cloned();
            }
            "elementIdentifier" => {
                element_identifier = v.as_text().map(|s| s.to_string());
            }
            "elementValue" => {
                element_value = Some(v.clone());
            }
            _ => {}
        }
    }

    Ok(IssuerSignedItem {
        digest_id: digest_id.ok_or_else(|| MdocError::Parse("missing digestID".to_string()))?,
        random: random.ok_or_else(|| MdocError::Parse("missing random".to_string()))?,
        element_identifier: element_identifier
            .ok_or_else(|| MdocError::Parse("missing elementIdentifier".to_string()))?,
        element_value: element_value
            .ok_or_else(|| MdocError::Parse("missing elementValue".to_string()))?,
        encoded,
    })
}

fn parse_device_signed(value: &ciborium::Value) -> Result<DeviceSigned, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Parse("deviceSigned is not a CBOR map".to_string()))?;

    let mut device_auth = None;
    let mut name_spaces: HashMap<String, HashMap<String, ciborium::Value>> = HashMap::new();
    // Inner bytes of DeviceNameSpaces (content of the Tag-24 wrapper). Default
    // to an empty map encoding so a deviceSigned without nameSpaces still
    // produces the canonical empty-map bytes used in DeviceAuthentication.
    let mut name_spaces_bytes: Vec<u8> = data_item::encode_cbor(&ciborium::Value::Map(vec![]))?;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("deviceSigned key is not text".to_string()))?;

        match key {
            "deviceAuth" => {
                device_auth = Some(parse_device_auth(v)?);
            }
            "nameSpaces" => {
                // DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces).
                // Unwrap the Tag 24 (or accept a raw bstr / bare map for
                // lenient producers) and keep the exact inner bytes for device
                // authentication, then decode them into the attribute map.
                let (ns_value, inner_bytes) = match v {
                    ciborium::Value::Tag(24, inner) => {
                        let bytes = inner.as_bytes().ok_or_else(|| {
                            MdocError::Parse(
                                "deviceSigned nameSpaces Tag 24 is not bytes".to_string(),
                            )
                        })?;
                        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice())
                            .map_err(|e| {
                                MdocError::Parse(format!("decode DeviceNameSpaces: {e}"))
                            })?;
                        (decoded, bytes.clone())
                    }
                    ciborium::Value::Bytes(bytes) => {
                        let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice())
                            .map_err(|e| {
                                MdocError::Parse(format!("decode DeviceNameSpaces: {e}"))
                            })?;
                        (decoded, bytes.clone())
                    }
                    other => {
                        // Bare (un-wrapped) DeviceNameSpaces map.
                        (other.clone(), data_item::encode_cbor(other)?)
                    }
                };
                name_spaces_bytes = inner_bytes;

                if let Some(ns_map) = ns_value.as_map() {
                    for (ns_key, ns_val) in ns_map {
                        let ns = ns_key
                            .as_text()
                            .ok_or_else(|| {
                                MdocError::Parse("namespace key is not text".to_string())
                            })?
                            .to_string();

                        let mut elements = HashMap::new();
                        if let Some(elem_map) = ns_val.as_map() {
                            for (ek, ev) in elem_map {
                                let elem = ek
                                    .as_text()
                                    .ok_or_else(|| {
                                        MdocError::Parse("element key is not text".to_string())
                                    })?
                                    .to_string();
                                elements.insert(elem, ev.clone());
                            }
                        }
                        name_spaces.insert(ns, elements);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(DeviceSigned {
        device_auth: device_auth
            .ok_or_else(|| MdocError::Parse("missing deviceAuth".to_string()))?,
        name_spaces,
        name_spaces_bytes,
    })
}

fn parse_device_auth(value: &ciborium::Value) -> Result<DeviceAuth, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Parse("deviceAuth is not a CBOR map".to_string()))?;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Parse("deviceAuth key is not text".to_string()))?;

        match key {
            "deviceSignature" => {
                let cose_bytes = data_item::encode_cbor(v)?;
                let sign1 = coset::CoseSign1::from_slice(&cose_bytes)
                    .map_err(|e| MdocError::Parse(format!("parse deviceSignature: {e}")))?;
                return Ok(DeviceAuth::Signature(sign1));
            }
            "deviceMac" => {
                let cose_bytes = data_item::encode_cbor(v)?;
                let mac0 = coset::CoseMac0::from_slice(&cose_bytes)
                    .map_err(|e| MdocError::Parse(format!("parse deviceMac: {e}")))?;
                return Ok(DeviceAuth::Mac(mac0));
            }
            _ => {}
        }
    }

    Err(MdocError::Parse(
        "deviceAuth has neither deviceSignature nor deviceMac".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn decode_hex_basic() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
    }

    #[test]
    fn decode_hex_skips_whitespace() {
        assert_eq!(
            decode_hex("de ad\n be\tef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn decode_hex_rejects_non_hex() {
        assert!(decode_hex("zz").is_err());
    }
}
