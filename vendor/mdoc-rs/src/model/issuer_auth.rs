//! IssuerAuth — COSE_Sign1 wrapper with MSO extraction.

use super::types::{DeviceKeyInfo, Mso, ValidityInfo};
use crate::error::MdocError;
use coset::CoseSign1;

/// Issuer authentication (COSE_Sign1 containing the MSO).
#[derive(Clone, Debug)]
pub struct IssuerAuth {
    /// The raw COSE_Sign1 structure.
    pub cose_sign1: CoseSign1,
}

impl IssuerAuth {
    /// Create from a CoseSign1.
    pub fn new(cose_sign1: CoseSign1) -> Self {
        Self { cose_sign1 }
    }

    /// Decode the MSO from the COSE_Sign1 payload.
    ///
    /// The payload is a Tag 24 encoded CBOR containing the MSO.
    pub fn mso(&self) -> Result<Mso, MdocError> {
        let payload = self
            .cose_sign1
            .payload
            .as_ref()
            .ok_or_else(|| MdocError::Mso("missing COSE_Sign1 payload".to_string()))?;

        // ISO 18013-5 §9.1.2.4: the payload is
        // `MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)`,
        // i.e. the MSO map wrapped in CBOR Tag 24. Conformant issuers (e.g. the
        // ISO Annex D vector) emit the tag; some implementations inline the raw
        // map. Accept both: unwrap Tag 24 when present, otherwise treat the
        // decoded value as the MSO directly.
        let decoded: ciborium::Value = ciborium::from_reader(payload.as_slice())
            .map_err(|e| MdocError::Mso(format!("decode MSO CBOR: {e}")))?;

        let mso_value = match &decoded {
            ciborium::Value::Tag(crate::cbor::data_item::TAG_ENCODED_CBOR, inner) => {
                let bytes = inner.as_bytes().ok_or_else(|| {
                    MdocError::Mso(
                        "MobileSecurityObjectBytes Tag 24 inner is not bytes".to_string(),
                    )
                })?;
                ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| MdocError::Mso(format!("decode inner MSO CBOR: {e}")))?
            }
            _ => decoded,
        };

        parse_mso(&mso_value)
    }

    /// Extract the issuer certificate (DER) from the COSE unprotected header's x5chain.
    pub fn certificate_der(&self) -> Result<Vec<u8>, MdocError> {
        // x5chain is label 33 in COSE headers
        let x5chain_label = coset::Label::Int(33);

        // Check unprotected header first
        for (label, value) in &self.cose_sign1.unprotected.rest {
            if *label == x5chain_label {
                return extract_first_cert(value);
            }
        }

        Err(MdocError::Certificate(
            "no x5chain in COSE_Sign1 unprotected header".to_string(),
        ))
    }

    /// Extract the full certificate chain from the x5chain header.
    pub fn certificate_chain_der(&self) -> Result<Vec<Vec<u8>>, MdocError> {
        let x5chain_label = coset::Label::Int(33);

        for (label, value) in &self.cose_sign1.unprotected.rest {
            if *label == x5chain_label {
                return extract_cert_chain(value);
            }
        }

        Err(MdocError::Certificate(
            "no x5chain in COSE_Sign1 unprotected header".to_string(),
        ))
    }
}

/// Extract the first certificate from an x5chain value.
fn extract_first_cert(value: &ciborium::Value) -> Result<Vec<u8>, MdocError> {
    match value {
        ciborium::Value::Bytes(b) => Ok(b.clone()),
        ciborium::Value::Array(arr) => {
            if let Some(ciborium::Value::Bytes(b)) = arr.first() {
                Ok(b.clone())
            } else {
                Err(MdocError::Certificate("empty x5chain array".to_string()))
            }
        }
        _ => Err(MdocError::Certificate(
            "x5chain is not bytes or array".to_string(),
        )),
    }
}

/// Extract all certificates from an x5chain value.
fn extract_cert_chain(value: &ciborium::Value) -> Result<Vec<Vec<u8>>, MdocError> {
    match value {
        ciborium::Value::Bytes(b) => Ok(vec![b.clone()]),
        ciborium::Value::Array(arr) => {
            let mut chain = Vec::new();
            for item in arr {
                if let ciborium::Value::Bytes(b) = item {
                    chain.push(b.clone());
                } else {
                    return Err(MdocError::Certificate(
                        "x5chain array contains non-bytes".to_string(),
                    ));
                }
            }
            Ok(chain)
        }
        _ => Err(MdocError::Certificate(
            "x5chain is not bytes or array".to_string(),
        )),
    }
}

/// Parse an MSO from a CBOR Value.
fn parse_mso(value: &ciborium::Value) -> Result<Mso, MdocError> {
    use super::types::DigestAlgorithm;
    use std::collections::HashMap;

    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Mso("MSO is not a CBOR map".to_string()))?;

    let mut version = None;
    let mut digest_algorithm = None;
    let mut doc_type = None;
    let mut validity_info = None;
    let mut value_digests: HashMap<String, HashMap<u32, Vec<u8>>> = HashMap::new();
    let mut _device_key_info = None;
    let mut status = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Mso("MSO key is not text".to_string()))?;

        match key {
            "version" => {
                version = v.as_text().map(|s| s.to_string());
            }
            "digestAlgorithm" => {
                let alg_str = v
                    .as_text()
                    .ok_or_else(|| MdocError::Mso("digestAlgorithm is not text".to_string()))?;
                digest_algorithm = DigestAlgorithm::from_str_name(alg_str);
            }
            "docType" => {
                doc_type = v.as_text().map(|s| s.to_string());
            }
            "valueDigests" => {
                if let Some(ns_map) = v.as_map() {
                    for (ns_key, ns_val) in ns_map {
                        let ns = ns_key
                            .as_text()
                            .ok_or_else(|| MdocError::Mso("namespace key is not text".to_string()))?
                            .to_string();
                        let mut digests = HashMap::new();
                        if let Some(digest_map) = ns_val.as_map() {
                            for (digest_id_val, digest_bytes_val) in digest_map {
                                let digest_id = digest_id_val
                                    .as_integer()
                                    .and_then(|i| {
                                        u32::try_from({
                                            let v: i128 = i.into();
                                            v
                                        })
                                        .ok()
                                    })
                                    .ok_or_else(|| {
                                        MdocError::Mso("digestID is not an integer".to_string())
                                    })?;
                                let digest_bytes = digest_bytes_val
                                    .as_bytes()
                                    .ok_or_else(|| {
                                        MdocError::Mso("digest value is not bytes".to_string())
                                    })?
                                    .clone();
                                digests.insert(digest_id, digest_bytes);
                            }
                        }
                        value_digests.insert(ns, digests);
                    }
                }
            }
            "validityInfo" => {
                validity_info = Some(parse_validity_info(v)?);
            }
            "deviceKeyInfo" => {
                _device_key_info = Some(parse_device_key_info(v)?);
            }
            "status" => {
                status = Some(parse_status(v)?);
            }
            _ => {}
        }
    }

    Ok(Mso {
        version: version.ok_or_else(|| MdocError::Mso("missing version".to_string()))?,
        digest_algorithm: digest_algorithm
            .ok_or_else(|| MdocError::Mso("missing or unsupported digestAlgorithm".to_string()))?,
        doc_type: doc_type.ok_or_else(|| MdocError::Mso("missing docType".to_string()))?,
        validity_info: validity_info
            .ok_or_else(|| MdocError::Mso("missing validityInfo".to_string()))?,
        value_digests,
        device_key_info: _device_key_info,
        status,
    })
}

/// Parse the MSO `status` element (revocation info, INFO-3/INFO-4).
///
/// Recognizes the IETF Token Status List form
/// (`status_list: { idx: uint, uri: tstr }`) and preserves the raw CBOR for any
/// other/forward-compatible shape.
fn parse_status(value: &ciborium::Value) -> Result<super::types::MsoStatus, MdocError> {
    use super::types::{MsoStatus, StatusListInfo};

    let status_list = if let Some(map) = value.as_map() {
        if let Some((_, sl)) = map.iter().find(|(k, _)| k.as_text() == Some("status_list")) {
            let sl_map = sl.as_map().ok_or_else(|| {
                MdocError::Mso("status.status_list is not a CBOR map".to_string())
            })?;
            let idx = sl_map
                .iter()
                .find(|(k, _)| k.as_text() == Some("idx"))
                .and_then(|(_, v)| v.as_integer())
                .and_then(|i| {
                    u64::try_from({
                        let n: i128 = i.into();
                        n
                    })
                    .ok()
                })
                .ok_or_else(|| {
                    MdocError::Mso(
                        "status.status_list.idx is not a valid unsigned integer".to_string(),
                    )
                })?;
            let uri = sl_map
                .iter()
                .find(|(k, _)| k.as_text() == Some("uri"))
                .and_then(|(_, v)| v.as_text())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    MdocError::Mso("status.status_list.uri is not a text string".to_string())
                })?;
            Some(StatusListInfo { idx, uri })
        } else {
            None
        }
    } else {
        None
    };

    Ok(MsoStatus {
        status_list,
        raw: value.clone(),
    })
}

/// Parse ValidityInfo from a CBOR map.
///
/// Expected structure:
/// ```text
/// {
///   "signed": tdate,      // Tag 0 (datetime string); Tag 1 (epoch) also accepted
///   "validFrom": tdate,
///   "validUntil": tdate,
///   "expectedUpdate": tdate  // optional
/// }
/// ```
fn parse_validity_info(value: &ciborium::Value) -> Result<ValidityInfo, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Mso("validityInfo is not a CBOR map".to_string()))?;

    let mut signed = None;
    let mut valid_from = None;
    let mut valid_until = None;
    let mut expected_update = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Mso("validityInfo key is not text".to_string()))?;

        match key {
            "signed" => signed = Some(parse_datetime(v)?),
            "validFrom" => valid_from = Some(parse_datetime(v)?),
            "validUntil" => valid_until = Some(parse_datetime(v)?),
            "expectedUpdate" => expected_update = Some(parse_datetime(v)?),
            _ => {}
        }
    }

    Ok(ValidityInfo {
        signed: signed.ok_or_else(|| MdocError::Mso("missing validityInfo.signed".to_string()))?,
        valid_from: valid_from
            .ok_or_else(|| MdocError::Mso("missing validityInfo.validFrom".to_string()))?,
        valid_until: valid_until
            .ok_or_else(|| MdocError::Mso("missing validityInfo.validUntil".to_string()))?,
        expected_update,
    })
}

/// Parse a CBOR datetime value.
///
/// ISO 18013-5 §9.1.2.4 mandates `tdate` (RFC 8949 Tag 0, an RFC 3339 string)
/// for the validityInfo timestamps. We accept that form, and additionally the
/// numeric epoch form (RFC 8949 **Tag 1**, seconds since 1970) for robustness.
///
/// Untagged plain-text datetimes are **rejected**: accepting them widened the
/// input surface with no spec basis and masked malformed credentials
/// (MEDIUM-3). Note: the previous implementation mislabeled the epoch tag as
/// "Tag 6" — Tag 6 is not a datetime tag; the epoch-time tag is Tag 1.
fn parse_datetime(value: &ciborium::Value) -> Result<chrono::DateTime<chrono::Utc>, MdocError> {
    use chrono::{DateTime, TimeZone, Utc};

    match value {
        // Tag 0 (tdate): RFC 3339 datetime string — the spec-mandated form.
        ciborium::Value::Tag(0, inner) => {
            if let Some(s) = inner.as_text() {
                DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| MdocError::Mso(format!("invalid datetime: {e}")))
            } else {
                Err(MdocError::Mso("Tag 0 inner is not text".to_string()))
            }
        }
        // Tag 1: epoch-based datetime (integer seconds since 1970-01-01 UTC).
        ciborium::Value::Tag(1, inner) => {
            if let Some(i) = inner.as_integer() {
                let secs: i64 = {
                    let v: i128 = i.into();
                    v
                } as i64;
                Utc.timestamp_opt(secs, 0)
                    .single()
                    .ok_or_else(|| MdocError::Mso("invalid epoch timestamp".to_string()))
            } else {
                Err(MdocError::Mso("Tag 1 inner is not integer".to_string()))
            }
        }
        _ => Err(MdocError::Mso(format!(
            "expected tdate (Tag 0) or epoch (Tag 1) datetime, got {:?}",
            value
        ))),
    }
}

/// Parse DeviceKeyInfo from a CBOR map.
fn parse_device_key_info(value: &ciborium::Value) -> Result<DeviceKeyInfo, MdocError> {
    use coset::{CborSerializable, CoseKey};

    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Mso("deviceKeyInfo is not a CBOR map".to_string()))?;

    let mut device_key = None;
    let mut key_authorizations = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Mso("deviceKeyInfo key is not text".to_string()))?;

        match key {
            "deviceKey" => {
                // deviceKey is a COSE_Key (CBOR map)
                let mut key_bytes = Vec::new();
                ciborium::into_writer(v, &mut key_bytes)
                    .map_err(|e| MdocError::Mso(format!("encode deviceKey: {e}")))?;
                let cose_key = CoseKey::from_slice(&key_bytes)
                    .map_err(|e| MdocError::Mso(format!("parse deviceKey COSE_Key: {e}")))?;
                device_key = Some(cose_key);
            }
            "keyAuthorizations" => {
                key_authorizations = Some(parse_key_authorizations(v)?);
            }
            _ => {}
        }
    }

    Ok(DeviceKeyInfo {
        device_key: device_key
            .ok_or_else(|| MdocError::Mso("missing deviceKey in deviceKeyInfo".to_string()))?,
        key_authorizations,
    })
}

/// Parse KeyAuthorizations from a CBOR map.
fn parse_key_authorizations(
    value: &ciborium::Value,
) -> Result<super::types::KeyAuthorizations, MdocError> {
    let map = value
        .as_map()
        .ok_or_else(|| MdocError::Mso("keyAuthorizations is not a CBOR map".to_string()))?;

    let mut name_spaces = None;
    let mut data_elements = None;

    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| MdocError::Mso("keyAuthorizations key is not text".to_string()))?;

        match key {
            "nameSpaces" => {
                if let Some(arr) = v.as_array() {
                    let ns: Vec<String> = arr
                        .iter()
                        .filter_map(|item| item.as_text().map(|s| s.to_string()))
                        .collect();
                    name_spaces = Some(ns);
                }
            }
            "dataElements" => {
                if let Some(ns_map) = v.as_map() {
                    let mut de = std::collections::HashMap::new();
                    for (ns_key, ns_val) in ns_map {
                        let ns = ns_key
                            .as_text()
                            .ok_or_else(|| MdocError::Mso("namespace key is not text".to_string()))?
                            .to_string();
                        if let Some(arr) = ns_val.as_array() {
                            let elems: Vec<String> = arr
                                .iter()
                                .filter_map(|item| item.as_text().map(|s| s.to_string()))
                                .collect();
                            de.insert(ns, elems);
                        }
                    }
                    data_elements = Some(de);
                }
            }
            _ => {}
        }
    }

    Ok(super::types::KeyAuthorizations {
        name_spaces,
        data_elements,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_datetime, parse_status};

    #[test]
    fn status_list_is_parsed() {
        // status = { status_list: { idx: 42, uri: "https://issuer/statuslist/1" } }
        let v = ciborium::Value::Map(vec![(
            ciborium::Value::Text("status_list".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("idx".into()),
                    ciborium::Value::Integer(42u8.into()),
                ),
                (
                    ciborium::Value::Text("uri".into()),
                    ciborium::Value::Text("https://issuer/statuslist/1".into()),
                ),
            ]),
        )]);
        let status = parse_status(&v).expect("status_list parsed");
        let sl = status.status_list.expect("status_list parsed");
        assert_eq!(sl.idx, 42);
        assert_eq!(sl.uri, "https://issuer/statuslist/1");
    }

    #[test]
    fn unknown_status_shape_is_preserved_raw() {
        // A non-status_list shape still round-trips via `raw`.
        let v = ciborium::Value::Map(vec![(
            ciborium::Value::Text("identifier_list".into()),
            ciborium::Value::Integer(7u8.into()),
        )]);
        let status = parse_status(&v).expect("unknown shape preserved");
        assert!(status.status_list.is_none());
        assert_eq!(status.raw, v);
    }

    #[test]
    fn malformed_status_list_is_rejected() {
        let v = ciborium::Value::Map(vec![(
            ciborium::Value::Text("status_list".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("idx".into()),
                    ciborium::Value::Text("not-an-integer".into()),
                ),
                (
                    ciborium::Value::Text("uri".into()),
                    ciborium::Value::Text("https://issuer/statuslist/1".into()),
                ),
            ]),
        )]);

        assert!(parse_status(&v).is_err());
    }

    #[test]
    fn tag0_tdate_is_accepted() {
        let v = ciborium::Value::Tag(
            0,
            Box::new(ciborium::Value::Text("2026-05-31T12:00:00Z".into())),
        );
        assert!(parse_datetime(&v).is_ok());
    }

    #[test]
    fn tag1_epoch_is_accepted() {
        let v = ciborium::Value::Tag(
            1,
            Box::new(ciborium::Value::Integer(1_780_000_000i64.into())),
        );
        assert!(parse_datetime(&v).is_ok());
    }

    #[test]
    fn untagged_text_is_rejected() {
        // MEDIUM-3: a plain (untagged) datetime string is no longer accepted.
        let v = ciborium::Value::Text("2026-05-31T12:00:00Z".into());
        assert!(parse_datetime(&v).is_err());
    }

    #[test]
    fn tag6_is_not_a_datetime() {
        // The old code mislabeled the epoch tag as "Tag 6"; Tag 6 must be rejected.
        let v = ciborium::Value::Tag(6, Box::new(ciborium::Value::Integer(0i64.into())));
        assert!(parse_datetime(&v).is_err());
    }
}
