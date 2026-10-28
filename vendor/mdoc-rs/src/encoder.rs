//! DeviceResponse / Document CBOR encoder (feature: `issue`).
//!
//! Turns the in-memory [`MDoc`] / [`IssuerSignedDocument`] produced by the
//! [`crate::builder`] and [`crate::response_builder`] into the wire-format
//! `DeviceResponse` CBOR that [`crate::verifier::Verifier::verify`] consumes —
//! so issuance ↔ verification is a real round trip (improvement #4).
//!
//! The output uses the deterministic (canonical) CBOR encoding (#2) and emits
//! Tag-24-wrapped `IssuerSignedItem`s, matching ISO/IEC 18013-5 §8.3.2.1.2.2.

use ciborium::Value;
use coset::CborSerializable;

use crate::cbor::data_item;
use crate::error::MdocError;
use crate::model::document::IssuerSignedDocument;
use crate::model::mdoc::MDoc;
use crate::model::types::DeviceAuth;

/// Serialize a `coset` structure (COSE_Sign1 / COSE_Mac0) into a `ciborium::Value`.
fn cose_to_value<T: CborSerializable>(x: T) -> Result<Value, MdocError> {
    let bytes = x
        .to_vec()
        .map_err(|e| MdocError::Issuance(format!("encode COSE structure: {e}")))?;
    ciborium::from_reader(bytes.as_slice()).map_err(|e| MdocError::Cbor(e.to_string()))
}

/// Encode a single [`IssuerSignedDocument`] as a `Document` CBOR value.
fn encode_document(doc: &IssuerSignedDocument) -> Result<Value, MdocError> {
    // issuerSigned.nameSpaces: { ns: [ #6.24(bstr .cbor IssuerSignedItem) ] }
    let mut ns_entries = Vec::new();
    for (ns, items) in &doc.issuer_signed.name_spaces {
        let arr: Vec<Value> = items
            .iter()
            .map(|i| data_item::wrap_tag24(&i.encoded))
            .collect();
        ns_entries.push((Value::Text(ns.clone()), Value::Array(arr)));
    }

    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), Value::Map(ns_entries)),
        (
            Value::Text("issuerAuth".into()),
            cose_to_value(doc.issuer_signed.issuer_auth.cose_sign1.clone())?,
        ),
    ]);

    let mut doc_entries = vec![
        (
            Value::Text("docType".into()),
            Value::Text(doc.doc_type.clone()),
        ),
        (Value::Text("issuerSigned".into()), issuer_signed),
    ];

    if let Some(ds) = &doc.device_signed {
        let device_auth = match &ds.device_auth {
            DeviceAuth::Signature(s) => Value::Map(vec![(
                Value::Text("deviceSignature".into()),
                cose_to_value(s.clone())?,
            )]),
            DeviceAuth::Mac(m) => Value::Map(vec![(
                Value::Text("deviceMac".into()),
                cose_to_value(m.clone())?,
            )]),
        };
        // deviceSigned.nameSpaces = #6.24(bstr .cbor DeviceNameSpaces); preserve
        // the exact inner bytes that device authentication was computed over.
        let device_signed = Value::Map(vec![
            (
                Value::Text("nameSpaces".into()),
                data_item::wrap_tag24(&ds.name_spaces_bytes),
            ),
            (Value::Text("deviceAuth".into()), device_auth),
        ]);
        doc_entries.push((Value::Text("deviceSigned".into()), device_signed));
    }

    Ok(Value::Map(doc_entries))
}

/// Encode an [`MDoc`] as a `DeviceResponse` CBOR byte string.
pub fn encode_device_response(mdoc: &MDoc) -> Result<Vec<u8>, MdocError> {
    let documents = mdoc
        .documents
        .iter()
        .map(encode_document)
        .collect::<Result<Vec<_>, _>>()?;

    let response = Value::Map(vec![
        (
            Value::Text("version".into()),
            Value::Text(mdoc.version.clone()),
        ),
        (Value::Text("documents".into()), Value::Array(documents)),
        (
            Value::Text("status".into()),
            Value::Integer((mdoc.status.clone() as u8).into()),
        ),
    ]);

    // Deterministic encoding (#2): canonical CBOR makes the framing reproducible
    // regardless of the source HashMap iteration order. The COSE substructures
    // are arrays (order preserved) carrying byte-string protected headers and
    // payloads, so canonicalization never disturbs the signed bytes.
    data_item::encode_cbor_canonical(&response)
}

impl MDoc {
    /// Encode this MDoc as a `DeviceResponse` CBOR byte string (feature `issue`).
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        encode_device_response(self)
    }
}

impl IssuerSignedDocument {
    /// Encode this single document as a complete `DeviceResponse` CBOR byte
    /// string (version "1.0", status OK, one document).
    pub fn to_device_response_cbor(&self) -> Result<Vec<u8>, MdocError> {
        let mdoc = MDoc {
            version: "1.0".to_string(),
            status: crate::model::mdoc::MDocStatus::Ok,
            documents: vec![self.clone()],
        };
        encode_device_response(&mdoc)
    }
}
