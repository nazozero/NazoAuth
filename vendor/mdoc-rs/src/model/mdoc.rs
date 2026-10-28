//! MDoc container (ISO 18013-5 §8.3.2.1.2.2).

use super::document::IssuerSignedDocument;

/// Top-level mdoc container.
#[derive(Clone, Debug)]
pub struct MDoc {
    /// Document version (must be "1.0").
    pub version: String,
    /// Status code.
    pub status: MDocStatus,
    /// Issuer-signed documents.
    pub documents: Vec<IssuerSignedDocument>,
}

/// MDoc status codes (ISO 18013-5 Table 8).
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MDocStatus {
    /// No error.
    Ok = 0,
    /// General error.
    GeneralError = 10,
    /// CBOR decoding error.
    CborDecodingError = 11,
    /// CBOR validation error.
    CborValidationError = 12,
}

impl MDocStatus {
    /// Parse from numeric value.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Ok,
            10 => Self::GeneralError,
            11 => Self::CborDecodingError,
            12 => Self::CborValidationError,
            _ => Self::GeneralError,
        }
    }
}
