//! Error types for the mdoc-rs crate.

use thiserror::Error;

/// Errors from mdoc parsing, verification, and issuance operations.
#[derive(Debug, Error)]
pub enum MdocError {
    /// CBOR encoding/decoding error.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// COSE structure error (malformed Sign1, Mac0, or Key).
    #[error("COSE error: {0}")]
    Cose(String),

    /// Document parsing error.
    #[error("parse error: {0}")]
    Parse(String),

    /// MSO (Mobile Security Object) validation error.
    #[error("MSO error: {0}")]
    Mso(String),

    /// Certificate chain or X.509 error.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// Signature verification failure.
    #[error("signature error: {0}")]
    Signature(String),

    /// Selective disclosure digest mismatch.
    #[error("disclosure error: {0}")]
    Disclosure(String),

    /// Device authentication error.
    #[error("device auth error: {0}")]
    DeviceAuth(String),

    /// Reader authentication error.
    #[error("reader auth error: {0}")]
    ReaderAuth(String),

    /// Session transcript error.
    #[error("session error: {0}")]
    Session(String),

    /// Document building/issuance error.
    #[error("issuance error: {0}")]
    Issuance(String),

    /// Validity period error.
    #[error("validity error: {0}")]
    Validity(String),

    /// Trust store / chain verification error.
    #[cfg(feature = "tsp")]
    #[error("trust error: {0}")]
    Trust(#[from] tsp_ltv::error::TrustError),

    /// Unsupported algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

impl From<ciborium::de::Error<std::io::Error>> for MdocError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        MdocError::Cbor(e.to_string())
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for MdocError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        MdocError::Cbor(e.to_string())
    }
}

impl From<coset::CoseError> for MdocError {
    fn from(e: coset::CoseError) -> Self {
        MdocError::Cose(e.to_string())
    }
}
