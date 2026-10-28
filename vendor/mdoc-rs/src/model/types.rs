//! Core types: MSO, ValidityInfo, DeviceKeyInfo, DeviceAuth, DigestAlgorithm.

use chrono::{DateTime, Utc};
use coset::{CoseKey, CoseMac0, CoseSign1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Digest algorithm for MSO value digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    #[serde(rename = "SHA-256")]
    Sha256,
    #[serde(rename = "SHA-384")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}

impl DigestAlgorithm {
    /// Parse from string (as used in MSO).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "SHA-256" => Some(Self::Sha256),
            "SHA-384" => Some(Self::Sha384),
            "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Get the string name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Get the digest output size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Mobile Security Object (ISO 18013-5 §9.1.2).
#[derive(Clone, Debug)]
pub struct Mso {
    /// MSO version (must be "1.0").
    pub version: String,
    /// Digest algorithm for value digests.
    pub digest_algorithm: DigestAlgorithm,
    /// Document type.
    pub doc_type: String,
    /// Validity information.
    pub validity_info: ValidityInfo,
    /// Value digests: namespace → (digestID → digest bytes).
    pub value_digests: HashMap<String, HashMap<u32, Vec<u8>>>,
    /// Device key information.
    pub device_key_info: Option<DeviceKeyInfo>,
    /// Revocation / status information (ISO 18013-5 Amd. / IETF Token Status
    /// List). Absent when the issuer published no status mechanism.
    pub status: Option<MsoStatus>,
}

/// MSO `status` element (revocation information).
///
/// ISO/IEC 18013-5 carries an optional `status` map in the MSO. The
/// most common form is the IETF Token Status List reference
/// (`status_list: { idx, uri }`); other/forward-compatible shapes are preserved
/// verbatim in [`MsoStatus::raw`] so callers can inspect them.
#[derive(Clone, Debug)]
pub struct MsoStatus {
    /// IETF Token Status List reference, when present.
    pub status_list: Option<StatusListInfo>,
    /// The raw, undecoded `status` CBOR value (always populated).
    pub raw: ciborium::Value,
}

/// IETF Token Status List reference (`status_list` member of the MSO `status`).
#[derive(Clone, Debug)]
pub struct StatusListInfo {
    /// Index of this credential's entry within the referenced status list.
    pub idx: u64,
    /// URI from which the status list token can be fetched.
    pub uri: String,
}

/// Validity information (ISO 18013-5 §9.1.2.4).
#[derive(Clone, Debug)]
pub struct ValidityInfo {
    /// When the MSO was signed.
    pub signed: DateTime<Utc>,
    /// When the MSO becomes valid.
    pub valid_from: DateTime<Utc>,
    /// When the MSO expires.
    pub valid_until: DateTime<Utc>,
    /// Expected next update (optional).
    pub expected_update: Option<DateTime<Utc>>,
}

/// Device key information from MSO.
#[derive(Clone, Debug)]
pub struct DeviceKeyInfo {
    /// Device's public key (COSE_Key).
    pub device_key: CoseKey,
    /// Key authorizations (optional).
    pub key_authorizations: Option<KeyAuthorizations>,
}

/// Key authorizations for device key.
#[derive(Clone, Debug)]
pub struct KeyAuthorizations {
    /// Authorized namespaces.
    pub name_spaces: Option<Vec<String>>,
    /// Authorized data elements per namespace.
    pub data_elements: Option<HashMap<String, Vec<String>>>,
}

/// Device authentication (ISO 18013-5 §9.1.3).
#[derive(Clone, Debug)]
pub enum DeviceAuth {
    /// ECDSA/EdDSA signature (COSE_Sign1).
    Signature(CoseSign1),
    /// HMAC via ECDH-derived key (COSE_Mac0).
    Mac(CoseMac0),
}

/// Supported COSE signing algorithms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseAlgorithm {
    ES256,
    ES384,
    ES512,
    EdDSA,
}

impl CoseAlgorithm {
    /// COSE algorithm identifier.
    pub fn cose_id(&self) -> i64 {
        match self {
            Self::ES256 => -7,
            Self::ES384 => -35,
            Self::ES512 => -36,
            Self::EdDSA => -8,
        }
    }

    /// Parse from COSE algorithm identifier.
    pub fn from_cose_id(id: i64) -> Option<Self> {
        match id {
            -7 => Some(Self::ES256),
            -35 => Some(Self::ES384),
            -36 => Some(Self::ES512),
            -8 => Some(Self::EdDSA),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
        }
    }
}
