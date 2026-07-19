//! Validation of operator-managed mTLS trust anchors.
//!
//! RFC 8705 defines certificate-bound OAuth behavior but deliberately leaves
//! CA trust decisions to deployments. This module validates the RFC 5280
//! certificate boundary without exposing an OAuth protocol shortcut.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use x509_parser::{prelude::parse_x509_certificate, public_key::PublicKey};

const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";
const MAX_PEM_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ValidatedMtlsTrustAnchor {
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MtlsTrustAnchorError {
    #[error("the trust anchor must contain exactly one PEM certificate")]
    InvalidPem,
    #[error("the trust anchor exceeds the 16 KiB input limit")]
    TooLarge,
    #[error("the trust anchor certificate is not currently valid")]
    NotCurrent,
    #[error("the certificate is not an RFC 5280 CA certificate")]
    NotCertificateAuthority,
    #[error("the CA certificate must have critical keyUsage with keyCertSign")]
    InvalidKeyUsage,
    #[error("the CA public key does not meet the deployment security policy")]
    WeakOrUnsupportedKey,
}

pub fn validate_mtls_trust_anchor(
    pem: &str,
) -> Result<ValidatedMtlsTrustAnchor, MtlsTrustAnchorError> {
    if pem.len() > MAX_PEM_BYTES {
        return Err(MtlsTrustAnchorError::TooLarge);
    }
    let trimmed = pem.trim();
    let body = trimmed
        .strip_prefix(BEGIN_CERTIFICATE)
        .and_then(|value| value.strip_suffix(END_CERTIFICATE))
        .ok_or(MtlsTrustAnchorError::InvalidPem)?;
    if body.contains(BEGIN_CERTIFICATE) || body.contains(END_CERTIFICATE) {
        return Err(MtlsTrustAnchorError::InvalidPem);
    }
    let encoded = body
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| MtlsTrustAnchorError::InvalidPem)?;
    let (remainder, certificate) =
        parse_x509_certificate(&der).map_err(|_| MtlsTrustAnchorError::InvalidPem)?;
    if !remainder.is_empty() {
        return Err(MtlsTrustAnchorError::InvalidPem);
    }
    if !certificate.validity().is_valid() {
        return Err(MtlsTrustAnchorError::NotCurrent);
    }
    certificate
        .basic_constraints()
        .map_err(|_| MtlsTrustAnchorError::NotCertificateAuthority)?
        .filter(|extension| extension.critical && extension.value.ca)
        .ok_or(MtlsTrustAnchorError::NotCertificateAuthority)?;
    certificate
        .key_usage()
        .map_err(|_| MtlsTrustAnchorError::InvalidKeyUsage)?
        .filter(|extension| extension.critical && extension.value.key_cert_sign())
        .ok_or(MtlsTrustAnchorError::InvalidKeyUsage)?;

    let public_key = certificate
        .public_key()
        .parsed()
        .map_err(|_| MtlsTrustAnchorError::WeakOrUnsupportedKey)?;
    match public_key {
        PublicKey::RSA(key)
            if key.key_size() >= 2048 && key.try_exponent().ok() == Some(65_537) => {}
        PublicKey::EC(key) if matches!(key.key_size(), 256 | 384 | 521) => {}
        _ => return Err(MtlsTrustAnchorError::WeakOrUnsupportedKey),
    }

    let canonical_body = STANDARD.encode(&der);
    let canonical_body = canonical_body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 output is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    let not_before = DateTime::from_timestamp(certificate.validity().not_before.timestamp(), 0)
        .ok_or(MtlsTrustAnchorError::InvalidPem)?;
    let not_after = DateTime::from_timestamp(certificate.validity().not_after.timestamp(), 0)
        .ok_or(MtlsTrustAnchorError::InvalidPem)?;
    Ok(ValidatedMtlsTrustAnchor {
        certificate_pem: format!("{BEGIN_CERTIFICATE}\n{canonical_body}\n{END_CERTIFICATE}\n"),
        certificate_sha256: hex_digest(&Sha256::digest(&der)),
        subject_dn: certificate.subject().to_string(),
        not_before,
        not_after,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
