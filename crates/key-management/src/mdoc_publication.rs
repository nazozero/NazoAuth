//! Persistence boundary for verified, externally signed CRL publications.

use std::{future::Future, pin::Pin};

use crate::Openid4vcPublicMaterial;

/// Positive CRL number, preserved without a machine-integer or JSON-number
/// conversion. The fixed-width representation also preserves unsigned order.
/// This numeric bound does not replace the host's DER/profile validation,
/// including the encoded positive-sign octet in the CRL extension's size bound.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MdocCrlNumber([u8; 20]);

impl MdocCrlNumber {
    pub fn from_big_endian(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= 20 && bytes[0] != 0,
            "CRL number must be a canonical positive integer of at most 20 bytes"
        );
        let mut number = [0_u8; 20];
        number[20 - bytes.len()..].copy_from_slice(bytes);
        Ok(Self(number))
    }

    pub fn to_fixed_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// The host has already authenticated the public authority and validated the
/// CRL signature, certificate bindings, contents and validity window.
#[derive(Clone)]
pub struct MdocCrlPublication {
    pub tenant_id: uuid::Uuid,
    /// Publication identifier derived from the IACA public key. A different DS
    /// or revocation snapshot under that IACA must not reset its number space.
    pub issuer_id: [u8; 32],
    pub issuer: String,
    pub number: MdocCrlNumber,
    pub der_sha256: [u8; 32],
    pub authority: Openid4vcPublicMaterial,
    pub this_update: jiff::Timestamp,
    pub next_update: jiff::Timestamp,
}

/// A successful ACK requires one atomic authoritative-public-material check and
/// persistent number fence, including the database clock. Exact republication
/// is idempotent; a lower number or an equal number with different bytes,
/// authority, issuer or timestamps must fail. Greater numbers may change the
/// authority but must not move thisUpdate backwards. Receipt retention spans
/// expiration and public-authority changes for the same tenant/IACA identifier.
pub trait MdocCrlPublicationStore: Send + Sync {
    fn accept_verified_publication<'a>(
        &'a self,
        publication: &'a MdocCrlPublication,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;
}
