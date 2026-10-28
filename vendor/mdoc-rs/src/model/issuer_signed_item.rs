//! IssuerSignedItem — individual attribute with digest verification.

use crate::cbor::data_item;
use crate::model::types::DigestAlgorithm;

/// A single issuer-signed data element (ISO 18013-5 §9.1.2.4).
///
/// Each item contains a random salt, element identifier, and value.
/// The CBOR encoding of the item is hashed and included in the MSO's `valueDigests`.
#[derive(Clone, Debug)]
pub struct IssuerSignedItem {
    /// Digest ID — maps to `valueDigests[namespace][digestID]` in the MSO.
    pub digest_id: u32,
    /// Random salt bytes.
    pub random: Vec<u8>,
    /// Attribute name (e.g., `"family_name"`, `"birth_date"`).
    pub element_identifier: String,
    /// Attribute value (CBOR).
    pub element_value: ciborium::Value,
    /// Original CBOR-encoded bytes (needed for digest computation).
    pub encoded: Vec<u8>,
}

impl IssuerSignedItem {
    /// Compute the digest of this item using the given algorithm.
    ///
    /// ISO 18013-5 §9.1.2.5 mandates that the value digest is taken over the
    /// `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)` — i.e. the
    /// **Tag-24-wrapped** encoding, not the bare item bytes. `self.encoded`
    /// holds the inner (un-tagged) item bytes exactly as received/produced, and
    /// we wrap them in the canonical Tag 24 envelope before hashing so we
    /// interoperate with conformant issuers (MEDIUM-1).
    pub fn compute_digest(&self, alg: &DigestAlgorithm) -> Vec<u8> {
        use sha2::Digest;
        let wrapped = data_item::encode_cbor(&data_item::wrap_tag24(&self.encoded))
            // Re-encoding a Tag 24 byte string can only fail on an allocator
            // error; fall back to the raw bytes so we still fail closed
            // (a wrong digest never matches) rather than panicking.
            .unwrap_or_else(|_| self.encoded.clone());
        match alg {
            DigestAlgorithm::Sha256 => sha2::Sha256::digest(&wrapped).to_vec(),
            DigestAlgorithm::Sha384 => sha2::Sha384::digest(&wrapped).to_vec(),
            DigestAlgorithm::Sha512 => sha2::Sha512::digest(&wrapped).to_vec(),
        }
    }

    /// Verify this item against a digest from the MSO.
    pub fn verify_digest(&self, expected_digest: &[u8], alg: &DigestAlgorithm) -> bool {
        let computed = self.compute_digest(alg);
        computed == expected_digest
    }
}
