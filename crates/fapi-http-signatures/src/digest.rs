use sfv::ItemSerializer;
use sha2::{Digest, Sha256};

/// Computes an RFC 9530 SHA-256 `Content-Digest` field value.
pub fn content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256={}",
        ItemSerializer::new().bare_item(digest.as_slice()).finish()
    )
}
