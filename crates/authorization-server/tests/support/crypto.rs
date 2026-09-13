//! Independent AES-GCM decryption oracle for tests. Kept deliberately
//! separate from `nazo_crypto` so tests do not prove the implementation
//! against itself.

use anyhow::anyhow;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

pub(crate) fn aes_256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("invalid AES-256-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid AES-256-GCM nonce"))?;
    let mut protected = Vec::with_capacity(ciphertext.len() + tag.len());
    protected.extend_from_slice(ciphertext);
    protected.extend_from_slice(tag);
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut protected)
        .map_err(|_| anyhow!("AES-256-GCM authentication failed"))?;
    Ok(plaintext.to_vec())
}
