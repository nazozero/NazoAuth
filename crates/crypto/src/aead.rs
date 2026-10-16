//! AES-128/256-GCM authenticated encryption with fixed 12-byte nonces and
//! 16-byte tags. Wire layout is `ciphertext || tag`.

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit as _,
    aead::{Aead as _, AeadInOut as _, Payload},
};

use crate::CryptoError;

/// Encrypts directly in the persisted `nonce || ciphertext || tag` buffer.
/// The caller supplies a fresh nonce for this key.
pub fn encrypt_nonce_prefixed(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> crate::Result<Vec<u8>> {
    let mut protected = Vec::with_capacity(12 + plaintext.len() + 16);
    protected.extend_from_slice(nonce);
    protected.extend_from_slice(plaintext);
    let tag = Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce.into(), aad, (&mut protected[12..]).into())
        .map_err(|_| CryptoError::OperationFailed)?;
    protected.extend_from_slice(&tag);
    Ok(protected)
}

pub fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidInput)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .encrypt(nonce.into(), payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .encrypt(nonce.into(), payload),
        _ => return Err(CryptoError::InvalidKey),
    }
    .map_err(|_| CryptoError::OperationFailed)
}

pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> crate::Result<Vec<u8>> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidInput)?;
    if ciphertext_and_tag.len() < 16 {
        return Err(CryptoError::InvalidInput);
    }
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .decrypt(nonce.into(), payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .decrypt(nonce.into(), payload),
        _ => return Err(CryptoError::InvalidKey),
    }
    .map_err(|_| CryptoError::AuthenticationFailed)
}
