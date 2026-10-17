//! AES-128/256-GCM authenticated encryption with fixed 12-byte nonces and
//! 16-byte tags. Wire layout is `ciphertext || tag`.

use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit as _, aead::AeadInOut as _};

use crate::CryptoError;

/// Encrypts directly in the final `prefix || ciphertext || tag` buffer.
/// The caller supplies the wire prefix and a fresh nonce for this key.
pub fn encrypt_prefixed(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    prefix: &[u8],
) -> crate::Result<Vec<u8>> {
    let mut protected = Vec::with_capacity(prefix.len() + plaintext.len() + 16);
    protected.extend_from_slice(prefix);
    protected.extend_from_slice(plaintext);
    let tag = Aes256Gcm::new(key.into())
        .encrypt_inout_detached(nonce.into(), aad, (&mut protected[prefix.len()..]).into())
        .map_err(|_| CryptoError::OperationFailed)?;
    protected.extend_from_slice(&tag);
    Ok(protected)
}

pub fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidInput)?;
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
    ciphertext.extend_from_slice(plaintext);
    let tag = encrypt_in_place(key, nonce, aad, &mut ciphertext)?;
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

/// Encrypts a caller-owned plaintext buffer and returns its detached authentication tag.
/// The caller supplies a fresh nonce for this key and must discard the buffer on error.
pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &mut [u8],
) -> crate::Result<[u8; 16]> {
    let tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .encrypt_inout_detached(nonce.into(), aad, plaintext.into()),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .encrypt_inout_detached(nonce.into(), aad, plaintext.into()),
        _ => return Err(CryptoError::InvalidKey),
    }
    .map_err(|_| CryptoError::OperationFailed)?;
    Ok(tag.into())
}

pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> crate::Result<Vec<u8>> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidInput)?;
    let (ciphertext, tag) = ciphertext_and_tag
        .split_last_chunk::<16>()
        .ok_or(CryptoError::InvalidInput)?;
    let mut plaintext = ciphertext.to_vec();
    decrypt_in_place(key, nonce, aad, &mut plaintext, tag)?;
    Ok(plaintext)
}

/// Authenticates `nonce || ciphertext || tag` in the caller's buffer and borrows
/// the plaintext region without moving it. Discard the buffer on error.
pub fn decrypt_nonce_prefixed<'a>(
    key: &[u8; 32],
    aad: &[u8],
    protected: &'a mut [u8],
) -> crate::Result<&'a [u8]> {
    let (nonce, ciphertext_and_tag) = protected
        .split_first_chunk_mut::<12>()
        .ok_or(CryptoError::InvalidInput)?;
    let (plaintext, tag) = ciphertext_and_tag
        .split_last_chunk_mut::<16>()
        .ok_or(CryptoError::InvalidInput)?;
    decrypt_in_place(key, nonce, aad, plaintext, tag)?;
    Ok(plaintext)
}

/// Authenticates and decrypts a caller-owned ciphertext buffer with a detached tag.
/// The caller must discard the buffer on error.
pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; 16],
) -> crate::Result<()> {
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into()),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey)?
            .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into()),
        _ => return Err(CryptoError::InvalidKey),
    }
    .map_err(|_| CryptoError::AuthenticationFailed)
}
