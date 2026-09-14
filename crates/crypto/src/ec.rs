//! P-256 secret-key ownership, SEC1 normalization, and raw ECDH agreement.

use p256::{
    PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{Generate as _, sec1::ToSec1Point as _},
};

use crate::CryptoError;

#[derive(Clone)]
pub struct P256SecretKey {
    inner: SecretKey,
}

impl std::fmt::Debug for P256SecretKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("P256SecretKey(..)")
    }
}

impl P256SecretKey {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            inner: SecretKey::generate(),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> crate::Result<Self> {
        SecretKey::from_slice(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// Returns the uncompressed SEC1 public point `0x04 || x || y`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 65] {
        let point = self.inner.public_key().to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256 SEC1 point is 65 bytes")
    }

    /// Raw P-256 ECDH agreement; the returned shared secret is zeroized on drop.
    pub fn agree(&self, peer_sec1: &[u8]) -> crate::Result<zeroize::Zeroizing<[u8; 32]>> {
        let peer = PublicKey::from_sec1_bytes(peer_sec1).map_err(|_| CryptoError::InvalidKey)?;
        let shared = diffie_hellman(self.inner.to_nonzero_scalar(), peer.as_affine());
        let raw = shared.raw_secret_bytes();
        let mut secret = zeroize::Zeroizing::new([0_u8; 32]);
        secret.copy_from_slice(raw.as_slice());
        Ok(secret)
    }
}

/// Validates a SEC1 point and returns its uncompressed `0x04 || x || y` form.
pub fn normalize_p256_public_key(sec1: &[u8]) -> crate::Result<[u8; 65]> {
    let key = PublicKey::from_sec1_bytes(sec1).map_err(|_| CryptoError::InvalidKey)?;
    let point = key.to_sec1_point(false);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)
}
