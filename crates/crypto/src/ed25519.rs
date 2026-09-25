//! Opaque Ed25519 signing/verification keys for the operator protocol.

use ed25519_dalek::{Signer as _, Verifier as _};

use crate::CryptoError;

#[derive(Clone)]
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SigningKey(..)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifyingKey(..)")
    }
}

impl SigningKey {
    #[must_use]
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> crate::Result<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        self.inner
            .verify(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> crate::Result<()> {
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        self.inner
            .verify_strict(message, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}
