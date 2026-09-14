//! Single cryptographic execution boundary for NazoAuth.
//!
//! Protocol, application, and key-management code consumes the stable,
//! backend-free operations declared here. All concrete library imports and
//! error translation live inside this crate; no backend type, provider, or
//! error escapes the public surface.

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "x509")]
pub mod certificate;
#[cfg(feature = "ecdh")]
pub mod ec;
#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "jose")]
pub mod jwt;
#[cfg(feature = "jose")]
pub mod key_wrap;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "jose")]
pub mod signature;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported cryptographic algorithm")]
    UnsupportedAlgorithm,
    #[error("invalid cryptographic key")]
    InvalidKey,
    #[error("invalid cryptographic input")]
    InvalidInput,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invalid token")]
    InvalidToken,
    #[error("cryptographic operation failed")]
    OperationFailed,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
