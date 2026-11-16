//! JWT decoding and verification-key construction behind the crypto boundary.
//!
//! The four JOSE data/policy types are the same upstream types the codebase
//! already used; reusing them avoids inventing a parallel JWT model. The
//! backend key object itself is opaque.

pub use jsonwebtoken::{Algorithm, Header, TokenData, Validation};

use crate::CryptoError;

#[derive(Clone)]
pub struct VerificationKey {
    pub(crate) inner: jsonwebtoken::DecodingKey,
}

impl std::fmt::Debug for VerificationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerificationKey(..)")
    }
}

impl VerificationKey {
    pub fn from_rsa_components(n: &str, e: &str) -> crate::Result<Self> {
        jsonwebtoken::DecodingKey::from_rsa_components(n, e)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn from_ec_components(x: &str, y: &str) -> crate::Result<Self> {
        jsonwebtoken::DecodingKey::from_ec_components(x, y)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidKey)
    }

    pub fn from_ed_components(x: &str) -> crate::Result<Self> {
        let inner = jsonwebtoken::DecodingKey::from_ed_components(x)
            .map_err(|_| CryptoError::InvalidKey)?;
        if inner
            .try_get_as_bytes()
            .map_err(|_| CryptoError::InvalidKey)?
            .len()
            != 32
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { inner })
    }

    /// Reuses RSA components already decoded for the caller's key policy.
    #[must_use]
    pub fn from_rsa_raw_components(n: &[u8], e: &[u8]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_rsa_raw_components(n, e),
        }
    }

    #[must_use]
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_ed_der(bytes),
        }
    }

    #[must_use]
    pub fn from_p256_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Self {
        let mut point = [0_u8; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        Self::from_ec_sec1(&point)
    }

    /// Builds a verification key from a certificate's raw SEC1 public point.
    #[must_use]
    pub fn from_ec_sec1(bytes: &[u8]) -> Self {
        Self {
            inner: jsonwebtoken::DecodingKey::from_ec_der(bytes),
        }
    }
}

pub fn decode_header(token: &str) -> crate::Result<Header> {
    let header = jsonwebtoken::decode_header(token).map_err(token_error)?;
    reject_unsupported_extensions(&header)?;
    Ok(header)
}

pub fn decode<T: serde::de::DeserializeOwned>(
    token: &str,
    key: &VerificationKey,
    validation: &Validation,
) -> crate::Result<TokenData<T>> {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    validate_portable_key(&key.inner)?;
    let decoded = jsonwebtoken::decode(token, &key.inner, validation).map_err(token_error)?;
    reject_unsupported_extensions(&decoded.header)?;
    Ok(decoded)
}

fn reject_unsupported_extensions(header: &Header) -> crate::Result<()> {
    if header.crit.is_some() {
        return Err(CryptoError::InvalidToken);
    }
    Ok(())
}

pub mod dangerous {
    pub fn insecure_decode<T: serde::de::DeserializeOwned>(
        token: &str,
    ) -> crate::Result<super::TokenData<T>> {
        jsonwebtoken::dangerous::insecure_decode(token).map_err(super::token_error)
    }
}

fn token_error(error: jsonwebtoken::errors::Error) -> CryptoError {
    match error.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidSignature => CryptoError::InvalidSignature,
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => CryptoError::UnsupportedAlgorithm,
        jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => CryptoError::InvalidKey,
        jsonwebtoken::errors::ErrorKind::Provider(_) => CryptoError::OperationFailed,
        _ => CryptoError::InvalidToken,
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn validate_portable_key(key: &jsonwebtoken::DecodingKey) -> crate::Result<()> {
    match key.kind() {
        jsonwebtoken::DecodingKeyKind::RsaModulusExponent { n, e } => {
            // Match the native provider's canonical unsigned representation and
            // modulus limits. The provider owns the remaining RSA validation.
            let first = n
                .first()
                .copied()
                .filter(|byte| *byte != 0)
                .ok_or(CryptoError::InvalidSignature)?;
            let bits = n.len() * 8 - first.leading_zeros() as usize;
            if !(2048..=8192).contains(&bits) || e.first().is_none_or(|byte| *byte == 0) {
                return Err(CryptoError::InvalidSignature);
            }
            Ok(())
        }
        jsonwebtoken::DecodingKeyKind::SecretOrDer(_) => Ok(()),
    }
}
