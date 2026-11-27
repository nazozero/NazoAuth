//! Encrypted digital-credential records; AAD binds ciphertext to its storage key.

pub(crate) mod datasets;
pub(crate) mod issuance;
pub(crate) mod presentation;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::ports::RepositoryError;
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{RocksDb, users::corrupt};

#[derive(Clone)]
pub(crate) struct EncryptedStore {
    pub(crate) provider: RocksDb,
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl EncryptedStore {
    pub(crate) fn new(provider: RocksDb, key: [u8; 32]) -> Self {
        Self {
            provider,
            key: Arc::new(Zeroizing::new(key)),
        }
    }

    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<String, RepositoryError> {
        seal(&self.key, aad, plaintext)
    }

    pub(crate) fn seal_value<T: Serialize + ?Sized>(
        &self,
        aad: &[u8],
        value: &T,
    ) -> Result<String, RepositoryError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| corrupt("credential serialization failed"))?,
        );
        self.seal(aad, &plaintext)
    }

    pub(crate) fn open<T: DeserializeOwned>(
        &self,
        aad: &[u8],
        ciphertext: &str,
    ) -> Result<T, RepositoryError> {
        let mut buffer = Zeroizing::new(
            STANDARD
                .decode(ciphertext)
                .map_err(|_| corrupt("invalid credential ciphertext"))?,
        );
        let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(&self.key, aad, &mut buffer)
            .map_err(|_| corrupt("credential authentication failed"))?;
        serde_json::from_slice(plaintext)
            .map_err(|_| corrupt("invalid encrypted credential record"))
    }

    pub(crate) fn open_bytes(
        &self,
        aad: &[u8],
        ciphertext: &str,
    ) -> Result<bytes::Bytes, RepositoryError> {
        let mut buffer = Zeroizing::new(
            STANDARD
                .decode(ciphertext)
                .map_err(|_| corrupt("invalid credential ciphertext"))?,
        );
        let length = nazo_crypto::aead::decrypt_nonce_prefixed(&self.key, aad, &mut buffer)
            .map_err(|_| corrupt("credential authentication failed"))?
            .len();
        // Move the authenticated allocation into Bytes; slice removes wire framing
        // without copying the response payload.
        Ok(bytes::Bytes::from(std::mem::take(&mut *buffer)).slice(12..12 + length))
    }
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<String, RepositoryError> {
    let nonce: [u8; 12] = rand::random();
    let ciphertext = nazo_crypto::aead::encrypt_prefixed(key, &nonce, aad, plaintext, &nonce)
        .map_err(|_| corrupt("credential encryption failed"))?;
    Ok(STANDARD.encode(ciphertext))
}

#[cfg(test)]
#[path = "../../tests/unit/digital_credentials.rs"]
mod tests;
