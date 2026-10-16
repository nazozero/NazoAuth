/// A typed temporary failure at this persistence owner; Context preserves it.
#[derive(Debug)]
pub struct SigningKeyRepositoryUnavailable(pub anyhow::Error);

impl std::fmt::Display for SigningKeyRepositoryUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("signing-key persistence is temporarily unavailable")
    }
}

impl std::error::Error for SigningKeyRepositoryUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

use std::{fmt, future::Future, pin::Pin};

use uuid::Uuid;

pub type SigningKeyRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// One tenant-bound, authoritative keyset record. The public projection and
/// encrypted private payload are one generation: callers must authenticate
/// both with [`SigningKeyWrappingKeyRing::open_generation`] before use.
#[derive(Clone, Debug)]
pub struct PersistedSigningKeyset {
    pub revision: i64,
    pub public_metadata: serde_json::Value,
    /// Twelve-byte nonce followed by AES-GCM ciphertext and tag.
    pub encrypted_private_material: Vec<u8>,
    pub wrapping_key_id: String,
}

#[derive(Clone, Debug)]
pub enum SigningKeysetCreateResult {
    Created(PersistedSigningKeyset),
    Existing(PersistedSigningKeyset),
}

#[derive(Clone, Debug)]
pub enum SigningKeysetCompareAndSwapResult {
    Applied(PersistedSigningKeyset),
    Conflict(PersistedSigningKeyset),
}

/// Persistence boundary for the one tenant selected by its adapter.
///
/// The adapter owns SQL and atomicity. Key-management owns key generation,
/// metadata validation, encryption, and lifecycle transitions.
pub trait SigningKeyRepository: Send + Sync {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>>;

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult>;

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult>;
}

/// Deployment-provided wrapping material for persisted signing-key private
/// material. The current key seals new generations; the previous key exists
/// only to read a generation sealed before a wrapping-key rotation.
#[derive(Clone)]
pub struct SigningKeyWrappingKeyRing {
    current: WrappingKey,
    previous: Option<WrappingKey>,
}

#[derive(Clone)]
struct WrappingKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyWrappingKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl fmt::Display for SigningKeyWrappingKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "signing-key encryption key id must not be empty",
            Self::IdTooLong => "signing-key encryption key id must be at most 128 bytes",
            Self::DuplicateId => "signing-key encryption current and previous ids must differ",
        })
    }
}

impl std::error::Error for SigningKeyWrappingKeyError {}

impl SigningKeyWrappingKeyRing {
    pub fn new(
        current_id: impl Into<String>,
        current_key: [u8; 32],
        previous: Option<(String, [u8; 32])>,
    ) -> Result<Self, SigningKeyWrappingKeyError> {
        let current = WrappingKey::new(current_id.into(), current_key)?;
        let previous = previous
            .map(|(id, key)| WrappingKey::new(id, key))
            .transpose()?;
        if previous.as_ref().is_some_and(|key| key.id == current.id) {
            return Err(SigningKeyWrappingKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current_id(&self) -> &str {
        &self.current.id
    }

    pub fn seal_generation(
        &self,
        tenant_id: Uuid,
        revision: i64,
        public_metadata: &serde_json::Value,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let nonce: [u8; 12] = rand::random();
        let ciphertext = nazo_crypto::aead::encrypt(
            &self.current.key,
            &nonce,
            &generation_associated_data(tenant_id, revision, public_metadata)?,
            plaintext,
        )?;
        let mut bytes = Vec::with_capacity(nonce.len() + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(bytes)
    }

    pub fn open_generation(
        &self,
        tenant_id: Uuid,
        record: &PersistedSigningKeyset,
    ) -> anyhow::Result<Vec<u8>> {
        let key = self
            .key_for(&record.wrapping_key_id)
            .ok_or_else(|| anyhow::anyhow!("signing-key wrapping key is unavailable"))?;
        let (nonce, ciphertext) = record
            .encrypted_private_material
            .split_at_checked(12)
            .ok_or_else(|| anyhow::anyhow!("signing-key encrypted material is malformed"))?;
        Ok(nazo_crypto::aead::decrypt(
            key,
            nonce,
            &generation_associated_data(tenant_id, record.revision, &record.public_metadata)?,
            ciphertext,
        )?)
    }

    fn key_for(&self, id: &str) -> Option<&[u8; 32]> {
        if self.current.id == id {
            Some(&self.current.key)
        } else {
            self.previous
                .as_ref()
                .filter(|key| key.id == id)
                .map(|key| &key.key)
        }
    }
}

impl WrappingKey {
    fn new(id: String, key: [u8; 32]) -> Result<Self, SigningKeyWrappingKeyError> {
        if id.trim().is_empty() {
            return Err(SigningKeyWrappingKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(SigningKeyWrappingKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }
}

fn generation_associated_data(
    tenant_id: Uuid,
    revision: i64,
    metadata: &serde_json::Value,
) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest as _, Sha256};

    let mut aad = b"nazoauth/signing-keyset/v1\0".to_vec();
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&Sha256::digest(serde_json::to_vec(metadata)?));
    Ok(aad)
}
