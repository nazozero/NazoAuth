//! Durable OpenID4VC state. Protocol decisions and credential crypto stay in
//! the shared services; these adapters own tenant scoping, AEAD and SQL fences.

mod datasets;
mod issuance;
mod presentation;
mod trust;

use crate::{D1Provider, db::DbError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::Rng as _;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) use datasets::DatasetStore;
pub(super) use issuance::IssuerStore;
pub(super) use presentation::PresentationStore;

#[derive(Clone)]
struct EncryptedStore {
    provider: D1Provider,
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl EncryptedStore {
    fn new(provider: D1Provider, key: [u8; 32]) -> Self {
        Self {
            provider,
            key: Arc::new(Zeroizing::new(key)),
        }
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<String, DbError> {
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        nazo_crypto::aead::encrypt_prefixed(&self.key, &nonce, aad, plaintext, &nonce)
            .map(|value| STANDARD.encode(value))
            .map_err(|_| DbError::Unavailable)
    }

    fn open(&self, aad: &[u8], encoded: &str) -> Result<Zeroizing<Vec<u8>>, DbError> {
        let mut bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| DbError::CorruptData)?);
        let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(&self.key, aad, &mut bytes)
            .map_err(|_| DbError::CorruptData)?;
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

fn encode(value: &impl Serialize) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|_| DbError::CorruptData)
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, DbError> {
    serde_json::from_str(value).map_err(|_| DbError::CorruptData)
}

fn timestamp(value: i64) -> Result<jiff::Timestamp, DbError> {
    jiff::Timestamp::from_microsecond(value).map_err(|_| DbError::CorruptData)
}

fn presentation_aad(domain: &[u8], tenant: Uuid, transaction: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    for value in [domain, tenant.as_bytes(), transaction.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
        aad.extend_from_slice(value);
    }
    aad
}

fn dataset_aad(tenant: Uuid, subject: Uuid, configuration: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40 + configuration.len());
    aad.extend_from_slice(tenant.as_bytes());
    aad.extend_from_slice(subject.as_bytes());
    aad.extend_from_slice(&(configuration.len() as u64).to_be_bytes());
    aad.extend_from_slice(configuration.as_bytes());
    aad
}
