use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_digital_credentials::CredentialFormat;
use serde_json::Value;
use uuid::Uuid;

use crate::{CredentialIdentifier, CredentialOfferGrants, NotificationEvent};

pub type CredentialStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AuthorizationOfferPort: Send + Sync {
    fn consume_authorization_offer<'a>(
        &'a self,
        issuer_state_hash: &'a str,
        subject_id: Uuid,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceRecord {
    pub nonce_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAuthorization {
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: String,
    pub configuration_ids: Vec<String>,
    pub credential_identifiers: Vec<CredentialIdentifier>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCredentialOffer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Option<Uuid>,
    pub credential_configuration_ids: Vec<String>,
    pub grants: CredentialOfferGrants,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAccess {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: String,
    pub configuration_ids: Vec<String>,
    pub credential_identifiers: Vec<CredentialIdentifier>,
    pub dpop_jkt: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeferredCredential {
    pub id: Uuid,
    pub transaction_hash: String,
    pub access: CredentialAccess,
    pub configuration_id: String,
    pub format: CredentialFormat,
    pub holder_bindings: Vec<Value>,
    pub payload_ciphertext: Vec<u8>,
    pub ready_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceNotification {
    pub notification_id: String,
    pub token_id: Uuid,
    pub event: NotificationEvent,
    pub description: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationHandle {
    pub notification_id: String,
    pub token_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

pub trait CredentialStorePort: Send + Sync {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn offer<'a>(
        &'a self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>;

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>;

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>>;

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>>;

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialStoreError {
    #[error("credential store is unavailable")]
    Unavailable,
    #[error("credential store rejected an invalid transition")]
    InvalidTransition,
}
