use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_digital_credentials::CredentialFormat;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{CredentialIdentifier, CredentialOfferGrants, NotificationEvent};

pub type CredentialStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AuthorizationOfferPort: Send + Sync {
    fn resolve_authorization_offer<'a>(
        &'a self,
        tenant_id: Uuid,
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

/// Provenance retained by the credential authorization owner, never inferred
/// from a placeholder client identifier. Legacy data has no such evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProofOrigin {
    RegisteredClient,
    AnonymousPreAuthorized,
    #[default]
    LegacyUnspecified,
}

impl CredentialProofOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegisteredClient => "registered_client",
            Self::AnonymousPreAuthorized => "anonymous_pre_authorized",
            Self::LegacyUnspecified => "legacy_unspecified",
        }
    }
}

/// The exact selector authorized when an issuance intent was created.
/// None on retained records means legacy token-bound ownership, not a guessed selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialSelection {
    pub configuration_id: String,
    pub credential_identifier: Option<CredentialIdentifier>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAccess {
    pub authorization_id: Option<Uuid>,
    pub mtls_x5t_s256: Option<String>,
    pub proof_origin: CredentialProofOrigin,
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub client_id: String,
    pub configuration_ids: Vec<String>,
    pub credential_identifiers: Vec<CredentialIdentifier>,
    pub dpop_jkt: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl CredentialAccess {
    /// A current token may continue only its original authorization and exact intent.
    /// Missing retained selector or lineage evidence preserves token-bound ownership.
    pub fn continues_access(
        &self,
        original: &Self,
        selection: Option<&CredentialSelection>,
        now: DateTime<Utc>,
    ) -> bool {
        let same_token = self.token_id == original.token_id;
        let same_authorization =
            self.authorization_id.is_some() && self.authorization_id == original.authorization_id;
        self.expires_at > now
            && self.tenant_id == original.tenant_id
            && self.subject_id == original.subject_id
            && self.client_id == original.client_id
            && self.proof_origin == original.proof_origin
            && self.dpop_jkt == original.dpop_jkt
            && self.mtls_x5t_s256 == original.mtls_x5t_s256
            && (same_token || same_authorization)
            && match selection {
                Some(selection) => self.authorizes_selection(selection),
                None => same_token,
            }
    }

    pub fn authorizes_selection(&self, selection: &CredentialSelection) -> bool {
        self.configuration_ids.contains(&selection.configuration_id)
            && match selection.credential_identifier.as_ref() {
                Some(identifier) => self.credential_identifiers.contains(identifier),
                None => self.credential_identifiers.is_empty(),
            }
    }

    pub fn continuation_expires_at(&self, intent_expires_at: DateTime<Utc>) -> DateTime<Utc> {
        if self.authorization_id.is_some() {
            intent_expires_at
        } else {
            self.expires_at.min(intent_expires_at)
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeferredCredential {
    pub selection: Option<CredentialSelection>,
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

/// A deferred transaction that is leased to one issuance attempt.
///
/// The lease is deliberately separate from `consumed_at`: signing and response
/// persistence can fail after a transaction has become ready, in which case a
/// later request must be able to retry the same transaction without allowing
/// two concurrent issuers to sign it.
#[derive(Clone, Debug, PartialEq)]
pub struct DeferredCredentialClaim {
    pub credential: DeferredCredential,
    pub claim_id: String,
}

/// A single owner-classified deferred claim attempt. Pending and Busy retain
/// the same live transaction and never confer signing authority.
#[derive(Clone, Debug, PartialEq)]
pub enum DeferredClaimOutcome {
    Claimed(Box<DeferredCredentialClaim>),
    Pending { retry_at: DateTime<Utc> },
    Busy { retry_at: DateTime<Utc> },
    Invalid,
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
    pub selection: Option<CredentialSelection>,
    pub notification_id: String,
    pub token_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialResponseEncoding {
    Json,
    Jwt,
}

/// The exact wire response committed with an issuance state transition. The
/// repository encrypts `body` at rest; the digest and issuance id prevent a
/// different request from retrieving a previously committed response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCredentialResponse {
    pub selection: Option<CredentialSelection>,
    pub issuance_id: Uuid,
    pub token_id: Uuid,
    pub request_digest: String,
    pub body: Vec<u8>,
    pub encoding: CredentialResponseEncoding,
    pub status: u16,
    pub dpop_nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
}

pub trait CredentialStorePort: Send + Sync {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    /// Persist a pre-authorized access grant. When `registered_client_id` is
    /// present the implementation must re-verify that registered client is
    /// still active under a `FOR SHARE` lock in the same transaction as the
    /// grant write, so a client deactivation cannot slip between the earlier
    /// authentication check and the grant becoming usable. Anonymous grants
    /// carry no registered client and skip the lock entirely.
    fn persist_pre_authorized_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>;

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>;

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    /// Lease a nonce for one issuance attempt. A lease may be reclaimed after
    /// its expiry; finalization is the only transition that makes the nonce
    /// permanently single-use.
    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Atomically persist the notification handle and finalize the nonce.
    /// Implementations must own this transition in one transaction; composing
    /// the two lower-level methods is not safe because a process failure could
    /// leave a notification without a consumed nonce (or vice versa).
    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>;

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>>;

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    /// Persist a deferred transaction and finalize its proof nonce as one
    /// state transition. Implementations must own this transition in one
    /// transaction rather than composing the lower-level operations.
    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>>;

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<DeferredClaimOutcome, CredentialStoreError>>;

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Atomically persist the notification handle and finalize a deferred
    /// transaction. The store owns this transition so a retry can never
    /// observe a notification without the corresponding consumed transaction.
    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>>;

    /// Accept one retained terminal event. An identical event/description retry
    /// succeeds without replacing the first occurrence time; conflicting, expired
    /// or wrong-owner notifications are rejected atomically by the store owner.
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
    #[error("credential client is inactive")]
    ClientInactive,
}
