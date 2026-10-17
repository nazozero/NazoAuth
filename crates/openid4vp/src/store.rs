use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{PresentationResult, PresentationTransaction};

pub type PresentationStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Binding generated from an admitted, normalized create request.
/// The caller owns input validation and canonicalization; stores compare the
/// binding with the persisted request and enforce atomic create uniqueness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationCreateIdempotency<'a> {
    pub request_jti: &'a str,
    pub request_sha256: &'a str,
    pub canonical_request: &'a str,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PresentationCreateOutcome {
    Created,
    Existing(Box<PresentationTransaction>),
}

pub trait PresentationStorePort: Send + Sync {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<PresentationCreateOutcome, PresentationStoreError>>;

    fn find_by_create_request<'a>(
        &'a self,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>;

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>;

    /// Update only the nonce on an active transaction already read by the caller.
    /// Other request fields are immutable; false means it is no longer available.
    fn bind_wallet_nonce<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: &'a str,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>>;

    /// Accept exactly one completion under the current tenant, state and trust
    /// policy. `now` is the caller's reported verification time; it cannot stand
    /// in for a fresh deadline check after connection or record-lock waits.
    /// The store owns the deadline check at its locked mutation acceptance point.
    /// An expired completion returns false without storing a result or erasing
    /// the response key. Keep the recorded result time and wire shape unchanged.
    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>>;

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationResult>, PresentationStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationStoreError {
    #[error("presentation store is unavailable")]
    Unavailable,
    #[error("presentation create idempotency key conflicts with another request")]
    IdempotencyConflict,
    #[error("presentation state transition is invalid")]
    InvalidTransition,
}
