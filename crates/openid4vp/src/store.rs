use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{PresentationResult, PresentationTransaction};

pub type PresentationStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub struct StoredPresentation {
    pub transaction: PresentationTransaction,
    pub completed: Option<PresentationResult>,
}

pub trait PresentationStorePort: Send + Sync {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>>;

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>;

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
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationStoreError {
    #[error("presentation store is unavailable")]
    Unavailable,
    #[error("presentation state transition is invalid")]
    InvalidTransition,
}
