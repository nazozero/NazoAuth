use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AccessRequest, NewAccessRequest, TenantId, UserId};

use super::common::{RepositoryError, RepositoryFuture};

pub trait GrantSummaryRepositoryPort: Send + Sync {
    fn authorized_client_count(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, i64>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedApplication {
    pub client_id: String,
    pub client_name: String,
    pub last_scopes: Value,
    pub last_authorized_at: DateTime<Utc>,
    pub authorization_count: i32,
}

pub trait AuthorizedApplicationRepositoryPort: Send + Sync {
    fn applications_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>>;
}

pub trait AccessRequestRepositoryPort: Send + Sync {
    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<AccessRequest>>;

    fn create(&self, request: NewAccessRequest) -> RepositoryFuture<'_, AccessRequest>;

    /// One-time consumption also requires the exact accepting owner's
    /// canonical Required outcome, in addition to current client linkage.
    /// Unavailable preserves the delivery for a later verified retry.
    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        _request_id: Uuid,
        _approved_client_id: Uuid,
        _client_id: &'a str,
        _secret_binding: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Err(RepositoryError::Unavailable) })
    }

    fn approved_delivery_matches<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
        approved_client_id: Uuid,
        client_id: &'a str,
        secret_binding: Option<&'a str>,
    ) -> RepositoryFuture<'a, bool>;
}

/// One immutable producer attempt and its original disclosure deadline.
#[derive(Clone, PartialEq)]
pub struct DeliveryStage {
    pub attempt_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub secret_binding: Option<String>,
    pub value: Value,
}

/// A snapshot whose opaque version must be compared by every mutation.
#[derive(Clone, PartialEq)]
pub struct DeliveryRecord {
    pub value: Value,
    pub opaque_version: String,
    pub attempt_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub secret_binding: Option<String>,
}

#[derive(Clone, PartialEq)]
pub enum DeliveryStageResult {
    Created(DeliveryRecord),
    Existing,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryPublish {
    Published,
    MissingOrChanged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeliveryConsume {
    Consumed(Value),
    MissingOrChanged,
}

pub trait DeliveryStorePort: Send + Sync {
    /// Create only if absent; an existing attempt is never replaced.
    fn stage<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult>;

    /// Publish only this exact, still-live unpublished stage. Preserve expiry;
    /// Missing, changed, consumed and expired records must never be recreated.
    fn publish<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        approved_client_id: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish>;

    fn load<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>>;

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>>;

    /// Retire the exact snapshot only. Producers may retire only their own
    /// unpublished stage after a known non-commit; unknown outcomes retain it.
    fn retire<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool>;

    fn consume<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume>;
}

impl<T> DeliveryStorePort for Arc<T>
where
    T: DeliveryStorePort + ?Sized,
{
    fn stage<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult> {
        self.as_ref().stage(user_id, token, stage)
    }

    fn publish<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        approved_client_id: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish> {
        self.as_ref()
            .publish(user_id, token, expected, approved_client_id)
    }

    fn load<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        self.as_ref().load(user_id, token)
    }

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        self.as_ref().load_many(lookups)
    }

    fn retire<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool> {
        self.as_ref().retire(user_id, token, expected)
    }

    fn consume<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        self.as_ref().consume(user_id, token, expected)
    }
}
