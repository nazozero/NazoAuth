use chrono::{DateTime, Utc};
use passkey_auth::PasskeyCredential as WebauthnCredential;
use uuid::Uuid;

use crate::{PublicAccount, TenantId, UserId};

use super::common::RepositoryFuture;

#[derive(Clone, Debug)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub credential: WebauthnCredential,
    pub label: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Display metadata scoped to one tenant and user; contains no credential payload.
#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyCredentialSummary {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub credential_id: String,
    pub label: String,
    pub sign_count: i64,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PasskeyCredential> for PasskeyCredentialSummary {
    fn from(row: PasskeyCredential) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            credential_id: row.credential.id.to_b64url(),
            label: row.label,
            sign_count: i64::from(row.credential.counter),
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub trait PasskeyAccountRepositoryPort: Send + Sync {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

pub trait PasskeyRepositoryPort: Send + Sync {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredential>>;

    fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredentialSummary>> {
        Box::pin(async move {
            self.list(tenant_id, user_id).await.map(|rows| {
                rows.into_iter()
                    .map(PasskeyCredentialSummary::from)
                    .collect()
            })
        })
    }

    fn by_credential_id<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
    ) -> RepositoryFuture<'a, Option<PasskeyCredential>>;

    fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential: WebauthnCredential,
        label: String,
    ) -> RepositoryFuture<'_, PasskeyCredential>;

    fn update_counter<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
        expected_sign_count: u32,
        new_sign_count: u32,
    ) -> RepositoryFuture<'a, ()>;

    fn delete(&self, tenant_id: TenantId, user_id: UserId, id: Uuid) -> RepositoryFuture<'_, bool>;
}

pub trait PasskeyCeremonyPort: Send + Sync {
    fn store_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyRegistration,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyRegistration>>;

    fn store_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyAuthentication,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyAuthentication>>;
}

impl<T> PasskeyCeremonyPort for std::sync::Arc<T>
where
    T: PasskeyCeremonyPort + ?Sized,
{
    fn store_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyRegistration,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref()
            .store_registration(ceremony_id, ceremony, ttl_seconds)
    }

    fn take_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyRegistration>> {
        self.as_ref().take_registration(ceremony_id)
    }

    fn store_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyAuthentication,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref()
            .store_authentication(ceremony_id, ceremony, ttl_seconds)
    }

    fn take_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyAuthentication>> {
        self.as_ref().take_authentication(ceremony_id)
    }
}

pub trait PasskeyAuditPort: Send + Sync {
    /// Best-effort telemetry: fire-and-forget, never awaited.
    fn record(&self, event: crate::passkey::PasskeyAuditEvent);
    /// Durable Required evidence: the caller awaits the append and fails
    /// closed on error, so a required fact is never silently dropped.
    fn record_required<'a>(
        &'a self,
        event: crate::passkey::PasskeyAuditEvent,
    ) -> RepositoryFuture<'a, ()>;
}

impl<T: PasskeyAuditPort + ?Sized> PasskeyAuditPort for std::sync::Arc<T> {
    fn record(&self, event: crate::passkey::PasskeyAuditEvent) {
        self.as_ref().record(event);
    }

    fn record_required<'a>(
        &'a self,
        event: crate::passkey::PasskeyAuditEvent,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref().record_required(event)
    }
}
