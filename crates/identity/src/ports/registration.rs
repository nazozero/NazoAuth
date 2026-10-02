use crate::{PasswordHash, PublicAccount};

use super::NewUser;

use super::common::{PasswordHashInput, RepositoryFuture};

pub trait RegistrationAccountRepositoryPort: Send + Sync {
    fn account_by_email<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn create_user(&self, user: NewUser) -> RepositoryFuture<'_, PublicAccount>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailVerificationRecord {
    pub password_hash: PasswordHash,
    pub opaque_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailVerificationConsume {
    Consumed,
    MissingOrChanged,
}

/// Tenant-owned email verification state.
///
/// Callers must pass the tenant selected for the registration flow to every
/// operation. Implementations must include it in the authoritative state key
/// and must not fall back to deployment-global state. Each send attempt owns
/// its reservations and code through one nonce. Cleanup atomically compares
/// that owner and must never delete state belonging to a later attempt.
pub trait EmailVerificationStorePort: Send + Sync {
    fn reserve_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        subject: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn reserve_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn store_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
        password_hash: PasswordHashInput,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn load_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>>;

    fn consume_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume>;

    fn delete_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()>;
    fn release_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()>;
    fn release_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        subject: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()>;
}

impl<T> EmailVerificationStorePort for std::sync::Arc<T>
where
    T: EmailVerificationStorePort + ?Sized,
{
    fn reserve_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        subject: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        self.as_ref()
            .reserve_peer_send(tenant_id, subject, owner, ttl_seconds)
    }

    fn reserve_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        self.as_ref()
            .reserve_email_send(tenant_id, email, owner, ttl_seconds)
    }

    fn store_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
        password_hash: PasswordHashInput,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref()
            .store_code(tenant_id, email, owner, password_hash, ttl_seconds)
    }

    fn load_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>> {
        self.as_ref().load_code(tenant_id, email)
    }

    fn consume_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume> {
        self.as_ref().consume_code(tenant_id, email, expected)
    }

    fn delete_code<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref().delete_code(tenant_id, email, owner)
    }

    fn release_email_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref().release_email_send(tenant_id, email, owner)
    }

    fn release_peer_send<'a>(
        &'a self,
        tenant_id: crate::TenantId,
        subject: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref().release_peer_send(tenant_id, subject, owner)
    }
}

pub trait SecretHashPort: Send + Sync {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput>;

    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool>;
}

pub trait VerificationEmailDeliveryPort: Send + Sync {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;
}

impl<T: SecretHashPort + ?Sized> SecretHashPort for std::sync::Arc<T> {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput> {
        self.as_ref().hash_secret(secret)
    }

    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool> {
        self.as_ref().verify_secret(secret, password_hash)
    }
}

impl<T: VerificationEmailDeliveryPort + ?Sized> VerificationEmailDeliveryPort
    for std::sync::Arc<T>
{
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref()
            .deliver(normalized_email, code, code_ttl_seconds)
    }
}
