use crate::{
    Principal, ProfilePatch, PublicAccount, SubjectClaims, TenantContext, TenantId, UserId,
};

use super::common::{PasswordHashInput, RepositoryFuture};

#[derive(Clone, Debug)]
pub struct NewUser {
    pub tenant: TenantContext,
    pub username: String,
    pub email: String,
    pub password_hash: PasswordHashInput,
    pub email_verified: bool,
}

#[derive(Clone, Debug)]
pub struct AdminUserUpdate {
    pub role: Option<String>,
    pub admin_level: Option<i32>,
    pub active: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct UserPage {
    pub total: i64,
    pub users: Vec<crate::PublicAccount>,
}

/// Persistence boundary for administrative account listing and atomic policy updates.
///
/// The update operation intentionally remains a single repository call: the
/// implementation must load the actor and target, evaluate the authorization
/// policy, and persist the result in one transaction.
pub trait AdminUserRepositoryPort: Send + Sync {
    fn page(&self, tenant_id: TenantId, limit: i64, offset: i64) -> RepositoryFuture<'_, UserPage>;

    /// The same hierarchy mutation owner also appends canonical Required
    /// evidence, binding the full current actor/target context through ACK.
    /// Preserve authorize_admin_update as the only hierarchy policy authority.
    fn update_authorized_with_required_audit(
        &self,
        tenant: TenantContext,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, crate::AdminUserUpdateOutcome>;

    /// Explicit system-boundary operation for managing an administrator in a
    /// different tenant. Implementations must re-check both tenant bindings
    /// and the actor's system-admin level in the same transaction.
    #[allow(clippy::too_many_arguments)]
    fn set_tenant_admin_authorized(
        &self,
        control_tenant_id: TenantId,
        actor_id: UserId,
        target_tenant_id: TenantId,
        target_id: UserId,
        admin_level: i32,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, crate::AdminUserUpdateOutcome>;
}

pub trait UserRepositoryPort: Send + Sync {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>>;

    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>>;
}

pub trait ProfileRepositoryPort: Send + Sync {
    fn update_profile<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfilePatch,
    ) -> RepositoryFuture<'a, PublicAccount>;
}
