use crate::ports::AdminUserUpdate;
use crate::{Principal, TenantId, UserRole};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminPolicyError {
    ActorNotAuthorized,
    CrossTenant,
    SelfElevation,
    SelfDemotionOrDisable,
    TargetAtOrAboveActor,
    GrantAtOrAboveActor,
    InvalidRoleLevel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAdminUserUpdate {
    pub role: String,
    pub admin_level: i32,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminUserUpdateOutcome {
    Updated(Box<crate::PublicAccount>),
    TargetNotFound,
    Denied(AdminPolicyError),
}

pub fn authorize_admin_update(
    actor: &Principal,
    target: &Principal,
    update: &AdminUserUpdate,
) -> Result<ResolvedAdminUserUpdate, AdminPolicyError> {
    if actor.tenant.tenant_id != target.tenant.tenant_id {
        return Err(AdminPolicyError::CrossTenant);
    }
    let actor_level = actor
        .active
        .then(|| actor.admin_level())
        .flatten()
        .filter(|level| *level > 0)
        .and_then(|level| i32::try_from(level).ok())
        .ok_or(AdminPolicyError::ActorNotAuthorized)?;
    let target_level = target
        .admin_level()
        .and_then(|level| i32::try_from(level).ok())
        .unwrap_or(0);
    let current_role = match target.role {
        UserRole::User => "user",
        UserRole::Admin { .. } => "admin",
    };
    let role = update.role.as_deref().unwrap_or(current_role);
    let admin_level = update.admin_level.unwrap_or(target_level);
    let active = update.active.unwrap_or(target.active);
    if !matches!((role, admin_level), ("user", 0) | ("admin", 1..)) {
        return Err(AdminPolicyError::InvalidRoleLevel);
    }

    if actor.user_id == target.user_id {
        if admin_level > actor_level {
            return Err(AdminPolicyError::SelfElevation);
        }
        if role != "admin" || admin_level < actor_level || !active {
            return Err(AdminPolicyError::SelfDemotionOrDisable);
        }
    } else {
        if target_level >= actor_level {
            return Err(AdminPolicyError::TargetAtOrAboveActor);
        }
        if admin_level >= actor_level {
            return Err(AdminPolicyError::GrantAtOrAboveActor);
        }
    }

    Ok(ResolvedAdminUserUpdate {
        role: role.to_owned(),
        admin_level,
        active,
    })
}

/// Authorize the explicit control-plane operation without applying the ordinary
/// same-tenant hierarchy policy. Persistence must bind both principals through
/// the mutation's commit acknowledgement.
pub fn authorize_tenant_admin_update(
    actor: &Principal,
    control_tenant: TenantId,
    target_tenant: TenantId,
    admin_level: i32,
) -> Result<(), AdminPolicyError> {
    if admin_level < 0 || control_tenant == target_tenant {
        return Err(AdminPolicyError::InvalidRoleLevel);
    }
    if actor.tenant.tenant_id != control_tenant
        || !actor.active
        || !actor.admin_level().is_some_and(|level| level >= 2)
    {
        return Err(AdminPolicyError::ActorNotAuthorized);
    }
    Ok(())
}
