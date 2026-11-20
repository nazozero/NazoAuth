//! Administrative policy evaluation with transaction-bound authority snapshots.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow, encode},
};
use nazo_identity::{
    AdminPolicyError, AdminUserUpdateOutcome, Principal, ResolvedAdminUserUpdate, TenantContext,
    TenantId, UserId, UserRole, authorize_admin_update, authorize_tenant_admin_update,
    ports::{
        AdminUserRepositoryPort, AdminUserUpdate, RepositoryError, RepositoryFuture, UserPage,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
struct Authority {
    tenant_id: TenantId,
    id: UserId,
    principal: String,
    epoch: i64,
    active: i64,
}

impl Authority {
    fn principal(&self) -> Result<Principal, DbError> {
        let mut principal: Principal =
            serde_json::from_str(&self.principal).map_err(|_| DbError::CorruptData)?;
        if principal.tenant.tenant_id != self.tenant_id || principal.user_id != self.id {
            return Err(DbError::CorruptData);
        }
        principal.authorization_epoch = self.epoch;
        principal.active = self.active != 0;
        Ok(principal)
    }
}

enum Change {
    Local(TenantContext, AdminUserUpdate),
    TenantLevel(i32),
}

fn denial(reason: AdminPolicyError) -> &'static str {
    match reason {
        AdminPolicyError::ActorNotAuthorized => "actor_not_authorized",
        AdminPolicyError::CrossTenant => "cross_tenant",
        AdminPolicyError::SelfElevation => "self_elevation",
        AdminPolicyError::SelfDemotionOrDisable => "self_demotion_or_disable",
        AdminPolicyError::TargetAtOrAboveActor => "target_at_or_above_actor",
        AdminPolicyError::GrantAtOrAboveActor => "grant_at_or_above_actor",
        AdminPolicyError::InvalidRoleLevel => "invalid_role_level",
    }
}

impl D1Provider {
    async fn update_admin_account(
        &self,
        actor_tenant: TenantId,
        actor_id: UserId,
        target_tenant: TenantId,
        target_id: UserId,
        change: Change,
        source: &str,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        self.require_tenant(actor_tenant.as_uuid())?;
        // D1 has no application callback inside a transaction. Read policy
        // inputs, evaluate the shared policy, then admit the whole batch only if
        // both persisted snapshots still match. Retry any concurrent change.
        for _ in 0..8 {
            let rows=self.database.query::<Authority>(
                "SELECT tenant_id,id,principal,epoch,active FROM nazo_users WHERE (tenant_id=?1 AND id=?2) OR (tenant_id=?3 AND id=?4)",
                vec![json!(actor_tenant),json!(actor_id),json!(target_tenant),json!(target_id)],
            ).await?;
            let actor = rows
                .iter()
                .find(|row| row.tenant_id == actor_tenant && row.id == actor_id);
            let target = rows
                .iter()
                .find(|row| row.tenant_id == target_tenant && row.id == target_id);
            let actor_principal = actor.map(Authority::principal).transpose()?;
            let target_principal = target.map(Authority::principal).transpose()?;
            let decision: Result<Option<ResolvedAdminUserUpdate>, AdminPolicyError> = match &change
            {
                Change::Local(tenant, update) => {
                    match (
                        actor_principal
                            .as_ref()
                            .filter(|actor| actor.tenant == *tenant),
                        target_principal.as_ref(),
                    ) {
                        (None, _) => Err(AdminPolicyError::ActorNotAuthorized),
                        (Some(_), None) => Ok(None),
                        (Some(_), Some(target)) if target.tenant != *tenant => {
                            Err(AdminPolicyError::CrossTenant)
                        }
                        (Some(actor), Some(target)) => {
                            authorize_admin_update(actor, target, update).map(Some)
                        }
                    }
                }
                Change::TenantLevel(level) => actor_principal
                    .as_ref()
                    .ok_or(AdminPolicyError::ActorNotAuthorized)
                    .and_then(|actor| {
                        authorize_tenant_admin_update(actor, actor_tenant, target_tenant, *level)
                    })
                    .map(|()| {
                        target_principal
                            .as_ref()
                            .map(|target| ResolvedAdminUserUpdate {
                                role: if *level == 0 { "user" } else { "admin" }.into(),
                                admin_level: *level,
                                active: target.active,
                            })
                    }),
            };
            let success = matches!(&decision, Ok(Some(_)));
            let reason = match &decision {
                Ok(Some(_)) => "admin_updated",
                Ok(None) => "target_not_found",
                Err(reason) => denial(*reason),
            };
            let event_type = if matches!(change, Change::TenantLevel(_)) {
                "system_tenant_admin_updated"
            } else if success {
                "admin_user_updated"
            } else {
                "admin_user_update_denied"
            };
            let resolved = decision.as_ref().ok().and_then(Option::as_ref);
            let payload = json!({
                "schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"administration",
                "tenant_id":target_tenant,"control_tenant_id":actor_tenant,
                "realm_id":target_principal.as_ref().map(|p|p.tenant.realm_id),"organization_id":target_principal.as_ref().map(|p|p.tenant.organization_id),
                "admin_user_id":actor_id,"actor_user_id":actor_id,"actor_tenant_id":actor_principal.as_ref().map(|p|p.tenant.tenant_id),
                "user_id":target_id,"target_tenant_id":target_tenant,"target_user_id":target_id,
                "role":resolved.map(|r|r.role.as_str()),"admin_level":resolved.map(|r|r.admin_level),
                "is_active":resolved.map(|r|r.active),"outcome":if success{"success"}else{"denied"},
                "reason":reason,"source_ip_hash":source,
            });
            let event = Uuid::new_v4();
            let mut statements=vec![Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT ?1,?2,?3,'administration',{NOW},?4
                 WHERE ((?7 IS NULL AND NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?5 AND id=?6))
                   OR (?7 IS NOT NULL AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?5 AND id=?6 AND principal=?7 AND epoch=?8 AND active=?9)))
                   AND ((?12 IS NULL AND NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?10 AND id=?11))
                   OR (?12 IS NOT NULL AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?10 AND id=?11 AND principal=?12 AND epoch=?13 AND active=?14)))
                 UNION ALL SELECT ?1,?2,?3,'administration',{NOW},?4 WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE event_id=?2) RETURNING event_id"),
                vec![json!(target_tenant),json!(event),json!(event_type),json!(encode(&payload)?),json!(actor_tenant),json!(actor_id),
                    json!(actor.map(|r|&r.principal)),json!(actor.map(|r|r.epoch)),json!(actor.map(|r|r.active)),
                    json!(target_tenant),json!(target_id),json!(target.map(|r|&r.principal)),json!(target.map(|r|r.epoch)),json!(target.map(|r|r.active))])];
            let admitted = "EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?3)";
            if let Some(resolved) = resolved {
                let mut next = target_principal.clone().ok_or(DbError::CorruptData)?;
                let deactivate = next.active && !resolved.active;
                next.role = if resolved.admin_level == 0 {
                    UserRole::User
                } else {
                    UserRole::Admin {
                        level: u32::try_from(resolved.admin_level)
                            .map_err(|_| DbError::CorruptData)?,
                    }
                };
                next.active = resolved.active;
                next.authorization_epoch += i64::from(deactivate);
                let noop = matches!(&change,Change::Local(_,update) if update.role.is_none()&&update.admin_level.is_none()&&update.active.is_none());
                if !noop {
                    statements.push(Statement::new(format!(
                        "UPDATE nazo_users SET principal=?4,active=?5,epoch=?6,updated_at={NOW},claims=json_set(claims,'$.updated_at',unixepoch())
                         WHERE tenant_id=?1 AND id=?2 AND {admitted}
                           AND (?5=0 OR NOT EXISTS(SELECT 1 FROM nazo_deleted_users WHERE tenant_id=?1 AND user_id=?2)) RETURNING id"),
                        vec![json!(target_tenant),json!(target_id),json!(event),json!(encode(&next)?),json!(next.active),json!(next.authorization_epoch)]));
                    // A deleted account cannot be reactivated. Force rollback if
                    // an otherwise admitted mutation could not update its row.
                    statements.push(Statement::new(format!(
                        "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                         SELECT ?1,?3,'duplicate','administration',{NOW},'{{}}' WHERE {admitted} AND changes()!=1"),
                        vec![json!(target_tenant),json!(target_id),json!(event)]));
                }
                if deactivate {
                    statements.push(Statement::new(format!("UPDATE nazo_refresh_families SET revoked_at={NOW} WHERE tenant_id=?1 AND user_id=?2 AND revoked_at IS NULL AND {admitted}"),vec![json!(target_tenant),json!(target_id),json!(event)]));
                    statements.push(Statement::new(format!("DELETE FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND {admitted}"),vec![json!(target_tenant),json!(target_id),json!(event)]));
                }
            }
            statements.push(Statement::new(format!("SELECT principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND {admitted}"),vec![json!(target_tenant),json!(target_id),json!(event)]));
            let mut result = self.database.batch(statements).await?;
            if result.first().ok_or(DbError::CorruptData)?.rows.is_empty() {
                continue;
            }
            return match decision {
                Err(reason) => Ok(AdminUserUpdateOutcome::Denied(reason)),
                Ok(None) => Ok(AdminUserUpdateOutcome::TargetNotFound),
                Ok(Some(_)) => {
                    let row = result
                        .pop()
                        .ok_or(DbError::CorruptData)?
                        .rows
                        .pop()
                        .ok_or(DbError::CorruptData)?;
                    let account = serde_json::from_value::<UserRow>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .public_account(target_tenant, target_id)?;
                    Ok(AdminUserUpdateOutcome::Updated(Box::new(account)))
                }
            };
        }
        Err(RepositoryError::Conflict)
    }
}

impl AdminUserRepositoryPort for D1Provider {
    fn page(&self, tenant_id: TenantId, limit: i64, offset: i64) -> RepositoryFuture<'_, UserPage> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            if limit < 0 || offset < 0 {
                return Err(DbError::CorruptData.into());
            }
            let mut result=self.database.batch(vec![
                Statement::new("SELECT id,principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 ORDER BY created_at DESC,id DESC LIMIT ?2 OFFSET ?3",vec![json!(self.tenant_id),json!(limit),json!(offset)]),
                Statement::new("SELECT count(*) AS total FROM nazo_users WHERE tenant_id=?1",vec![json!(self.tenant_id)]),
            ]).await?.into_iter();
            let users = result
                .next()
                .ok_or(DbError::CorruptData)?
                .rows
                .into_iter()
                .map(|row| {
                    let id = serde_json::from_value::<UserId>(
                        row.get("id").cloned().ok_or(DbError::CorruptData)?,
                    )
                    .map_err(|_| DbError::CorruptData)?;
                    serde_json::from_value::<UserRow>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .public_account(tenant_id, id)
                })
                .collect::<Result<Vec<_>, DbError>>()?;
            let total = result
                .next()
                .and_then(|r| r.rows.into_iter().next())
                .and_then(|r| r.get("total").and_then(Value::as_i64))
                .ok_or(DbError::CorruptData)?;
            Ok(UserPage { total, users })
        })
    }
    fn update_authorized_with_required_audit(
        &self,
        tenant: TenantContext,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(async move {
            self.update_admin_account(
                tenant.tenant_id,
                actor_id,
                tenant.tenant_id,
                target_id,
                Change::Local(tenant, update),
                &source_ip_hash,
            )
            .await
        })
    }
    fn set_tenant_admin_authorized(
        &self,
        control_tenant_id: TenantId,
        actor_id: UserId,
        target_tenant_id: TenantId,
        target_id: UserId,
        admin_level: i32,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, AdminUserUpdateOutcome> {
        Box::pin(async move {
            if admin_level < 0 || control_tenant_id == target_tenant_id {
                return Ok(AdminUserUpdateOutcome::Denied(
                    AdminPolicyError::InvalidRoleLevel,
                ));
            }
            self.update_admin_account(
                control_tenant_id,
                actor_id,
                target_tenant_id,
                target_id,
                Change::TenantLevel(admin_level),
                &source_ip_hash,
            )
            .await
        })
    }
}
