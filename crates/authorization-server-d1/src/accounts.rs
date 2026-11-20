//! Registration writes and current administrator authority for D1 mutations.

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow, encode},
};
use nazo_identity::{
    Principal, PublicAccount, TenantContext, TenantId, UserId, UserRole,
    ports::{NewUser, RegistrationAccountRepositoryPort, RepositoryError, RepositoryFuture},
};
use serde_json::{Value, json};
use uuid::Uuid;

impl D1Provider {
    /// Read a typed authority snapshot; the caller must compare it again inside
    /// the batch that performs its mutation. Never authorize from a session copy.
    pub(super) async fn admin_actor_snapshot(
        &self,
        tenant: TenantContext,
        actor: UserId,
    ) -> Result<UserRow, DbError> {
        self.require_tenant(tenant.tenant_id.as_uuid())?;
        let row = self
            .user_row(actor.as_uuid())
            .await?
            .ok_or(DbError::CorruptData)?;
        let principal = row.principal(tenant.tenant_id, actor)?;
        if principal.tenant != tenant
            || !principal.active
            || !principal.admin_level().is_some_and(|level| level > 0)
        {
            return Err(DbError::CorruptData);
        }
        Ok(row)
    }

    async fn create_account(
        &self,
        new_user: NewUser,
        audit: Option<(UserId, String)>,
    ) -> Result<PublicAccount, RepositoryError> {
        let tenant = new_user.tenant;
        self.require_tenant(tenant.tenant_id.as_uuid())?;
        let user_id = UserId::new(Uuid::new_v4()).map_err(|_| DbError::CorruptData)?;
        let principal = Principal {
            authorization_epoch: 0,
            user_id,
            tenant,
            role: UserRole::User,
            active: true,
        };
        let claims = json!({
            "subject":user_id,"preferred_username":new_user.username,"email":new_user.email,
            "email_verified":new_user.email_verified,"phone_number_verified":false,"updated_at":0,
        });
        let mut parameters = vec![
            json!(self.tenant_id),
            json!(user_id),
            json!(new_user.email),
            json!(encode(&principal)?),
            json!(encode(&claims)?),
            json!(new_user.password_hash.into_persistence_value()),
        ];
        let predicate = if let Some((actor, _)) = &audit {
            let snapshot = self.admin_actor_snapshot(tenant, *actor).await?;
            parameters.extend([
                json!(actor),
                json!(snapshot.principal),
                json!(snapshot.epoch),
                json!(snapshot.active),
            ]);
            "EXISTS(SELECT 1 FROM nazo_users a WHERE a.tenant_id=?1 AND a.id=?7 AND a.principal=?8 AND a.epoch=?9 AND a.active=?10)"
        } else {
            "1"
        };
        // The native unique username and case-insensitive email constraints are
        // represented by 0005. DO NOTHING makes races a domain Conflict.
        let mut statements = vec![Statement::new(format!(
            "INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at)
             SELECT ?1,?2,?3,?4,json_set(?5,'$.updated_at',unixepoch()),?6,0,1,0,0,{NOW},{NOW} WHERE {predicate}
             ON CONFLICT DO NOTHING RETURNING principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at"),parameters)];
        if let Some((actor, source)) = audit {
            let payload = json!({
                "schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category":"administration","tenant_id":self.tenant_id,
                "realm_id":tenant.realm_id,"organization_id":tenant.organization_id,
                "admin_user_id":actor,"user_id":user_id,"role":"user","admin_level":0,
                "is_active":true,"outcome":"success","source_ip_hash":source,
            });
            statements.push(Statement::new(
                format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT ?1,?2,'admin_user_created','administration',{NOW},?3 WHERE changes()=1"),
                vec![
                    json!(self.tenant_id),
                    json!(Uuid::new_v4()),
                    json!(encode(&payload)?),
                ],
            ));
        }
        let mut results = self.database.batch(statements).await?;
        let row = results
            .remove(0)
            .rows
            .pop()
            .ok_or(RepositoryError::Conflict)?;
        serde_json::from_value::<UserRow>(row)
            .map_err(|_| DbError::CorruptData)?
            .public_account(tenant.tenant_id, user_id)
            .map_err(Into::into)
    }
}

impl RegistrationAccountRepositoryPort for D1Provider {
    fn email_exists<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            Ok(!self.database.query::<Value>("SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND lower(email)=lower(?2) LIMIT 1",vec![json!(self.tenant_id),json!(email)]).await?.is_empty())
        })
    }
    fn create_user(&self, new_user: NewUser) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move { self.create_account(new_user, None).await })
    }
    fn create_user_with_required_audit(
        &self,
        new_user: NewUser,
        actor_id: UserId,
        source_ip_hash: String,
    ) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move {
            self.create_account(new_user, Some((actor_id, source_ip_hash)))
                .await
        })
    }
}
