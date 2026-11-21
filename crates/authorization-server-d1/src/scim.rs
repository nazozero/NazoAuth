//! SCIM account mutations, revocation and required evidence in one D1 batch.

use nazo_identity::{
    Principal, PublicAccount, SubjectClaims, TenantContext, TenantId, UserId, UserRole,
    ports::{
        NewScimUser, RepositoryError, RepositoryFuture, ScimCredentialPort, ScimListQuery,
        ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimPatch, ScimTokenCredential},
};
use nazo_scim_events::{MutationContext, StoredEvent};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow, encode},
};

pub(crate) struct ScimRepository {
    provider: D1Provider,
    retention_seconds: u64,
}

#[derive(Deserialize)]
struct AccountRow {
    id: UserId,
    #[serde(flatten)]
    account: UserRow,
}

impl ScimRepository {
    pub(crate) const fn new(provider: D1Provider, retention_seconds: u64) -> Self {
        Self {
            provider,
            retention_seconds,
        }
    }

    async fn write(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        plan: Value,
        mutation: MutationContext,
        event: Option<(StoredEvent, Value, Value)>,
    ) -> Result<PublicAccount, RepositoryError> {
        self.provider.require_tenant(tenant.tenant_id.as_uuid())?;
        let command = Uuid::new_v4();
        let tenant_id = self.provider.tenant_id;
        let identity: std::sync::Arc<[Value]> =
            vec![json!(tenant_id), json!(user_id), json!(command)].into();
        let mut planned = identity.to_vec();
        planned.push(json!(encode(&plan)?));
        let planned: std::sync::Arc<[Value]> = planned.into();
        // The batch-local receipt captures admission, the previous activation
        // state and the database timestamp under the same transaction lock.
        // It is removed before commit, including on rejected mutations.
        let mut statements=vec![Statement::new(format!(
            "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at)
             VALUES(?1,'scim_mutation',?3,json_object('at',{NOW},
                'old_active',(SELECT active FROM nazo_users WHERE tenant_id=?1 AND id=?2),
                'outcome',CASE
                    WHEN json_extract(?4,'$.kind')='create' AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2) THEN 'conflict'
                    WHEN json_extract(?4,'$.kind')!='create' AND (NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2) OR EXISTS(SELECT 1 FROM nazo_deleted_users WHERE tenant_id=?1 AND user_id=?2)) THEN 'not_found'
                    WHEN EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id!=?2 AND lower(email)=lower(json_extract(?4,'$.email'))) THEN 'conflict'
                    WHEN EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id!=?2 AND json_extract(claims,'$.preferred_username')=json_extract(?4,'$.user_name')) THEN 'conflict'
                    ELSE 'applied' END),?3,unixepoch()+60)"),planned.clone())];
        let admitted = "EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='scim_mutation' AND key=?3 AND json_extract(value,'$.outcome')='applied')";
        let at = "(SELECT json_extract(value,'$.at') FROM nazo_state WHERE tenant_id=?1 AND kind='scim_mutation' AND key=?3)";
        let operation = plan
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(DbError::CorruptData)?;
        let audit_type = match operation {
            "create" => "scim_user_created",
            "replace" => "scim_user_replaced",
            "patch" => "scim_user_patched",
            "delete" => "scim_user_deleted",
            _ => return Err(DbError::CorruptData.into()),
        };
        let mut audit_params = identity.to_vec();
        audit_params.extend([json!(audit_type), json!(mutation.transaction_id())]);
        statements.push(Statement::new(format!(
            "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
             SELECT ?1,?3,?4,'identity_lifecycle',{at},json_object('schema_version',1,'category','identity_lifecycle','tenant_id',?1,'user_id',?2,'transaction_id',?5)
             WHERE {admitted}"),audit_params));
        if operation == "create" {
            statements.push(Statement::new(format!(
                "INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at)
                 SELECT ?1,?2,json_extract(?4,'$.email'),json_extract(?4,'$.principal'),
                    json_set(json_extract(?4,'$.claims'),'$.updated_at',CAST({at}/1000000 AS INTEGER)),
                    json_extract(?4,'$.password_hash'),0,json_extract(?4,'$.active'),0,0,{at},{at}
                 WHERE {admitted}"),planned.clone()));
        } else {
            statements.push(Statement::new(format!(
                "UPDATE nazo_users SET
                    epoch=epoch+CASE WHEN active=1 AND json_extract(?4,'$.active')=0 THEN 1 ELSE 0 END,
                    active=coalesce(json_extract(?4,'$.active'),active),
                    email=coalesce(json_extract(?4,'$.email'),email),
                    claims=json_set(claims,
                        '$.preferred_username',coalesce(json_extract(?4,'$.user_name'),json_extract(claims,'$.preferred_username')),
                        '$.email',coalesce(json_extract(?4,'$.email'),email),
                        '$.email_verified',json(CASE WHEN json_extract(?4,'$.kind')='delete' THEN CASE WHEN json_extract(claims,'$.email_verified')=1 THEN 'true' ELSE 'false' END ELSE 'true' END),
                        '$.name',CASE WHEN json_extract(?4,'$.kind')='replace' OR json_extract(?4,'$.display_name') IS NOT NULL THEN json_extract(?4,'$.display_name') ELSE json_extract(claims,'$.name') END,
                        '$.given_name',CASE WHEN json_extract(?4,'$.kind')='replace' OR json_extract(?4,'$.given_name') IS NOT NULL THEN json_extract(?4,'$.given_name') ELSE json_extract(claims,'$.given_name') END,
                        '$.family_name',CASE WHEN json_extract(?4,'$.kind')='replace' OR json_extract(?4,'$.family_name') IS NOT NULL THEN json_extract(?4,'$.family_name') ELSE json_extract(claims,'$.family_name') END,
                        '$.updated_at',CAST({at}/1000000 AS INTEGER)),updated_at={at}
                 WHERE tenant_id=?1 AND id=?2 AND {admitted}"),planned));
            if operation == "delete" {
                statements.push(Statement::new(format!(
                    "INSERT INTO nazo_deleted_users(tenant_id,user_id,deleted_at) SELECT ?1,?2,{at} WHERE {admitted}"),identity.clone()));
            }
            let deactivated = format!(
                "{admitted} AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=0)"
            );
            let reason = if operation == "delete" {
                "scim_user_deleted"
            } else {
                "scim_user_deactivated"
            };
            statements.push(Statement::new(format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                 SELECT ?1,lower(hex(randomblob(16))),'refresh_family_security_revoked','token_lifecycle',{at},
                    json_object('schema_version',1,'category','token_lifecycle','tenant_id',?1,'user_id',?2,'client_id',client_id,'token_family_id',id,'reason','{reason}')
                 FROM nazo_refresh_families WHERE tenant_id=?1 AND user_id=?2 AND revoked_at IS NULL AND {deactivated}"),identity.clone()));
            statements.push(Statement::new(format!(
                "UPDATE nazo_refresh_families SET revoked_at={at} WHERE tenant_id=?1 AND user_id=?2 AND revoked_at IS NULL AND {deactivated}"),identity.clone()));
            statements.push(Statement::new(
                format!(
                    "DELETE FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND {deactivated}"
                ),
                identity.clone(),
            ));
        }
        if let Some((event, activate, deactivate)) = event {
            let retention = i64::try_from(self.retention_seconds)
                .ok()
                .and_then(|n| n.checked_mul(1_000_000))
                .ok_or_else(|| {
                    RepositoryError::Consistency("SCIM retention is out of range".into())
                })?;
            let mut parameters = identity.to_vec();
            parameters.extend([
                json!(event.id),
                json!(event.transaction_id),
                json!(event.subject_uri),
                json!(encode(&event.events)?),
                json!(encode(&activate)?),
                json!(encode(&deactivate)?),
                json!(retention),
            ]);
            statements.push(Statement::new(format!(
                "INSERT INTO nazo_scim_events(tenant_id,id,transaction_id,subject_uri,events,occurred_at,expires_at)
                 SELECT ?1,?4,?5,?6,
                    CASE WHEN json_extract(receipt.value,'$.old_active')!=account.active THEN CASE WHEN account.active=1 THEN ?8 ELSE ?9 END ELSE ?7 END,
                    json_extract(receipt.value,'$.at'),json_extract(receipt.value,'$.at')+?10
                 FROM nazo_state AS receipt JOIN nazo_users AS account ON account.tenant_id=receipt.tenant_id AND account.id=?2
                 WHERE receipt.tenant_id=?1 AND receipt.kind='scim_mutation' AND receipt.key=?3 AND {admitted}"),parameters));
        }
        statements.push(Statement::new(format!(
            "SELECT principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND {admitted}"),identity.clone()));
        statements.push(Statement::new("SELECT json_extract(value,'$.outcome') AS outcome FROM nazo_state WHERE tenant_id=?1 AND kind='scim_mutation' AND key=?2",vec![json!(tenant_id),json!(command)]));
        statements.push(Statement::new(
            "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind='scim_mutation' AND key=?2",
            vec![json!(tenant_id), json!(command)],
        ));
        let mut results = self.provider.database.batch(statements).await?;
        results.pop();
        let outcome = results
            .pop()
            .and_then(|r| r.rows.into_iter().next())
            .ok_or(DbError::CorruptData)?;
        match outcome.get("outcome").and_then(Value::as_str) {
            Some("not_found") => Err(RepositoryError::NotFound),
            Some("conflict") => Err(RepositoryError::Conflict),
            Some("applied") => {
                let row: UserRow = serde_json::from_value(
                    results
                        .pop()
                        .and_then(|r| r.rows.into_iter().next())
                        .ok_or(DbError::CorruptData)?,
                )
                .map_err(|_| DbError::CorruptData)?;
                row.public_account(tenant.tenant_id, user_id)
                    .map_err(Into::into)
            }
            _ => Err(DbError::CorruptData.into()),
        }
    }
}

fn notice(
    mutation: MutationContext,
    tenant: TenantId,
    user: UserId,
    kind: &str,
    attributes: &[String],
) -> Option<(StoredEvent, Value, Value)> {
    let transaction = mutation.transaction_id()?;
    let at = jiff::Timestamp::now();
    let event = |transition| match kind {
        "create" => StoredEvent::create_notice(tenant.as_uuid(), user.as_uuid(), transaction, at),
        "replace" => StoredEvent::put_notice(
            tenant.as_uuid(),
            user.as_uuid(),
            transaction,
            at,
            transition,
        ),
        "patch" => StoredEvent::patch_notice(
            tenant.as_uuid(),
            user.as_uuid(),
            transaction,
            at,
            attributes,
            transition,
        ),
        _ => StoredEvent::delete(tenant.as_uuid(), user.as_uuid(), transaction, at),
    };
    Some((
        event(None),
        json!(event(Some(true)).events),
        json!(event(Some(false)).events),
    ))
}

impl ScimRepositoryPort for ScimRepository {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(async move {
            self.provider.require_tenant(query.tenant_id.as_uuid())?;
            let email = query.email;
            let filter = "tenant_id=?1 AND (?2 IS NULL OR email=?2) AND NOT EXISTS(SELECT 1 FROM nazo_deleted_users AS deleted WHERE deleted.tenant_id=nazo_users.tenant_id AND deleted.user_id=nazo_users.id)";
            let result=self.provider.database.batch(vec![
                Statement::new(format!("SELECT count(*) AS total FROM nazo_users WHERE {filter}"),vec![json!(self.provider.tenant_id),json!(email)]),
                Statement::new(format!("SELECT id,principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE {filter} AND (?3 IS NULL OR (created_at,id)>(?3,?4)) ORDER BY created_at,id LIMIT ?5 OFFSET ?6"),
                    vec![json!(self.provider.tenant_id),json!(email),json!(query.after.map(|(at,_)|at.as_microsecond())),json!(query.after.map(|(_,id)|id)),json!(query.limit.max(0)),json!(query.offset.max(0))]),
            ]).await?;
            let total = result[0]
                .rows
                .first()
                .and_then(|row| row.get("total"))
                .and_then(Value::as_i64)
                .ok_or(DbError::CorruptData)?;
            let users = result
                .into_iter()
                .nth(1)
                .ok_or(DbError::CorruptData)?
                .rows
                .into_iter()
                .map(|row| {
                    let row: AccountRow =
                        serde_json::from_value(row).map_err(|_| DbError::CorruptData)?;
                    row.account.public_account(query.tenant_id, row.id)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(UserPage { total, users })
        })
    }

    fn get<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            self.provider.require_tenant(tenant.tenant_id.as_uuid())?;
            self.provider.database.query::<UserRow>(
                "SELECT principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND NOT EXISTS(SELECT 1 FROM nazo_deleted_users WHERE tenant_id=?1 AND user_id=?2)",
                vec![json!(self.provider.tenant_id),json!(user_id)],
            ).await?.pop().map(|row|row.public_account(tenant.tenant_id,user_id).map_err(Into::into)).transpose()
        })
    }

    fn create<'a>(&'a self, new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            let NewScimUser {
                tenant,
                input,
                password_hash,
                mutation,
            } = new_user;
            let user_id = UserId::new(Uuid::new_v4()).map_err(|_| DbError::CorruptData)?;
            let principal = Principal {
                authorization_epoch: 0,
                user_id,
                tenant,
                role: UserRole::User,
                active: input.active,
            };
            let claims:SubjectClaims=serde_json::from_value(json!({
                "subject":user_id,"preferred_username":input.user_name,"email":input.email,
                "email_verified":true,"phone_number_verified":false,"updated_at":0,
                "name":input.display_name,"given_name":input.given_name,"family_name":input.family_name,
            })).map_err(|_|DbError::CorruptData)?;
            let plan = json!({"kind":"create","user_name":input.user_name,"email":input.email,
                "active":input.active,"principal":principal,"claims":claims,
                "password_hash":password_hash.into_persistence_value()});
            self.write(
                tenant,
                user_id,
                plan,
                mutation,
                notice(mutation, tenant.tenant_id, user_id, "create", &[]),
            )
            .await
        })
    }

    fn replace<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        input: NormalizedScimUser,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            self.write(
                tenant,
                user_id,
                json!({"kind":"replace","user_name":input.user_name,
                "email":input.email,"active":input.active,"display_name":input.display_name,
                "given_name":input.given_name,"family_name":input.family_name}),
                mutation,
                notice(mutation, tenant.tenant_id, user_id, "replace", &[]),
            )
            .await
        })
    }

    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move {
            let event = notice(
                mutation,
                tenant.tenant_id,
                user_id,
                "patch",
                &patch.event_attributes(),
            );
            self.write(
                tenant,
                user_id,
                json!({"kind":"patch","user_name":patch.user_name,
                "email":patch.email,"active":patch.active,"display_name":patch.display_name,
                "given_name":patch.given_name,"family_name":patch.family_name}),
                mutation,
                event,
            )
            .await
        })
    }

    fn delete<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        mutation: MutationContext,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            match self
                .write(
                    tenant,
                    user_id,
                    json!({"kind":"delete","active":false}),
                    mutation,
                    notice(mutation, tenant.tenant_id, user_id, "delete", &[]),
                )
                .await
            {
                Ok(_) => Ok(true),
                Err(RepositoryError::NotFound) => Ok(false),
                Err(error) => Err(error),
            }
        })
    }
}

impl ScimCredentialPort for D1Provider {
    fn active_credential<'a>(
        &'a self,
        token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<ScimTokenCredential>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct CredentialRow {
                id: Uuid,
                tenant_id: Uuid,
                scopes: String,
                event_audience: Option<String>,
            }
            self.database.query::<CredentialRow>(&format!(
                "SELECT id,tenant_id,scopes,event_audience FROM nazo_scim_tokens WHERE tenant_id=?1 AND token_hash=?2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>{NOW})"),
                vec![json!(self.tenant_id),json!(token_hash)],
            ).await?.pop().map(|row|Ok(ScimTokenCredential{id:row.id,tenant_id:row.tenant_id,
                scopes:serde_json::from_str(&row.scopes).map_err(|_|DbError::CorruptData)?,event_audience:row.event_audience})).transpose()
        })
    }
}

impl D1Provider {
    /// Provision separate SCIM authority outside request handling. The caller
    /// retains the bearer secret; only its digest crosses the persistence port.
    pub async fn provision_scim_credential(
        &self,
        credential: &ScimTokenCredential,
        token_hash: &str,
        expires_at: Option<jiff::Timestamp>,
    ) -> anyhow::Result<()> {
        self.require_tenant(credential.tenant_id)?;
        anyhow::ensure!(
            !credential.id.is_nil()
                && token_hash.len() == 64
                && token_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid SCIM credential authority"
        );
        anyhow::ensure!(
            !credential.scopes.is_empty()
                && credential.scopes.iter().all(|scope| matches!(
                    scope.as_str(),
                    "scim:read" | "scim:write" | "scim:events" | "scim:*"
                )),
            "invalid SCIM credential scopes"
        );
        self.database.batch(vec![Statement::new(format!(
            "INSERT INTO nazo_scim_tokens(tenant_id,id,token_hash,scopes,event_audience,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,{NOW},?6)"),
            vec![json!(self.tenant_id),json!(credential.id),json!(token_hash),json!(encode(&credential.scopes)?),json!(credential.event_audience),json!(expires_at.map(|at|at.as_microsecond()))])]).await?;
        Ok(())
    }
}
