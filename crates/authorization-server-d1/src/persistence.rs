use futures_util::future::BoxFuture;
use jiff::Timestamp;
use nazo_auth::{AuthorizationFuture, AuthorizationPortError, OAuthClient};
use nazo_identity::{
    PublicAccount, SubjectClaims, TenantId, UserId,
    ports::{RepositoryError, RepositoryFuture},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    rows::ClientRow,
};

pub(super) const NOW: &str = "CAST(unixepoch('subsec') * 1000000 AS INTEGER)";

pub(super) fn timestamp(value: i64) -> Result<Timestamp, DbError> {
    Timestamp::from_microsecond(value).map_err(|_| DbError::CorruptData)
}
pub(super) fn encode(value: &impl serde::Serialize) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|_| DbError::CorruptData)
}
pub(super) fn digest(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

impl From<DbError> for RepositoryError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::Consistency("D1 stored data is invalid".into()),
        }
    }
}
impl From<DbError> for AuthorizationPortError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::CorruptData,
        }
    }
}
impl From<DbError> for nazo_auth::TokenPortError {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::CorruptData,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct Flag {
    pub value: i64,
}
#[derive(Deserialize)]
pub(super) struct UserRow {
    pub principal: String,
    pub claims: String,
    pub epoch: i64,
    pub active: i64,
    pub mfa_enabled: i64,
    pub avatar_revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
}
impl UserRow {
    pub fn principal(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<nazo_identity::Principal, DbError> {
        let mut principal: nazo_identity::Principal =
            serde_json::from_str(&self.principal).map_err(|_| DbError::CorruptData)?;
        if principal.tenant.tenant_id != tenant_id || principal.user_id != user_id {
            return Err(DbError::CorruptData);
        }
        principal.authorization_epoch = self.epoch;
        principal.active = self.active != 0;
        Ok(principal)
    }
    pub fn claims(&self) -> Result<SubjectClaims, DbError> {
        serde_json::from_str(&self.claims).map_err(|_| DbError::CorruptData)
    }
    pub fn public_account(
        self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<PublicAccount, DbError> {
        let principal = self.principal(tenant_id, user_id)?;
        let claims = self.claims()?;
        if claims.subject != user_id {
            return Err(DbError::CorruptData);
        }
        Ok(PublicAccount {
            principal,
            account: nazo_identity::AccountIdentity {
                username: claims.preferred_username,
                email: claims.email,
                email_verified: claims.email_verified,
                mfa_enabled: self.mfa_enabled != 0,
            },
            profile: nazo_identity::UserProfile {
                avatar_revision: self.avatar_revision,
                display_name: claims.name,
                avatar_url: claims.picture,
                given_name: claims.given_name,
                family_name: claims.family_name,
                middle_name: claims.middle_name,
                nickname: claims.nickname,
                profile_url: claims.profile,
                website_url: claims.website,
                gender: claims.gender,
                birthdate: claims.birthdate,
                zoneinfo: claims.zoneinfo,
                locale: claims.locale,
                address: claims.address.unwrap_or_default(),
                phone_number: claims.phone_number,
                phone_number_verified: claims.phone_number_verified,
            },
            created_at: timestamp(self.created_at)?,
            updated_at: timestamp(self.updated_at)?,
        })
    }
}

impl D1Provider {
    pub(super) fn require_tenant(&self, tenant: Uuid) -> Result<(), DbError> {
        if tenant == self.tenant_id {
            Ok(())
        } else {
            Err(DbError::CorruptData)
        }
    }
    pub(super) async fn client_row(&self, client_id: &str) -> Result<Option<ClientRow>, DbError> {
        Ok(self
            .database
            .query(
                "SELECT * FROM nazo_clients WHERE tenant_id=?1 AND client_id=?2",
                vec![json!(self.tenant_id), json!(client_id)],
            )
            .await?
            .into_iter()
            .next())
    }
    pub(super) async fn user_row(&self, user_id: Uuid) -> Result<Option<UserRow>, DbError> {
        Ok(self
            .database
            .query(
                    "SELECT principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND id=?2",
                vec![json!(self.tenant_id), json!(user_id)],
            )
            .await?
            .into_iter()
            .next())
    }

    /// Provision a validated static client outside the HTTP request path.
    /// Existing registrations are never silently overwritten.
    pub async fn provision_client(
        &self,
        client: &OAuthClient,
        secret_digest: Option<&str>,
        epoch: i64,
    ) -> anyhow::Result<()> {
        self.require_tenant(client.tenant_id)?;
        anyhow::ensure!(
            epoch >= 0 && !client.id.is_nil(),
            "invalid client authority"
        );
        validate_client_capabilities(client)?;
        let rows = self.database.query::<Value>("INSERT INTO nazo_clients(tenant_id,id,client_id,realm_id,organization_id,registration,secret_digest,epoch,active,require_mtls_bound_tokens) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) RETURNING 1", vec![json!(self.tenant_id),json!(client.id),json!(client.client_id),json!(client.realm_id),json!(client.organization_id),json!(encode(&client.registration)?),json!(secret_digest),json!(epoch),json!(client.is_active),json!(client.require_mtls_bound_tokens)]).await?;
        if rows.len() != 1 {
            return Err(DbError::Unavailable.into());
        }
        Ok(())
    }

    /// Provision an account and its claim projection in the same transaction.
    pub async fn provision_user(
        &self,
        account: &PublicAccount,
        claims: &SubjectClaims,
        password_hash: nazo_identity::ports::PasswordHashInput,
    ) -> anyhow::Result<()> {
        self.require_tenant(account.tenant_id())?;
        anyhow::ensure!(
            account.user_id() == claims.subject && !account.account.mfa_enabled,
            "invalid account or unsupported MFA"
        );
        anyhow::ensure!(
            account.account.email == claims.email
                && account.account.username == claims.preferred_username,
            "account and claims differ"
        );
        let rows = self.database.query::<Value>("INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,?9,?10,?11) RETURNING 1", vec![json!(self.tenant_id),json!(account.id()),json!(account.account.email),json!(encode(&account.principal)?),json!(encode(claims)?),json!(password_hash.into_persistence_value()),json!(account.principal.authorization_epoch),json!(account.principal.active),json!(account.profile.avatar_revision),json!(account.created_at.as_microsecond()),json!(account.updated_at.as_microsecond())]).await?;
        if rows.len() != 1 {
            return Err(DbError::Unavailable.into());
        }
        Ok(())
    }

    /// Persist the deployment-selected module profile before starting any isolate.
    pub async fn initialize_modules(
        &self,
        enabled: &[nazo_runtime_modules::ModuleId],
    ) -> anyhow::Result<()> {
        use nazo_runtime_modules::ModuleId;
        anyhow::ensure!(
            enabled.iter().all(|module| matches!(
                module,
                ModuleId::RequestObjects
                    | ModuleId::DeviceAuthorization
                    | ModuleId::DynamicClientRegistration
                    | ModuleId::Jarm
                    | ModuleId::SessionManagement
                    | ModuleId::TokenExchange
                    | ModuleId::JwtBearerGrant
                    | ModuleId::NativeSso
                    | ModuleId::AuthorizationDetails
                    | ModuleId::FrontchannelLogout
                    | ModuleId::HttpMessageSignatures
                    | ModuleId::Ciba
                    | ModuleId::Scim
                    | ModuleId::ScimSecurityEvents
                    | ModuleId::Openid4vciIssuer
                    | ModuleId::Openid4vpVerifier
            )),
            "unsupported Workers module"
        );
        let mut statements = ModuleId::ALL
            .into_iter()
            .map(|module| {
                Ok(Statement::new(
                    "INSERT INTO nazo_modules(tenant_id,module_id,enabled) VALUES(?1,?2,?3)",
                    vec![
                        json!(self.tenant_id),
                        serde_json::to_value(module)?,
                        json!(enabled.contains(&module)),
                    ],
                ))
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;
        statements.push(Statement::new(
            "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM json_each(?2) m WHERE NOT EXISTS(
                SELECT 1 FROM nazo_modules p JOIN nazo_module_desired d USING(tenant_id,module_id)
                WHERE p.tenant_id=?1 AND p.module_id=m.value
                    AND p.enabled=EXISTS(SELECT 1 FROM json_each(?3) e WHERE e.value=m.value)
                    AND d.mode=CASE p.enabled WHEN 1 THEN 'enabled' ELSE 'disabled' END
                    AND d.revision=1 AND d.actor_id IS NULL AND d.reason='deployment profile' AND d.updated_at=0))
                THEN 1 ELSE json('module deployment profile was not committed') END",
            vec![json!(self.tenant_id), json!(encode(&ModuleId::ALL)?), json!(encode(&enabled)?)],
        ));
        self.database.batch(statements).await?;
        Ok(())
    }
}

impl nazo_identity::ports::LoginAccountRepositoryPort for D1Provider {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<nazo_identity::AuthenticationIdentity>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct AuthenticationRow {
                id: Uuid,
                active: i64,
                password_hash: String,
            }
            let rows: Vec<AuthenticationRow> = self
                .database
                .query(
                    "SELECT id,active,password_hash FROM nazo_users WHERE tenant_id=?1 AND email=?2",
                    vec![json!(self.tenant_id), json!(email)],
                )
                .await?;
            rows.into_iter()
                .next()
                .map(|row| {
                    Ok(nazo_identity::AuthenticationIdentity {
                        user_id: UserId::new(row.id).map_err(|_| DbError::CorruptData)?,
                        active: row.active != 0,
                        password_hash: nazo_identity::PasswordHash::new(row.password_hash)
                            .map_err(|_| DbError::CorruptData)?,
                    })
                })
                .transpose()
        })
    }
    fn login_state_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<nazo_identity::ports::LoginAccountState>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct LoginStateRow {
                epoch: i64,
                active: i64,
                mfa_enabled: i64,
            }
            Ok(self
                .database
                .query::<LoginStateRow>(
                    "SELECT epoch,active,mfa_enabled FROM nazo_users WHERE tenant_id=?1 AND id=?2",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| nazo_identity::ports::LoginAccountState {
                    authorization_epoch: row.epoch,
                    active: row.active != 0,
                    mfa_enabled: row.mfa_enabled != 0,
                }))
        })
    }
}
impl nazo_identity::ports::SessionAccountPort for D1Provider {
    fn principal_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<nazo_identity::Principal>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            #[derive(Deserialize)]
            struct PrincipalRow {
                principal: String,
                epoch: i64,
                active: i64,
            }
            self.database
                .query::<PrincipalRow>(
                    "SELECT principal,epoch,active FROM nazo_users WHERE tenant_id=?1 AND id=?2",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| {
                    let mut principal: nazo_identity::Principal =
                        serde_json::from_str(&row.principal).map_err(|_| DbError::CorruptData)?;
                    if principal.tenant.tenant_id != tenant_id || principal.user_id != user_id {
                        return Err(DbError::CorruptData.into());
                    }
                    principal.authorization_epoch = row.epoch;
                    principal.active = row.active != 0;
                    Ok(principal)
                })
                .transpose()
        })
    }
    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.user_row(user_id.as_uuid())
                .await?
                .map(|row| row.public_account(tenant_id, user_id).map_err(Into::into))
                .transpose()
        })
    }
}

impl nazo_persistence::DatabaseHealthPort for D1Provider {
    fn check(&self) -> BoxFuture<'_, Result<(), nazo_persistence::DatabaseHealthError>> {
        Box::pin(async move {
            self.database
                .query::<Flag>("SELECT 1 AS value", vec![])
                .await
                .map(|_| ())
                .map_err(|_| nazo_persistence::DatabaseHealthError)
        })
    }
}

impl nazo_auth::AuthorizationRepositoryPort for D1Provider {
    fn client_by_id<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            self.client_row(client_id)
                .await?
                .map(|row| row.into_domain().map_err(Into::into))
                .transpose()
        })
    }
    fn active_client_presentation<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::ClientPresentation>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct Presentation {
                client_name: String,
                logo_uri: Option<String>,
                policy_uri: Option<String>,
                tos_uri: Option<String>,
            }
            Ok(self.database.query::<Presentation>(
                "SELECT json_extract(registration,'$.client_name') AS client_name,json_extract(registration,'$.presentation.logo_uri') AS logo_uri,json_extract(registration,'$.presentation.policy_uri') AS policy_uri,json_extract(registration,'$.presentation.tos_uri') AS tos_uri FROM nazo_clients WHERE tenant_id=?1 AND client_id=?2 AND active=1",
                vec![json!(self.tenant_id),json!(client_id)]
            ).await?.into_iter().next().map(|row|nazo_auth::ClientPresentation { client_name:row.client_name, logo_uri:row.logo_uri,policy_uri:row.policy_uri,tos_uri:row.tos_uri }))
        })
    }
    fn client_authentication_snapshot<'a>(
        &'a self,
        client_id: &'a str,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::ClientAuthenticationSnapshot>> {
        Box::pin(async move {
            self.client_row(client_id)
                .await?
                .map(|mut row| {
                    let client_epoch = row.epoch;
                    let secret_digest = row.secret_digest.take().filter(|_| row.active != 0);
                    Ok(nazo_auth::ClientAuthenticationSnapshot {
                        client_epoch,
                        secret_digest,
                        client: row.into_domain()?,
                    })
                })
                .transpose()
        })
    }
    fn mtls_trust_anchor_bundle(&self, client_id: Uuid) -> AuthorizationFuture<'_, String> {
        Box::pin(async move {
            let tenant_id =
                TenantId::new(self.tenant_id).map_err(|_| AuthorizationPortError::CorruptData)?;
            nazo_identity::ports::MtlsTrustAnchorStore::active_bundle(
                self,
                tenant_id,
                Some(client_id),
            )
            .await
            .map_err(|error| match error {
                RepositoryError::Unavailable => AuthorizationPortError::Unavailable,
                RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
                    AuthorizationPortError::Conflict
                }
                RepositoryError::Consistency(_) => AuthorizationPortError::CorruptData,
                RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
                    AuthorizationPortError::Unexpected
                }
            })
        })
    }
    fn grant<'a>(
        &'a self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> AuthorizationFuture<'a, Option<nazo_auth::StoredAuthorizationGrant>> {
        Box::pin(async move {
            self.grant_row(user_id, client_id)
                .await?
                .map(|row| row.into_domain().map_err(Into::into))
                .transpose()
        })
    }
    fn commit_decision<'a>(
        &'a self,
        input: nazo_auth::AuthorizationDecisionCommit,
    ) -> AuthorizationFuture<'a, nazo_auth::AuthorizationDecisionCommitResult> {
        Box::pin(async move { self.commit_authorization(input).await })
    }
}

#[derive(Deserialize)]
pub(super) struct GrantRow {
    pub scopes: String,
    pub resources: String,
    pub details: String,
    pub revision: String,
}
impl GrantRow {
    fn into_domain(self) -> Result<nazo_auth::StoredAuthorizationGrant, DbError> {
        Ok(nazo_auth::StoredAuthorizationGrant {
            scopes: serde_json::from_str(&self.scopes).map_err(|_| DbError::CorruptData)?,
            resource_indicators: serde_json::from_str(&self.resources)
                .map_err(|_| DbError::CorruptData)?,
            authorization_details: serde_json::from_str(&self.details)
                .map_err(|_| DbError::CorruptData)?,
        })
    }
}

impl D1Provider {
    async fn grant_row(&self, user_id: Uuid, client_id: Uuid) -> Result<Option<GrantRow>, DbError> {
        Ok(self.database.query("SELECT scopes,resources,details,revision FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=?3", vec![json!(self.tenant_id),json!(user_id),json!(client_id)]).await?.into_iter().next())
    }

    async fn commit_authorization(
        &self,
        mut input: nazo_auth::AuthorizationDecisionCommit,
    ) -> Result<nazo_auth::AuthorizationDecisionCommitResult, AuthorizationPortError> {
        use nazo_auth::{AuthorizationDecisionCommitResult as Result, AuthorizationDecisionKind};
        self.require_tenant(input.tenant_id)?;
        if input.tenant_id.is_nil()
            || input.user_id.is_nil()
            || input.user_epoch < 0
            || input.event_id.is_nil()
            || input.request_id.is_empty()
            || input.request_id.len() > 512
            || input.client_id.is_empty()
            || input.client_id.len() > 512
            || input
                .pushed_request_uri
                .as_ref()
                .is_some_and(|uri| uri.is_empty() || uri.len() > 1024)
            || input.retain_until < input.valid_until
            || input.retain_until < input.occurred_at
            || !input.audit_fields.is_object()
            || !input.authorization_details.is_array()
        {
            return Err(AuthorizationPortError::CorruptData);
        }
        let Some(client) = self.client_row(&input.client_id).await? else {
            return Ok(Result::ClientUnavailable);
        };
        let grant_revision = if input.decision == AuthorizationDecisionKind::PromptNone {
            let Some(grant) = self.grant_row(input.user_id, client.id).await? else {
                return Ok(Result::GrantUnavailable);
            };
            let revision = grant.revision.clone();
            if !nazo_auth::stored_grant_covers_requested_authorization(
                &grant.into_domain()?,
                &input.scopes,
                &input.resource_indicators,
                &input.authorization_details,
            ) {
                return Ok(Result::GrantUnavailable);
            }
            Some(revision)
        } else {
            None
        };
        let event = input.event_id.to_string();
        let request_hash = digest(&input.request_id);
        let par_hash = input.pushed_request_uri.as_deref().map(digest);
        if let Some(fields) = input.audit_fields.as_object_mut() {
            // The persistence owner binds identity and outcome to the accepted
            // command. Only the shared application's non-secret evidence may
            // accompany it; arbitrary caller fields never enter the ledger.
            fields.retain(|key, _| {
                matches!(
                    key.as_str(),
                    "source_ip_hash"
                        | "pushed_request_digest"
                        | "code_id"
                        | "code_hash"
                        | "code_payload_digest"
                )
            });
            fields.insert(
                "schema_version".into(),
                json!(nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION),
            );
            fields.insert("event_category".into(), json!("authorization"));
            fields.insert("tenant_id".into(), json!(input.tenant_id));
            fields.insert("user_id".into(), json!(input.user_id));
            fields.insert("client_id".into(), json!(input.client_id));
            fields.insert("decision".into(), json!(input.decision.as_str()));
            fields.insert("scope".into(), json!(input.scopes.join(" ")));
            fields.insert("valid_until".into(), json!(input.valid_until.to_string()));
            fields.insert("retain_until".into(), json!(input.retain_until.to_string()));
            fields.insert("request_id_hash".into(), json!(request_hash));
            let resource_digest = (!input.resource_indicators.is_empty()).then(|| {
                let mut hasher = blake3::Hasher::new();
                for (index, resource) in input.resource_indicators.iter().enumerate() {
                    if index > 0 {
                        hasher.update(b"\x1f");
                    }
                    hasher.update(resource.as_bytes());
                }
                hasher.finalize().to_hex().to_string()
            });
            let details_digest = input
                .authorization_details
                .as_array()
                .filter(|details| !details.is_empty())
                .map(|_| {
                    let mut hasher = blake3::Hasher::new();
                    serde_json::to_writer(&mut hasher, &input.authorization_details)
                        .map_err(|_| AuthorizationPortError::CorruptData)?;
                    Ok::<_, AuthorizationPortError>(hasher.finalize().to_hex().to_string())
                })
                .transpose()?;
            for (key, value) in [
                ("pushed_request_uri_hash", par_hash.clone()),
                ("resource_digest", resource_digest),
                ("authorization_details_digest", details_digest),
            ] {
                if let Some(value) = value {
                    fields.insert(key.into(), json!(value));
                } else {
                    fields.remove(key);
                }
            }
        }
        let audit_payload = encode(&input.audit_fields)?;
        let approve = input.decision == AuthorizationDecisionKind::Approve;
        let params = vec![
            json!(self.tenant_id),
            json!(input.user_id),
            json!(client.id),
            json!(input.valid_until.as_microsecond()),
            json!(grant_revision),
            json!(request_hash),
            json!(par_hash),
            json!(event),
            json!(audit_payload),
            json!(input.occurred_at.as_microsecond()),
            json!(approve),
            json!(input.user_epoch),
        ];
        let admission = format!(
            "EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND id=?3 AND active=1) AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1 AND epoch=?12) AND ?4>{NOW} AND (?5 IS NULL OR EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=?3 AND revision=?5)) AND NOT EXISTS(SELECT 1 FROM nazo_decisions WHERE tenant_id=?1 AND (request_hash=?6 OR (?7 IS NOT NULL AND par_hash=?7)))"
        );
        // A reused event must hit UNIQUE and roll back, even when current
        // admission fails; only this batch's insert may authorize the writes.
        let mut batch = vec![Statement::new(
            format!(
                "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?8,'authorization_decision','authorization',?10,
                    CASE WHEN ?11 THEN json_set(?9,'$.authorization_count',COALESCE((SELECT authorization_count FROM nazo_grant_activity WHERE tenant_id=?1 AND user_id=?2 AND client_id=?3),0)+1) ELSE ?9 END
                    WHERE ({admission}) OR EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?8 AND event_type='authorization_decision')"
            ),
            params,
        )];
        batch.push(Statement::new(
            "SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?2 AND event_type='authorization_decision') OR changes()=1
                THEN 1 ELSE json('authorization decision audit was not inserted') END",
            vec![json!(self.tenant_id), json!(event)],
        ));
        batch.push(Statement::new("INSERT INTO nazo_decisions(tenant_id,request_hash,par_hash,event_id,retain_until) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4 AND event_type='authorization_decision')",vec![json!(self.tenant_id),json!(request_hash),json!(par_hash),json!(event),json!(input.retain_until.as_microsecond())]));
        if approve {
            batch.push(Statement::new("INSERT INTO nazo_grants(tenant_id,user_id,client_id,scopes,resources,details,revision) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?7 AND event_type='authorization_decision') ON CONFLICT(tenant_id,user_id,client_id) DO UPDATE SET scopes=excluded.scopes,resources=excluded.resources,details=excluded.details,revision=excluded.revision",vec![json!(self.tenant_id),json!(input.user_id),json!(client.id),json!(encode(&input.scopes)?),json!(encode(&input.resource_indicators)?),json!(encode(&input.authorization_details)?),json!(event)]));
        }
        batch.push(Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) OR (
            EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4 AND event_type='authorization_decision' AND category='authorization' AND occurred_at=?10
                AND ((?11=0 AND payload=?9) OR (?11=1 AND json_type(payload,'$.authorization_count')='integer' AND payload=json_set(?9,'$.authorization_count',json_extract(payload,'$.authorization_count')))))
            AND EXISTS(SELECT 1 FROM nazo_decisions WHERE tenant_id=?1 AND request_hash=?5 AND par_hash IS ?6 AND event_id=?4 AND retain_until=?7)
            AND (?8 IS NULL OR EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?1 AND user_id=?2 AND client_id=?3 AND revision=?8))
            AND (?11=0 OR (EXISTS(SELECT 1 FROM nazo_grants g JOIN nazo_grant_activity h ON h.tenant_id=g.tenant_id AND h.user_id=g.user_id AND h.client_id=g.client_id
                JOIN nazo_audit a ON a.tenant_id=g.tenant_id AND a.event_id=g.revision
                WHERE g.tenant_id=?1 AND g.user_id=?2 AND g.client_id=?3 AND g.revision=?4 AND g.scopes=?12 AND g.resources=?13 AND g.details=?14
                    AND h.last_authorized_at=a.occurred_at AND h.authorization_count=json_extract(a.payload,'$.authorization_count'))
                AND NOT EXISTS(SELECT 1 FROM nazo_grant_history_unknown WHERE tenant_id=?1 AND user_id=?2 AND client_id=?3 AND last_authorization_unknown<>0))))
            THEN 1 ELSE json('authorization decision effects were not accepted') END",
            vec![json!(self.tenant_id),json!(input.user_id),json!(client.id),json!(event),json!(request_hash),json!(par_hash),json!(input.retain_until.as_microsecond()),json!(grant_revision),json!(audit_payload),json!(input.occurred_at.as_microsecond()),json!(approve),json!(encode(&input.scopes)?),json!(encode(&input.resource_indicators)?),json!(encode(&input.authorization_details)?)]));
        batch.push(Statement::new(format!("SELECT CASE WHEN EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?3 AND event_id=?1 AND event_type='authorization_decision') THEN 'committed' WHEN ?2<={NOW} THEN 'expired' WHEN NOT EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?3 AND id=?4 AND active=1) THEN 'client' WHEN NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?3 AND id=?5 AND active=1 AND epoch=?7) THEN 'subject' WHEN ?6 IS NOT NULL AND NOT EXISTS(SELECT 1 FROM nazo_grants WHERE tenant_id=?3 AND user_id=?5 AND client_id=?4 AND revision=?6) THEN 'grant' ELSE 'conflict' END AS outcome"),vec![json!(event),json!(input.valid_until.as_microsecond()),json!(self.tenant_id),json!(client.id),json!(input.user_id),json!(grant_revision),json!(input.user_epoch)]));
        let result = self.database.batch(batch).await?;
        match result
            .last()
            .and_then(|outcome| outcome.rows.first())
            .and_then(|row| row.get("outcome"))
            .and_then(Value::as_str)
        {
            Some("committed") => Ok(Result::Committed),
            Some("expired") => Ok(Result::Expired),
            Some("client") => Ok(Result::ClientUnavailable),
            Some("subject") => Ok(Result::SubjectUnavailable),
            Some("grant") => Ok(Result::GrantUnavailable),
            Some("conflict") => Ok(Result::Conflict),
            _ => Err(AuthorizationPortError::CorruptData),
        }
    }
}

/// Client protocol admission belongs to the shared preparation policy. D1
/// persists its typed result and checks only the shared storage invariant.
pub(super) fn validate_client_capabilities(client: &OAuthClient) -> anyhow::Result<()> {
    anyhow::ensure!(
        client.security_policy.validate().is_ok(),
        "invalid client security policy"
    );
    Ok(())
}
