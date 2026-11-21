//! Persistence for the shared federation service. Provider verification,
//! identity admission and browser binding generation stay in nazo-identity.
use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow, digest, encode, timestamp},
};
use nazo_identity::{
    OidcFederationState, Principal, PublicAccount, SocialFederationState, TenantId, UserId,
    UserRole,
    ports::{
        FederationLinkRepositoryPort, FederationLinkSummary, FederationLogin,
        FederationLoginRepositoryPort, FederationStatePort, NewFederatedIdentity, RepositoryError,
        RepositoryFuture,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
struct LinkRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    provider_type: String,
    provider_id: String,
    subject: String,
    email: String,
    created_at: i64,
    updated_at: i64,
    last_login_at: Option<i64>,
}
impl LinkRow {
    fn summary(self) -> Result<FederationLinkSummary, RepositoryError> {
        Ok(FederationLinkSummary {
            id: self.id,
            tenant_id: TenantId::new(self.tenant_id).map_err(|_| DbError::CorruptData)?,
            user_id: UserId::new(self.user_id).map_err(|_| DbError::CorruptData)?,
            provider_type: self.provider_type,
            provider_id: self.provider_id,
            subject: self.subject,
            email: self.email,
            created_at: timestamp(self.created_at)?,
            updated_at: timestamp(self.updated_at)?,
            last_login_at: self.last_login_at.map(timestamp).transpose()?,
        })
    }
}
#[derive(Deserialize)]
struct AccountRow {
    id: Uuid,
    #[serde(flatten)]
    user: UserRow,
}
impl AccountRow {
    fn account(self, tenant: TenantId) -> Result<PublicAccount, RepositoryError> {
        Ok(self.user.public_account(
            tenant,
            UserId::new(self.id).map_err(|_| DbError::CorruptData)?,
        )?)
    }
}
const ACCOUNT_BY_LINK: &str = "SELECT u.* FROM nazo_federation_links l JOIN nazo_users u ON u.tenant_id=l.tenant_id AND u.id=l.user_id WHERE l.tenant_id=?1 AND l.provider_type=?2 AND l.provider_id=?3 AND l.subject=?4";
const LINK_FIELDS: &str = "id,tenant_id,user_id,provider_type,provider_id,subject,email,created_at,updated_at,last_login_at";

impl FederationLinkRepositoryPort for D1Provider {
    fn list_summaries(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> RepositoryFuture<'_, Vec<FederationLinkSummary>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            self.database.query::<LinkRow>(&format!("SELECT {LINK_FIELDS} FROM nazo_federation_links WHERE tenant_id=?1 AND user_id=?2 ORDER BY created_at,id"),vec![json!(tenant),json!(user)]).await?.into_iter().map(LinkRow::summary).collect()
        })
    }
    fn delete(
        &self,
        tenant: TenantId,
        user: UserId,
        id: Uuid,
    ) -> RepositoryFuture<'_, Option<FederationLinkSummary>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            let event = Uuid::new_v4();
            let params = vec![json!(tenant), json!(user), json!(id), json!(event)];
            let mut results=self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                    SELECT ?1,?4,'external_identity_unlinked','identity_lifecycle',{NOW},json_object('schema_version','nazo.audit.v1','event_category','identity_lifecycle','tenant_id',?1,'user_id',?2,'link_id',id,'provider_type',provider_type,'provider_id',provider_id)
                    FROM nazo_federation_links WHERE tenant_id=?1 AND user_id=?2 AND id=?3"),params.clone()),
                Statement::new(format!("DELETE FROM nazo_federation_links WHERE tenant_id=?1 AND user_id=?2 AND id=?3 AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4 AND event_type='external_identity_unlinked' AND json_extract(payload,'$.link_id')=?3 AND json_extract(payload,'$.user_id')=?2) RETURNING {LINK_FIELDS}"),params.clone()),
                Statement::new("SELECT CASE WHEN (EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) AND NOT EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND user_id=?2 AND id=?3)) OR (NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?4) AND NOT EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND user_id=?2 AND id=?3)) THEN 1 ELSE json('federation unlink atomicity failure') END AS checked",params),
            ]).await?;
            results.pop();
            results
                .pop()
                .ok_or(RepositoryError::Unavailable)?
                .rows
                .into_iter()
                .next()
                .map(|value| {
                    serde_json::from_value::<LinkRow>(value)
                        .map_err(|_| RepositoryError::from(DbError::CorruptData))?
                        .summary()
                })
                .transpose()
        })
    }
}

impl FederationLoginRepositoryPort for D1Provider {
    fn resolve_existing<'a>(
        &'a self,
        login: &'a FederationLogin,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(login.tenant.tenant_id.as_uuid())?;
            let params = vec![
                json!(self.tenant_id),
                json!(login.provider_type),
                json!(login.provider_id),
                json!(login.subject),
            ];
            let mut update = params.clone();
            update.extend([json!(login.email), json!(encode(&login.claims)?)]);
            let mut results=self.database.batch(vec![
                Statement::new(format!("UPDATE nazo_federation_links SET email=COALESCE(?5,email),claims=?6,updated_at={NOW},last_login_at={NOW} WHERE tenant_id=?1 AND provider_type=?2 AND provider_id=?3 AND subject=?4"),update),
                Statement::new(ACCOUNT_BY_LINK,params),
            ]).await?;
            results
                .pop()
                .ok_or(RepositoryError::Unavailable)?
                .rows
                .into_iter()
                .next()
                .map(|value| {
                    serde_json::from_value::<AccountRow>(value)
                        .map_err(|_| RepositoryError::from(DbError::CorruptData))?
                        .account(login.tenant.tenant_id)
                })
                .transpose()
        })
    }
    fn email_exists<'a>(&'a self, tenant: TenantId, email: &'a str) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            Ok(!self
                .database
                .query::<Value>(
                    "SELECT id FROM nazo_users WHERE tenant_id=?1 AND email=?2",
                    vec![json!(tenant), json!(email)],
                )
                .await?
                .is_empty())
        })
    }
    fn create_federated(
        &self,
        identity: NewFederatedIdentity,
    ) -> RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move {
            let NewFederatedIdentity {
                login,
                email,
                display_name,
                password_hash,
            } = identity;
            let tenant = login.tenant.tenant_id;
            self.require_tenant(tenant.as_uuid())?;
            let user = UserId::new(Uuid::new_v4()).map_err(|_| DbError::CorruptData)?;
            let link = Uuid::new_v4();
            let event = Uuid::new_v4();
            let principal = Principal {
                authorization_epoch: 0,
                user_id: user,
                tenant: login.tenant,
                role: UserRole::User,
                active: true,
            };
            let claims = json!({"subject":user,"preferred_username":email,"email":email,"email_verified":true,"phone_number_verified":false,"name":display_name,"updated_at":jiff::Timestamp::now().as_second()});
            let payload = json!({"schema_version":nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,"event_category":"identity_lifecycle","tenant_id":tenant,"user_id":user,"provider_type":login.provider_type,"provider_id":login.provider_id});
            if !nazo_persistence::security_audit_payload_within_limit(&payload) {
                return Err(RepositoryError::Consistency(
                    "federation audit exceeds its size bound".into(),
                ));
            }
            let params = vec![
                json!(tenant),
                json!(login.provider_type),
                json!(login.provider_id),
                json!(login.subject),
                json!(user),
                json!(email),
                json!(encode(&principal)?),
                json!(encode(&claims)?),
                json!(password_hash.into_persistence_value()),
                json!(link),
                json!(encode(&login.claims)?),
                json!(event),
                json!(encode(&payload)?),
            ];
            let mut results=self.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_users(tenant_id,id,email,principal,claims,password_hash,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at)
                    SELECT ?1,?5,?6,?7,?8,?9,0,1,0,0,{NOW},{NOW} WHERE NOT EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND provider_type=?2 AND provider_id=?3 AND subject=?4)
                    ON CONFLICT(tenant_id,email) DO NOTHING"),params[..9].to_vec()),
                Statement::new(format!("INSERT INTO nazo_federation_links(tenant_id,id,user_id,provider_type,provider_id,subject,email,claims,created_at,updated_at,last_login_at)
                    SELECT ?1,?10,?5,?2,?3,?4,?6,?11,{NOW},{NOW},{NOW} WHERE EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?5)"),params[..11].to_vec()),
                Statement::new(format!("INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload)
                    SELECT ?1,?12,'external_identity_linked','identity_lifecycle',{NOW},?13 WHERE EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND id=?10 AND user_id=?5)"),params.clone()),
                Statement::new("SELECT CASE WHEN
                    (EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?5) AND EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND id=?10 AND user_id=?5 AND provider_type=?2 AND provider_id=?3 AND subject=?4) AND EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?12 AND event_type='external_identity_linked' AND payload=?13))
                    OR (NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?5) AND NOT EXISTS(SELECT 1 FROM nazo_audit WHERE tenant_id=?1 AND event_id=?12) AND (EXISTS(SELECT 1 FROM nazo_federation_links WHERE tenant_id=?1 AND provider_type=?2 AND provider_id=?3 AND subject=?4) OR EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND email=?6)))
                    THEN 1 ELSE json('federation creation atomicity failure') END AS checked",params),
                Statement::new(format!("UPDATE nazo_federation_links SET email=COALESCE(?5,email),claims=?6,updated_at={NOW},last_login_at={NOW} WHERE tenant_id=?1 AND provider_type=?2 AND provider_id=?3 AND subject=?4 AND id<>?7"),vec![json!(tenant),json!(login.provider_type),json!(login.provider_id),json!(login.subject),json!(login.email),json!(encode(&login.claims)?),json!(link)]),
                Statement::new(ACCOUNT_BY_LINK,vec![json!(tenant),json!(login.provider_type),json!(login.provider_id),json!(login.subject)]),
            ]).await?;
            let result = results
                .pop()
                .ok_or(RepositoryError::Unavailable)?
                .rows
                .into_iter()
                .next()
                .ok_or(RepositoryError::Conflict)?;
            serde_json::from_value::<AccountRow>(result)
                .map_err(|_| RepositoryError::from(DbError::CorruptData))?
                .account(tenant)
        })
    }
}

impl D1Provider {
    async fn store_federation<T: Serialize>(
        &self,
        kind: &str,
        state: &str,
        value: &T,
        ttl: u64,
    ) -> Result<(), RepositoryError> {
        let ttl = i64::try_from(ttl)
            .ok()
            .filter(|t| *t > 0)
            .ok_or(DbError::CorruptData)?;
        let rows = self.database.query::<Value>("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,?4,?5,unixepoch()+?6)
            ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at RETURNING 1",vec![json!(self.tenant_id),json!(kind),json!(digest(state)),json!(encode(value)?),json!(Uuid::new_v4()),json!(ttl)]).await?;
        if rows.len() != 1 {
            return Err(DbError::Unavailable.into());
        }
        Ok(())
    }
    async fn take_federation<T: DeserializeOwned>(
        &self,
        kind: &str,
        state: &str,
        browser: &str,
    ) -> Result<Option<T>, RepositoryError> {
        #[derive(Deserialize)]
        struct Raw {
            value: String,
        }
        // A malformed or unbound value must not be deleted. Once an exact
        // browser owns it, remove raw bytes atomically before typed parsing.
        self.database.query::<Raw>("DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch()
            AND CASE WHEN json_valid(value) THEN json_type(value,'$.browser_binding_hash')='text' AND json_extract(value,'$.browser_binding_hash')=?4 ELSE 0 END RETURNING value",vec![json!(self.tenant_id),json!(kind),json!(digest(state)),json!(browser)]).await?.into_iter().next().map(|row|serde_json::from_str(&row.value).map_err(|_|RepositoryError::from(DbError::CorruptData))).transpose()
    }
}
impl FederationStatePort for D1Provider {
    fn store_oidc<'a>(
        &'a self,
        state: &'a str,
        value: &'a OidcFederationState,
        ttl: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.store_federation("federation_oidc", state, value, ttl)
                .await
        })
    }
    fn take_oidc<'a>(
        &'a self,
        state: &'a str,
        browser: &'a str,
    ) -> RepositoryFuture<'a, Option<OidcFederationState>> {
        Box::pin(async move {
            self.take_federation("federation_oidc", state, browser)
                .await
        })
    }
    fn store_social<'a>(
        &'a self,
        state: &'a str,
        value: &'a SocialFederationState,
        ttl: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.store_federation("federation_social", state, value, ttl)
                .await
        })
    }
    fn take_social<'a>(
        &'a self,
        state: &'a str,
        browser: &'a str,
    ) -> RepositoryFuture<'a, Option<SocialFederationState>> {
        Box::pin(async move {
            self.take_federation("federation_social", state, browser)
                .await
        })
    }
    fn reserve_saml_replay<'a>(
        &'a self,
        signature: &'a str,
        ttl: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let ttl = i64::try_from(ttl)
                .ok()
                .filter(|t| *t > 0)
                .ok_or(DbError::CorruptData)?;
            Ok(!self.database.query::<Value>("INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,'federation_saml_replay',?2,'null','',unixepoch()+?3) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING key",vec![json!(self.tenant_id),json!(digest(signature)),json!(ttl)]).await?.is_empty())
        })
    }
}
