//! D1 implementations of the existing WebAuthn credential and one-use ceremony ports.
use jiff::Timestamp;
use nazo_identity::{
    PublicAccount, TenantId, UserId,
    passkey::{StoredPasskeyAuthentication, StoredPasskeyRegistration},
    ports::{
        PasskeyAccountRepositoryPort, PasskeyAuthenticationUpdate, PasskeyCeremonyPort,
        PasskeyCredential, PasskeyCredentialSummary, PasskeyRepositoryPort, RepositoryError,
        RepositoryFuture,
    },
};
use nazo_passkey::{CredentialId, PasskeyCredential as WebauthnCredential};
use nazo_persistence::SecurityAuditEvent;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::UserRow,
};

#[derive(Deserialize)]
struct StoredCredential {
    id: Uuid,
    user_id: Uuid,
    credential_id: String,
    credential: String,
    label: String,
    last_used_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    version: String,
}

impl StoredCredential {
    fn domain(self, tenant_id: TenantId) -> Result<PasskeyCredential, DbError> {
        let credential: WebauthnCredential =
            serde_json::from_str(&self.credential).map_err(|_| DbError::CorruptData)?;
        if credential.id.to_b64url() != self.credential_id {
            return Err(DbError::CorruptData);
        }
        Ok(PasskeyCredential {
            id: self.id,
            tenant_id,
            user_id: UserId::new(self.user_id).map_err(|_| DbError::CorruptData)?,
            credential,
            label: self.label,
            last_used_at: self
                .last_used_at
                .map(|value| Timestamp::from_microsecond(value).map_err(|_| DbError::CorruptData))
                .transpose()?,
            created_at: Timestamp::from_microsecond(self.created_at)
                .map_err(|_| DbError::CorruptData)?,
            updated_at: Timestamp::from_microsecond(self.updated_at)
                .map_err(|_| DbError::CorruptData)?,
        })
    }
}

#[derive(Deserialize)]
struct IdentifiedUser {
    id: Uuid,
    #[serde(flatten)]
    row: UserRow,
}

#[derive(Deserialize)]
struct KeyRow {
    credential_id: String,
}

#[derive(Deserialize)]
struct StateRow {
    value: String,
}

#[derive(Deserialize)]
struct Present {
    #[serde(rename = "applied")]
    _applied: i64,
}

impl D1Provider {
    async fn user_passkeys(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<PasskeyCredential>, RepositoryError> {
        self.require_tenant(tenant_id.as_uuid())?;
        self.database
            .query::<StoredCredential>(
                "SELECT id,user_id,credential_id,credential,label,last_used_at,created_at,updated_at,version FROM nazo_passkeys WHERE tenant_id=?1 AND user_id=?2 ORDER BY created_at,id",
                vec![json!(self.tenant_id), json!(user_id)],
            )
            .await?
            .into_iter()
            .map(|row| row.domain(tenant_id).map_err(Into::into))
            .collect()
    }

    async fn ceremony_store<T: serde::Serialize + ?Sized>(
        &self,
        kind: &str,
        id: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), RepositoryError> {
        let ttl = i64::try_from(ttl_seconds)
            .ok()
            .filter(|ttl| (1..=300).contains(ttl))
            .ok_or(DbError::CorruptData)?;
        let content = serde_json::to_string(value).map_err(|_| DbError::CorruptData)?;
        let result = self
            .database
            .query::<Present>(
                "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,?4,?5,unixepoch()+?6) ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at WHERE nazo_state.expires_at<=unixepoch() RETURNING 1 AS applied",
                vec![json!(self.tenant_id), json!(kind), json!(id), json!(content), json!(Uuid::new_v4()), json!(ttl)],
            )
            .await?;
        if result.is_empty() {
            Err(RepositoryError::Conflict)
        } else {
            Ok(())
        }
    }

    async fn ceremony_take<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<T>, RepositoryError> {
        let rows: Vec<StateRow> = self
            .database
            .query(
                "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND expires_at>unixepoch() RETURNING value",
                vec![json!(self.tenant_id), json!(kind), json!(id)],
            )
            .await?;
        rows.into_iter()
            .next()
            .map(|row| serde_json::from_str(&row.value).map_err(|_| DbError::CorruptData.into()))
            .transpose()
    }

    fn passkey_audit(&self, event: &str, user: UserId, id: Uuid) -> SecurityAuditEvent {
        SecurityAuditEvent {
            event_id: Uuid::new_v4(),
            event_type: event.into(),
            event_category: "authentication".into(),
            occurred_at: Timestamp::now(),
            payload: json!({
                "schema_version": nazo_persistence::SECURITY_AUDIT_SCHEMA_VERSION,
                "event_category": "authentication",
                "tenant_id": self.tenant_id,
                "user_id": user.as_uuid(),
                "credential_id": id,
            }),
        }
    }

    fn conditional_audit(
        &self,
        event: &SecurityAuditEvent,
        credential_id: Uuid,
    ) -> Result<Statement, RepositoryError> {
        if !nazo_persistence::security_audit_payload_within_limit(&event.payload) {
            return Err(RepositoryError::Consistency(
                "security audit exceeds its size bound".into(),
            ));
        }
        Ok(Statement::new(
            "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,?3,?4,?5,?6 FROM nazo_passkeys WHERE tenant_id=?1 AND id=?7",
            vec![
                json!(self.tenant_id),
                json!(event.event_id),
                json!(event.event_type),
                json!(event.event_category),
                json!(event.occurred_at.as_microsecond()),
                json!(serde_json::to_string(&event.payload).map_err(|_| DbError::CorruptData)?),
                json!(credential_id),
            ],
        ))
    }
}

impl PasskeyAccountRepositoryPort for D1Provider {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.database
                .query::<IdentifiedUser>(
                    "SELECT id,principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users WHERE tenant_id=?1 AND email=?2 AND active=1",
                    vec![json!(self.tenant_id), json!(email)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| {
                    let user_id = UserId::new(row.id).map_err(|_| DbError::CorruptData)?;
                    row.row.public_account(tenant_id, user_id)
                })
                .transpose()
                .map_err(Into::into)
        })
    }

    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.user_row(user_id.as_uuid())
                .await?
                .map(|row| row.public_account(tenant_id, user_id))
                .transpose()
                .map_err(Into::into)
        })
    }
}

impl PasskeyRepositoryPort for D1Provider {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredential>> {
        Box::pin(self.user_passkeys(tenant_id, user_id))
    }

    fn list_summaries(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredentialSummary>> {
        Box::pin(async move {
            Ok(self
                .user_passkeys(tenant_id, user_id)
                .await?
                .into_iter()
                .map(PasskeyCredentialSummary::from)
                .collect())
        })
    }

    fn credential_ids(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<CredentialId>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.database
                .query::<KeyRow>(
                    "SELECT credential_id FROM nazo_passkeys WHERE tenant_id=?1 AND user_id=?2 ORDER BY created_at,id",
                    vec![json!(self.tenant_id), json!(user_id)],
                )
                .await?
                .into_iter()
                .map(|row| {
                    CredentialId::from_b64url(&row.credential_id)
                        .map_err(|_| DbError::CorruptData.into())
                })
                .collect()
        })
    }

    fn by_credential_id<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
    ) -> RepositoryFuture<'a, Option<PasskeyCredential>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.database
                .query::<StoredCredential>(
                    "SELECT id,user_id,credential_id,credential,label,last_used_at,created_at,updated_at,version FROM nazo_passkeys WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3",
                    vec![json!(self.tenant_id), json!(user_id), json!(credential_id)],
                )
                .await?
                .into_iter()
                .next()
                .map(|row| row.domain(tenant_id).map_err(Into::into))
                .transpose()
        })
    }

    fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential: WebauthnCredential,
        label: String,
    ) -> RepositoryFuture<'_, PasskeyCredential> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let now = Timestamp::now();
            let id = Uuid::new_v4();
            let version = Uuid::new_v4();
            let credential_id = credential.id.to_b64url();
            let encoded = serde_json::to_string(&credential).map_err(|_| DbError::CorruptData)?;
            let event = self.passkey_audit("passkey_registered", user_id, id);
            let statements = vec![
                Statement::new(
                    "INSERT INTO nazo_passkeys(tenant_id,id,user_id,credential_id,credential,label,created_at,updated_at,version) SELECT ?1,?2,?3,?4,?5,?6,?7,?7,?8 WHERE EXISTS (SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?3 AND active=1) ON CONFLICT DO NOTHING RETURNING 1 AS applied",
                    vec![
                        json!(self.tenant_id),
                        json!(id),
                        json!(user_id),
                        json!(credential_id),
                        json!(encoded),
                        json!(label),
                        json!(now.as_microsecond()),
                        json!(version),
                    ],
                ),
                self.conditional_audit(&event, id)?,
            ];
            let results = self.database.batch(statements).await?;
            if results[0].rows.is_empty() {
                return Err(RepositoryError::Conflict);
            }
            Ok(PasskeyCredential {
                id,
                tenant_id,
                user_id,
                credential,
                label,
                last_used_at: None,
                created_at: now,
                updated_at: now,
            })
        })
    }

    fn update_authentication<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
        update: PasskeyAuthenticationUpdate,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let row = self.database.query::<StoredCredential>(
                "SELECT id,user_id,credential_id,credential,label,last_used_at,created_at,updated_at,version FROM nazo_passkeys WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3",
                vec![json!(self.tenant_id),json!(user_id),json!(credential_id)],
            ).await?.into_iter().next().ok_or(RepositoryError::Conflict)?;
            let mut credential: WebauthnCredential =
                serde_json::from_str(&row.credential).map_err(|_| DbError::CorruptData)?;
            let facts = update.credential;
            if credential.id.to_b64url() != row.credential_id
                || credential.counter != facts.expected_counter
                || credential.backup_eligible != facts.expected_backup_eligible
                || credential.backup_state != facts.expected_backup_state
                || credential
                    .backup_eligible
                    .is_some_and(|v| v != facts.backup_eligible)
            {
                return Err(RepositoryError::Conflict);
            }
            credential.counter = facts.new_counter;
            credential.backup_eligible = Some(facts.backup_eligible);
            credential.backup_state = Some(facts.backup_state);
            if update.initialize_user_verification {
                credential.uv_initialized = Some(true);
            }
            let modified = serde_json::to_string(&credential).map_err(|_| DbError::CorruptData)?;
            let result = self.database.query::<Present>(
                "UPDATE nazo_passkeys SET credential=?4,version=?5,last_used_at=?6,updated_at=?6 WHERE tenant_id=?1 AND user_id=?2 AND credential_id=?3 AND version=?7 AND EXISTS (SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1) RETURNING 1 AS applied",
                vec![
                    json!(self.tenant_id), json!(user_id), json!(credential_id), json!(modified),
                    json!(Uuid::new_v4()), json!(Timestamp::now().as_microsecond()), json!(row.version),
                ],
            ).await?;
            if result.len() == 1 {
                Ok(())
            } else {
                Err(RepositoryError::Conflict)
            }
        })
    }

    fn delete(&self, tenant_id: TenantId, user_id: UserId, id: Uuid) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let event = self.passkey_audit("passkey_deleted", user_id, id);
            let results = self.database.batch(vec![
                Statement::new(
                    "INSERT INTO nazo_audit(tenant_id,event_id,event_type,category,occurred_at,payload) SELECT ?1,?2,?3,?4,?5,?6 FROM nazo_passkeys WHERE tenant_id=?1 AND id=?7 AND user_id=?8",
                    vec![
                        json!(self.tenant_id), json!(event.event_id), json!(event.event_type),
                        json!(event.event_category), json!(event.occurred_at.as_microsecond()),
                        json!(serde_json::to_string(&event.payload).map_err(|_| DbError::CorruptData)?),
                        json!(id), json!(user_id),
                    ],
                ),
                Statement::new(
                    "DELETE FROM nazo_passkeys WHERE tenant_id=?1 AND id=?2 AND user_id=?3 RETURNING 1 AS applied",
                    vec![json!(self.tenant_id), json!(id), json!(user_id)],
                ),
            ]).await?;
            Ok(!results[1].rows.is_empty())
        })
    }
}

impl PasskeyCeremonyPort for D1Provider {
    fn store_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a StoredPasskeyRegistration,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(self.ceremony_store("passkey_registration", ceremony_id, ceremony, ttl_seconds))
    }

    fn take_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<StoredPasskeyRegistration>> {
        Box::pin(self.ceremony_take("passkey_registration", ceremony_id))
    }

    fn store_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a StoredPasskeyAuthentication,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(self.ceremony_store("passkey_authentication", ceremony_id, ceremony, ttl_seconds))
    }

    fn take_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<StoredPasskeyAuthentication>> {
        Box::pin(self.ceremony_take("passkey_authentication", ceremony_id))
    }
}
