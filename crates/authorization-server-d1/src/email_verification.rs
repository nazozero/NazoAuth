//! Owner-bound verification sends and single-use, attempt-limited challenges.

use crate::{D1Provider, db::DbError, persistence::digest};
use nazo_identity::{
    PasswordHash, TenantId,
    ports::{
        EmailVerificationConsume, EmailVerificationRecord, EmailVerificationStorePort,
        PasswordHashInput, RepositoryError, RepositoryFuture,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

const EMAIL_SEND: &str = "email_send";
const PEER_SEND: &str = "email_peer_send";

fn ttl(seconds: u64) -> Result<i64, RepositoryError> {
    i64::try_from(seconds)
        .ok()
        .filter(|ttl| *ttl > 0)
        .ok_or_else(|| RepositoryError::Consistency("invalid verification lifetime".into()))
}

impl D1Provider {
    async fn reserve_verification_send(
        &self,
        tenant_id: TenantId,
        kind: &str,
        subject: &str,
        owner: &str,
        seconds: u64,
    ) -> Result<bool, RepositoryError> {
        self.require_tenant(tenant_id.as_uuid())?;
        if owner.is_empty() {
            return Err(DbError::CorruptData.into());
        }
        Ok(!self.database.query::<Value>(
            "INSERT INTO nazo_state(tenant_id,kind,key,value,version,expires_at) VALUES(?1,?2,?3,?4,?4,unixepoch()+?5)
             ON CONFLICT(tenant_id,kind,key) DO UPDATE SET value=excluded.value,version=excluded.version,expires_at=excluded.expires_at
             WHERE nazo_state.expires_at<=unixepoch() RETURNING key",
            vec![json!(self.tenant_id),json!(kind),json!(digest(subject)),json!(owner),json!(ttl(seconds)?)],
        ).await?.is_empty())
    }

    async fn release_verification_send(
        &self,
        tenant_id: TenantId,
        kind: &str,
        subject: &str,
        owner: &str,
    ) -> Result<(), RepositoryError> {
        self.require_tenant(tenant_id.as_uuid())?;
        self.database
            .query::<Value>(
                "DELETE FROM nazo_state WHERE tenant_id=?1 AND kind=?2 AND key=?3 AND value=?4",
                vec![
                    json!(self.tenant_id),
                    json!(kind),
                    json!(digest(subject)),
                    json!(owner),
                ],
            )
            .await?;
        Ok(())
    }
}

impl EmailVerificationStorePort for D1Provider {
    fn reserve_peer_send<'a>(
        &'a self,
        tenant_id: TenantId,
        subject: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_verification_send(tenant_id, PEER_SEND, subject, owner, ttl_seconds)
                .await
        })
    }
    fn reserve_email_send<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.reserve_verification_send(tenant_id, EMAIL_SEND, email, owner, ttl_seconds)
                .await
        })
    }
    fn store_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
        password_hash: PasswordHashInput,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let rows=self.database.query::<Value>(
                "INSERT INTO nazo_email_codes(tenant_id,email_hash,owner,verification_hash,version,attempts,expires_at)
                 SELECT ?1,?2,?3,?4,?5,0,unixepoch()+?6
                 WHERE EXISTS(SELECT 1 FROM nazo_state WHERE tenant_id=?1 AND kind='email_send' AND key=?2 AND value=?3 AND expires_at>unixepoch())
                 ON CONFLICT(tenant_id,email_hash) DO UPDATE SET owner=excluded.owner,verification_hash=excluded.verification_hash,version=excluded.version,attempts=0,expires_at=excluded.expires_at RETURNING version",
                vec![json!(self.tenant_id),json!(digest(email)),json!(owner),json!(password_hash.into_persistence_value()),json!(Uuid::new_v4()),json!(ttl(ttl_seconds)?)],
            ).await?;
            if rows.is_empty() {
                Err(RepositoryError::Conflict)
            } else {
                Ok(())
            }
        })
    }
    fn reserve_code_attempt<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        max_attempts: u64,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let limit = i64::try_from(max_attempts).map_err(|_| DbError::CorruptData)?;
            #[derive(Deserialize)]
            struct Record {
                verification_hash: String,
                version: String,
            }
            self.database.query::<Record>(
                "UPDATE nazo_email_codes SET attempts=attempts+1 WHERE tenant_id=?1 AND email_hash=?2 AND expires_at>unixepoch() AND attempts<?3 RETURNING verification_hash,version",
                vec![json!(self.tenant_id),json!(digest(email)),json!(limit)],
            ).await?.pop().map(|row|{
                Ok(EmailVerificationRecord{password_hash:PasswordHash::new(row.verification_hash).map_err(|_|DbError::CorruptData)?,opaque_version:row.version})
            }).transpose()
        })
    }
    fn consume_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        expected_version: &'a str,
    ) -> RepositoryFuture<'a, EmailVerificationConsume> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            let rows=self.database.query::<Value>("DELETE FROM nazo_email_codes WHERE tenant_id=?1 AND email_hash=?2 AND version=?3 AND expires_at>unixepoch() RETURNING version",
                vec![json!(self.tenant_id),json!(digest(email)),json!(expected_version)]).await?;
            Ok(if rows.is_empty() {
                EmailVerificationConsume::MissingOrChanged
            } else {
                EmailVerificationConsume::Consumed
            })
        })
    }
    fn delete_code<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.require_tenant(tenant_id.as_uuid())?;
            self.database.query::<Value>("DELETE FROM nazo_email_codes WHERE tenant_id=?1 AND email_hash=?2 AND owner=?3",
                vec![json!(self.tenant_id),json!(digest(email)),json!(owner)]).await?;
            Ok(())
        })
    }
    fn release_email_send<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.release_verification_send(tenant_id, EMAIL_SEND, email, owner)
                .await
        })
    }
    fn release_peer_send<'a>(
        &'a self,
        tenant_id: TenantId,
        subject: &'a str,
        owner: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.release_verification_send(tenant_id, PEER_SEND, subject, owner)
                .await
        })
    }
}
