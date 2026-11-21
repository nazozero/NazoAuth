//! Immutable, bounded image objects stored as D1 chunks. The shared avatar
//! service owns validation and the account's CAS-selected URL is authoritative.
use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::{NOW, UserRow},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::{AvatarContentType, AvatarObject, PublicAccount, TenantId, UserId, ports::*};
use serde::Deserialize;
use serde_json::{Value, json};

const R2_ABANDONED_AFTER_MICROS: i64 = 86_400 * 1_000_000;

pub struct AvatarMutation {
    user: UserId,
    candidate: Option<String>,
    previous: Option<String>,
}
fn storage_error(_: DbError) -> AvatarStorageError {
    AvatarStorageError::Unavailable("D1 avatar storage failed".into())
}
fn valid_version(version: &str) -> bool {
    uuid::Uuid::parse_str(version).is_ok() && version.len() == 36
}

fn validate_candidate(avatar: &AvatarObject) -> Result<(), AvatarStorageError> {
    if !valid_version(&avatar.version) || !(1..=2_097_152).contains(&avatar.bytes.len()) {
        return Err(AvatarStorageError::InvalidState);
    }
    Ok(())
}

impl D1Provider {
    pub async fn retire_d1_avatar(
        &self,
        user: UserId,
        version: &str,
    ) -> Result<(), AvatarStorageError> {
        self.database.query::<Value>(
            "DELETE FROM nazo_avatar_objects WHERE tenant_id=?1 AND user_id=?2 AND version=?3 AND storage='d1'
             AND NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND json_extract(claims,'$.picture')=?4)",
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version),json!(format!("/auth/me/avatar?v={version}"))]
        ).await.map_err(storage_error)?;
        Ok(())
    }

    /// Reserve a catalog entry before writing bytes to object storage. Only a
    /// confirmed R2 write can make it eligible for account CAS publication.
    pub async fn prepare_r2_avatar(
        &self,
        user: UserId,
        avatar: &AvatarObject,
    ) -> Result<(), AvatarStorageError> {
        validate_candidate(avatar)?;
        self.database.query::<Value>(
            &format!("INSERT INTO nazo_avatar_objects(tenant_id,user_id,version,content_type,byte_length,created_at,storage)
                VALUES(?1,?2,?3,?4,?5,{NOW},'r2_pending')"),
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(avatar.version),json!(avatar.content_type.as_str()),json!(avatar.bytes.len())],
        ).await.map_err(storage_error)?;
        Ok(())
    }

    pub async fn publish_r2_avatar(
        &self,
        user: UserId,
        version: &str,
    ) -> Result<(), AvatarStorageError> {
        let rows = self.database.query::<Value>(
            "UPDATE nazo_avatar_objects SET storage='r2_ready' WHERE tenant_id=?1 AND user_id=?2 AND version=?3 AND storage IN ('r2_pending','r2_ready') RETURNING 1",
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version)],
        ).await.map_err(storage_error)?;
        if rows.is_empty() {
            return Err(AvatarStorageError::Conflict);
        }
        Ok(())
    }

    pub async fn r2_avatar_metadata(
        &self,
        user: UserId,
        version: &str,
    ) -> Result<Option<(AvatarContentType, usize)>, AvatarStorageError> {
        if !valid_version(version) {
            return Err(AvatarStorageError::InvalidState);
        }
        #[derive(Deserialize)]
        struct Metadata {
            content_type: String,
            byte_length: usize,
        }
        let rows = self.database.query::<Metadata>(
            "SELECT content_type,byte_length FROM nazo_avatar_objects WHERE tenant_id=?1 AND user_id=?2 AND version=?3 AND storage='r2_ready'",
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version)],
        ).await.map_err(storage_error)?;
        rows.into_iter()
            .next()
            .map(|row| {
                let content_type = AvatarContentType::parse(&row.content_type)
                    .ok_or(AvatarStorageError::InvalidState)?;
                Ok((content_type, row.byte_length))
            })
            .transpose()
    }

    /// Once retired, a version is ineligible for CAS, so an idempotent R2
    /// delete cannot race with a reference being published by another request.
    pub async fn retire_r2_avatar(
        &self,
        user: UserId,
        version: &str,
    ) -> Result<bool, AvatarStorageError> {
        let rows = self.database.query::<Value>(
            "UPDATE nazo_avatar_objects SET storage='r2_retired' WHERE tenant_id=?1 AND user_id=?2 AND version=?3 AND storage<>'d1'
                AND NOT EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND json_extract(claims,'$.picture')=?4) RETURNING 1",
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version),json!(format!("/auth/me/avatar?v={version}"))],
        ).await.map_err(storage_error)?;
        Ok(!rows.is_empty())
    }

    pub async fn forget_retired_r2_avatar(
        &self,
        user: UserId,
        version: &str,
    ) -> Result<(), AvatarStorageError> {
        self.database.query::<Value>(
            "DELETE FROM nazo_avatar_objects WHERE tenant_id=?1 AND user_id=?2 AND version=?3 AND storage='r2_retired'",
            vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version)],
        ).await.map_err(storage_error)?;
        Ok(())
    }

    pub async fn stale_r2_avatars(&self) -> Result<Vec<(UserId, String)>, AvatarStorageError> {
        #[derive(Deserialize)]
        struct Candidate {
            user_id: UserId,
            version: String,
        }
        let rows = self.database.query::<Candidate>(
            &format!("SELECT user_id,version FROM nazo_avatar_objects AS o
                WHERE tenant_id=?1 AND storage<>'d1' AND (storage='r2_retired' OR created_at<={NOW}-{R2_ABANDONED_AFTER_MICROS})
                AND NOT EXISTS(SELECT 1 FROM nazo_users AS u WHERE u.tenant_id=o.tenant_id AND u.id=o.user_id AND json_extract(u.claims,'$.picture')='/auth/me/avatar?v='||o.version)
                LIMIT 16"),
            vec![json!(self.tenant_id)],
        ).await.map_err(storage_error)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.user_id, row.version))
            .collect())
    }
}

impl AvatarRepositoryPort for D1Provider {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant: TenantId,
        user: UserId,
        expected_url: Option<&'a str>,
        expected_revision: i64,
        url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            if !(0..9_007_199_254_740_991).contains(&expected_revision) {
                return Err(RepositoryError::Unavailable);
            }
            let params = vec![
                json!(self.tenant_id),
                json!(user.as_uuid()),
                json!(expected_url),
                json!(expected_revision),
                json!(url),
            ];
            let outcomes = self.database.batch(vec![
                Statement::new(format!("UPDATE nazo_users SET claims=json_set(claims,'$.picture',?5,'$.updated_at',unixepoch()),avatar_revision=avatar_revision+1,updated_at={NOW}
                    WHERE tenant_id=?1 AND id=?2 AND active=1 AND avatar_revision=?4 AND json_extract(claims,'$.picture') IS ?3
                    AND (?5 IS NULL OR EXISTS(SELECT 1 FROM nazo_avatar_objects WHERE tenant_id=?1 AND user_id=?2 AND storage IN ('d1','r2_ready') AND '/auth/me/avatar?v='||version=?5))
                    RETURNING principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at"),params.clone()),
                Statement::new("SELECT principal,claims,epoch,active,mfa_enabled,avatar_revision,created_at,updated_at FROM nazo_users
                    WHERE tenant_id=?1 AND id=?2 AND active=1 AND ?5 IS NOT NULL AND avatar_revision=?4+1 AND json_extract(claims,'$.picture') IS ?5",params),
            ]).await?;
            outcomes
                .iter()
                .find_map(|result| result.rows.first())
                .cloned()
                .map(|row| {
                    serde_json::from_value::<UserRow>(row)
                        .map_err(|_| DbError::CorruptData)?
                        .public_account(tenant, user)
                        .map_err(Into::into)
                })
                .transpose()
        })
    }
}

impl AvatarStoragePort for D1Provider {
    type Mutation = AvatarMutation;
    fn begin_replace<'a>(
        &'a self,
        user: UserId,
        expected: Option<&'a str>,
        avatar: AvatarObject,
    ) -> AvatarStorageFuture<'a, AvatarMutation> {
        Box::pin(async move {
            validate_candidate(&avatar)?;
            if expected == Some(&avatar.version) {
                return Err(AvatarStorageError::InvalidState);
            }
            let mut statements = vec![Statement::new(
                format!(
                    "INSERT INTO nazo_avatar_objects(tenant_id,user_id,version,content_type,byte_length,created_at) VALUES(?1,?2,?3,?4,?5,{NOW})"
                ),
                vec![
                    json!(self.tenant_id),
                    json!(user.as_uuid()),
                    json!(avatar.version),
                    json!(avatar.content_type.as_str()),
                    json!(avatar.bytes.len()),
                ],
            )];
            for (ordinal, bytes) in avatar.bytes.chunks(64 * 1024).enumerate() {
                statements.push(Statement::new("INSERT INTO nazo_avatar_chunks(tenant_id,user_id,version,ordinal,value) VALUES(?1,?2,?3,?4,?5)",
                    vec![json!(self.tenant_id),json!(user.as_uuid()),json!(avatar.version),json!(ordinal),json!(STANDARD.encode(bytes))]));
            }
            self.database
                .batch(statements)
                .await
                .map_err(storage_error)?;
            Ok(AvatarMutation {
                user,
                candidate: Some(avatar.version),
                previous: expected.map(str::to_owned),
            })
        })
    }
    fn begin_delete<'a>(
        &'a self,
        user: UserId,
        expected: Option<&'a str>,
    ) -> AvatarStorageFuture<'a, AvatarMutation> {
        Box::pin(async move {
            Ok(AvatarMutation {
                user,
                candidate: None,
                previous: expected.map(str::to_owned),
            })
        })
    }
    fn commit<'a>(&'a self, mutation: &'a AvatarMutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            if let Some(previous) = &mutation.previous {
                let _ = self.retire_d1_avatar(mutation.user, previous).await;
            }
            Ok(())
        })
    }
    fn rollback<'a>(&'a self, mutation: &'a AvatarMutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            if let Some(candidate) = &mutation.candidate {
                self.retire_d1_avatar(mutation.user, candidate).await?;
            }
            Ok(())
        })
    }
    fn read<'a>(&'a self, user: UserId, version: &'a str) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(async move {
            if !valid_version(version) {
                return Err(AvatarStorageError::InvalidState);
            }
            #[derive(Deserialize)]
            struct Chunk {
                content_type: String,
                byte_length: usize,
                ordinal: usize,
                value: String,
            }
            let rows = self.database.query::<Chunk>(
                "SELECT o.content_type,o.byte_length,c.ordinal,c.value FROM nazo_avatar_objects o JOIN nazo_avatar_chunks c USING(tenant_id,user_id,version)
                 WHERE o.tenant_id=?1 AND o.user_id=?2 AND o.version=?3 ORDER BY c.ordinal",
                vec![json!(self.tenant_id),json!(user.as_uuid()),json!(version)]).await.map_err(storage_error)?;
            let first = rows.first().ok_or(AvatarStorageError::Missing)?;
            let content_type = AvatarContentType::parse(&first.content_type)
                .ok_or(AvatarStorageError::InvalidState)?;
            let length = first.byte_length;
            if length > 2_097_152 {
                return Err(AvatarStorageError::InvalidState);
            }
            let mut bytes = Vec::with_capacity(length);
            for (ordinal, row) in rows.into_iter().enumerate() {
                if row.ordinal != ordinal {
                    return Err(AvatarStorageError::InvalidState);
                }
                let chunk = STANDARD
                    .decode(row.value)
                    .map_err(|_| AvatarStorageError::InvalidState)?;
                if chunk.len() > length.saturating_sub(bytes.len()) {
                    return Err(AvatarStorageError::InvalidState);
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() != length {
                return Err(AvatarStorageError::InvalidState);
            }
            Ok(AvatarObject {
                bytes,
                content_type,
                version: version.into(),
            })
        })
    }
}
