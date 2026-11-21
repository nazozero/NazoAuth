//! R2 holds immutable bytes. D1 owns their preparation and selected version.
use nazo_identity::{
    AvatarObject, UserId,
    ports::{AvatarStorageError, AvatarStorageFuture, AvatarStoragePort},
};
use nazo_oauth_server_d1::D1Provider;
use uuid::Uuid;
use worker::{
    Bucket,
    send::{SendFuture, SendWrapper},
};

pub(crate) const AVATAR_BUCKET: &str = "NAZO_AVATARS";

pub(crate) struct R2Avatars {
    catalog: D1Provider,
    tenant: Uuid,
    bucket: SendWrapper<Bucket>,
}

pub(crate) struct Mutation {
    user: UserId,
    candidate: Option<String>,
    previous: Option<String>,
}

fn unavailable() -> AvatarStorageError {
    AvatarStorageError::Unavailable("R2 avatar storage failed".into())
}

impl R2Avatars {
    pub(crate) fn new(catalog: D1Provider, tenant: Uuid, bucket: Bucket) -> Self {
        Self {
            catalog,
            tenant,
            bucket: SendWrapper::new(bucket),
        }
    }

    fn key(&self, user: UserId, version: &str) -> String {
        format!("avatars/{}/{}/{version}", self.tenant, user.as_uuid())
    }

    async fn retire(&self, user: UserId, version: &str) -> Result<(), AvatarStorageError> {
        if self.catalog.retire_r2_avatar(user, version).await? {
            self.bucket
                .delete(self.key(user, version))
                .await
                .map_err(|_| unavailable())?;
            return self.catalog.forget_retired_r2_avatar(user, version).await;
        }
        self.catalog.retire_d1_avatar(user, version).await
    }

    pub(crate) async fn clean_up(&self) -> Result<(), AvatarStorageError> {
        let candidates = self.catalog.stale_r2_avatars().await?;
        let mut result = Ok(());
        for (user, version) in candidates {
            if let Err(error) = self.retire(user, &version).await {
                result = Err(error);
            }
        }
        result
    }
}

impl AvatarStoragePort for R2Avatars {
    type Mutation = Mutation;

    fn begin_replace<'a>(
        &'a self,
        user: UserId,
        expected: Option<&'a str>,
        avatar: AvatarObject,
    ) -> AvatarStorageFuture<'a, Mutation> {
        Box::pin(SendFuture::new(async move {
            if expected == Some(&avatar.version) {
                return Err(AvatarStorageError::InvalidState);
            }
            self.catalog.prepare_r2_avatar(user, &avatar).await?;
            let key = self.key(user, &avatar.version);
            self.bucket
                .put(&key, avatar.bytes)
                .execute()
                .await
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            let published = self.catalog.publish_r2_avatar(user, &avatar.version).await;
            if published == Err(AvatarStorageError::Conflict) {
                // A delayed put may finish after reclamation. The retired
                // candidate cannot be selected by account CAS.
                self.bucket.delete(key).await.map_err(|_| unavailable())?;
            }
            published?;
            Ok(Mutation {
                user,
                candidate: Some(avatar.version),
                previous: expected.map(str::to_owned),
            })
        }))
    }

    fn begin_delete<'a>(
        &'a self,
        user: UserId,
        expected: Option<&'a str>,
    ) -> AvatarStorageFuture<'a, Mutation> {
        Box::pin(async move {
            Ok(Mutation {
                user,
                candidate: None,
                previous: expected.map(str::to_owned),
            })
        })
    }

    fn commit<'a>(&'a self, mutation: &'a Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(SendFuture::new(async move {
            if let Some(version) = &mutation.previous
                && self.retire(mutation.user, version).await.is_err()
            {
                // The account CAS already succeeded. Keep the catalog record
                // for reclamation instead of returning a failed mutation.
                worker::console_error!("NazoAuth avatar retirement deferred");
            }
            Ok(())
        }))
    }

    fn rollback<'a>(&'a self, mutation: &'a Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(SendFuture::new(async move {
            if let Some(version) = &mutation.candidate {
                self.retire(mutation.user, version).await?;
            }
            Ok(())
        }))
    }

    fn read<'a>(&'a self, user: UserId, version: &'a str) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(SendFuture::new(async move {
            let Some((content_type, length)) =
                self.catalog.r2_avatar_metadata(user, version).await?
            else {
                // Keep reading previously selected D1 avatars after enabling R2.
                return self.catalog.read(user, version).await;
            };
            let object = self
                .bucket
                .get(self.key(user, version))
                .execute()
                .await
                .map_err(|_| unavailable())?
                .ok_or(AvatarStorageError::Missing)?;
            if object.size() != length as u64 {
                return Err(AvatarStorageError::InvalidState);
            }
            let bytes = object
                .body()
                .ok_or(AvatarStorageError::Missing)?
                .bytes()
                .await
                .map_err(|_| unavailable())?;
            if bytes.len() != length {
                return Err(AvatarStorageError::InvalidState);
            }
            Ok(AvatarObject {
                bytes,
                content_type,
                version: version.into(),
            })
        }))
    }
}
