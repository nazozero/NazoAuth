use std::borrow::Cow;

use jiff::Timestamp;
use nazo_identity::{
    AvatarUploadAuthorization, AvatarUploadClaim, TenantId, UserId,
    ports::{AvatarUploadStatePort, RepositoryError, RepositoryFuture},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, TenantState,
    storage::{deadline, decode, encode, now_ms, set_until},
};

#[derive(Serialize, Deserialize)]
struct Authorization<'a> {
    upload_id: Cow<'a, str>,
    tenant_id: Uuid,
    user_id: Uuid,
    expected_avatar_url: Option<Cow<'a, str>>,
    expected_avatar_revision: i64,
    staging_object_id: Cow<'a, str>,
    expires_at: Timestamp,
}

impl<'a> From<&'a AvatarUploadAuthorization> for Authorization<'a> {
    fn from(value: &'a AvatarUploadAuthorization) -> Self {
        Self {
            upload_id: Cow::Borrowed(&value.upload_id),
            tenant_id: value.tenant_id.as_uuid(),
            user_id: value.user_id.as_uuid(),
            expected_avatar_url: value.expected_avatar_url.as_deref().map(Cow::Borrowed),
            expected_avatar_revision: value.expected_avatar_revision,
            staging_object_id: Cow::Borrowed(&value.staging_object_id),
            expires_at: value.expires_at,
        }
    }
}

impl Authorization<'_> {
    fn into_domain(self) -> Result<AvatarUploadAuthorization, Error> {
        Ok(AvatarUploadAuthorization {
            upload_id: self.upload_id.into_owned(),
            tenant_id: TenantId::new(self.tenant_id).map_err(|_| Error::CorruptData)?,
            user_id: UserId::new(self.user_id).map_err(|_| Error::CorruptData)?,
            expected_avatar_url: self.expected_avatar_url.map(Cow::into_owned),
            expected_avatar_revision: self.expected_avatar_revision,
            staging_object_id: self.staging_object_id.into_owned(),
            expires_at: self.expires_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Candidate<'a> {
    staged_version: Cow<'a, str>,
    final_object_id: Cow<'a, str>,
}

#[derive(Serialize, Deserialize)]
enum Upload<'a> {
    Active {
        authorization: Authorization<'a>,
        generation: u64,
        lease_until: Option<Timestamp>,
        candidate: Option<Candidate<'a>>,
        expires_at_ms: u64,
    },
    Completed {
        user_id: Uuid,
        final_object_id: Cow<'a, str>,
        expires_at_ms: u64,
    },
}

impl Upload<'_> {
    fn matches(&self, user: UserId) -> bool {
        let (owner, expires) = match self {
            Self::Active {
                authorization,
                expires_at_ms,
                ..
            } => (authorization.user_id, *expires_at_ms),
            Self::Completed {
                user_id,
                expires_at_ms,
                ..
            } => (*user_id, *expires_at_ms),
        };
        owner == user.as_uuid() && expires > now_ms()
    }
}

fn owns_lease(generation: u64, lease_until: Option<Timestamp>, token: &str) -> bool {
    generation.to_string() == token && lease_until.is_some_and(|until| until > Timestamp::now())
}

impl AvatarUploadStatePort for TenantState {
    fn create<'a>(
        &'a self,
        authorization: &'a AvatarUploadAuthorization,
        seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            if authorization.tenant_id != self.tenant_id {
                return Err(Error::Unexpected.into());
            }
            let key = self.key("avatar", &[authorization.upload_id.as_bytes()]);
            let expires_at_ms = deadline(seconds)?.min(
                authorization
                    .expires_at
                    .as_millisecond()
                    .try_into()
                    .map_err(|_| Error::Unexpected)?,
            );
            let raw = encode(&Upload::Active {
                authorization: authorization.into(),
                generation: 0,
                lease_until: None,
                candidate: None,
                expires_at_ms,
            })?;
            let created = self.volatile.with_key(&key, |db| -> Result<bool, Error> {
                if expires_at_ms <= now_ms() || db.get(&key)?.is_some() {
                    return Ok(false);
                }
                set_until(db, &key, raw, expires_at_ms);
                Ok(true)
            })?;
            created.then_some(()).ok_or(RepositoryError::Conflict)
        })
    }

    fn claim<'a>(
        &'a self,
        user: UserId,
        id: &'a str,
        lease_until: Timestamp,
    ) -> RepositoryFuture<'a, AvatarUploadClaim> {
        Box::pin(async move {
            let key = self.key("avatar", &[id.as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(AvatarUploadClaim::Missing);
                    };
                    let mut state: Upload<'_> = decode(&raw)?;
                    if !state.matches(user) {
                        return Ok(AvatarUploadClaim::Missing);
                    }
                    match &mut state {
                        Upload::Completed {
                            final_object_id, ..
                        } => {
                            return Ok(AvatarUploadClaim::Completed {
                                final_object_id: final_object_id.to_string(),
                            });
                        }
                        Upload::Active {
                            generation,
                            lease_until: current,
                            ..
                        } => {
                            let now = Timestamp::now();
                            if current.is_some_and(|until| until > now) {
                                return Ok(AvatarUploadClaim::Busy);
                            }
                            if lease_until <= now {
                                return Ok(AvatarUploadClaim::Missing);
                            }
                            *generation = generation.checked_add(1).ok_or(Error::CorruptData)?;
                            *current = Some(lease_until);
                        }
                    }
                    let replacement = encode(&state)?;
                    let Upload::Active {
                        authorization,
                        generation,
                        candidate,
                        expires_at_ms,
                        ..
                    } = state
                    else {
                        unreachable!()
                    };
                    let authorization = authorization.into_domain()?;
                    set_until(db, &key, replacement, expires_at_ms);
                    let ownership_token = generation.to_string();
                    Ok(match candidate {
                        None => AvatarUploadClaim::Pending {
                            authorization,
                            ownership_token,
                        },
                        Some(candidate) => AvatarUploadClaim::Publishing {
                            authorization,
                            ownership_token,
                            staged_version: candidate.staged_version.into_owned(),
                            final_object_id: candidate.final_object_id.into_owned(),
                        },
                    })
                })
                .map_err(Into::into)
        })
    }

    fn record_candidate<'a>(
        &'a self,
        user: UserId,
        id: &'a str,
        token: &'a str,
        version: &'a str,
        final_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let key = self.key("avatar", &[id.as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(false);
                    };
                    let mut state: Upload<'_> = decode(&raw)?;
                    if !state.matches(user) {
                        return Ok(false);
                    }
                    let expires = match &mut state {
                        Upload::Active {
                            generation,
                            lease_until,
                            candidate,
                            expires_at_ms,
                            ..
                        } if owns_lease(*generation, *lease_until, token) => {
                            if let Some(candidate) = candidate {
                                return Ok(candidate.staged_version == version
                                    && candidate.final_object_id == final_id);
                            }
                            *candidate = Some(Candidate {
                                staged_version: Cow::Borrowed(version),
                                final_object_id: Cow::Borrowed(final_id),
                            });
                            *expires_at_ms
                        }
                        _ => return Ok(false),
                    };
                    set_until(db, &key, encode(&state)?, expires);
                    Ok(true)
                })
                .map_err(Into::into)
        })
    }

    fn complete<'a>(
        &'a self,
        user: UserId,
        id: &'a str,
        token: &'a str,
        final_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let key = self.key("avatar", &[id.as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(false);
                    };
                    let state: Upload<'_> = decode(&raw)?;
                    if !state.matches(user) {
                        return Ok(false);
                    }
                    let expires_at_ms = match state {
                        Upload::Completed {
                            final_object_id, ..
                        } => return Ok(final_object_id == final_id),
                        Upload::Active {
                            generation,
                            lease_until,
                            candidate: Some(candidate),
                            expires_at_ms,
                            ..
                        } if owns_lease(generation, lease_until, token)
                            && candidate.final_object_id == final_id =>
                        {
                            expires_at_ms
                        }
                        _ => return Ok(false),
                    };
                    set_until(
                        db,
                        &key,
                        encode(&Upload::Completed {
                            user_id: user.as_uuid(),
                            final_object_id: Cow::Borrowed(final_id),
                            expires_at_ms,
                        })?,
                        expires_at_ms,
                    );
                    Ok(true)
                })
                .map_err(Into::into)
        })
    }

    fn release<'a>(
        &'a self,
        user: UserId,
        id: &'a str,
        token: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let key = self.key("avatar", &[id.as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(false);
                    };
                    let mut state: Upload<'_> = decode(&raw)?;
                    if !state.matches(user) {
                        return Ok(false);
                    }
                    let expires = match &mut state {
                        Upload::Active {
                            generation,
                            lease_until,
                            expires_at_ms,
                            ..
                        } if owns_lease(*generation, *lease_until, token) => {
                            *lease_until = None;
                            *expires_at_ms
                        }
                        _ => return Ok(false),
                    };
                    set_until(db, &key, encode(&state)?, expires);
                    Ok(true)
                })
                .map_err(Into::into)
        })
    }
}
