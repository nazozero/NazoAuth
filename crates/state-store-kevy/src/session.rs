use std::borrow::Cow;

use nazo_identity::{
    SessionId, SessionRotationOutcome, SessionSnapshot, SessionUpdateOutcome, SessionVersion,
    UserId,
    ports::{LoginSessionCreate, LoginSessionPort, RepositoryFuture, SessionStorePort},
    session::{SessionRecord, UpstreamSession},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, TenantState,
    storage::{deadline, decode, encode, now_ms, set_until},
};

#[derive(Serialize, Deserialize)]
struct SessionWire<'a> {
    expires_at_ms: u64,
    user_id: Uuid,
    authorization_epoch: i64,
    auth_time: i64,
    auth_time_micros: Option<i64>,
    amr: Cow<'a, [String]>,
    pending_mfa: bool,
    oidc_sid: Option<Cow<'a, str>>,
    logged_in_client_ids: Cow<'a, [String]>,
    upstream: Option<Cow<'a, UpstreamSession>>,
}

impl<'a> SessionWire<'a> {
    fn new(record: &'a SessionRecord, expires_at_ms: u64) -> Self {
        Self {
            expires_at_ms,
            user_id: record.user_id().as_uuid(),
            authorization_epoch: record.authorization_epoch(),
            auth_time: record.auth_time(),
            auth_time_micros: record.auth_time_micros(),
            amr: Cow::Borrowed(record.amr()),
            pending_mfa: record.pending_mfa(),
            oidc_sid: record.oidc_sid().map(Cow::Borrowed),
            logged_in_client_ids: Cow::Borrowed(record.logged_in_client_ids()),
            upstream: record.upstream().map(Cow::Borrowed),
        }
    }

    fn into_record(self) -> Result<SessionRecord, Error> {
        let mut record = SessionRecord::new(
            UserId::new(self.user_id).map_err(|_| Error::CorruptData)?,
            self.authorization_epoch,
            self.auth_time,
            self.amr.into_owned(),
            self.pending_mfa,
            self.oidc_sid.map(Cow::into_owned),
        );
        if !record.restore_auth_time_micros(self.auth_time_micros) {
            return Err(Error::CorruptData);
        }
        record.set_upstream(self.upstream.map(Cow::into_owned));
        for client in self.logged_in_client_ids.into_owned() {
            record.add_logged_in_client(client);
        }
        Ok(record)
    }
}

#[derive(Serialize, Deserialize)]
struct UpstreamCutoff {
    cutoff: i64,
    expires_at_ms: u64,
}

#[derive(Deserialize)]
struct SessionDeadline {
    expires_at_ms: u64,
}

impl TenantState {
    fn upstream_update(
        &self,
        db: &mut kevy_store::Store,
        scope: &str,
        cutoff: i64,
        retain_until: i64,
    ) -> Result<(Vec<u8>, Vec<u8>, u64), Error> {
        let key = self.key("upstream-session", &[scope.as_bytes()]);
        let previous: Option<UpstreamCutoff> = db.get(&key)?.as_deref().map(decode).transpose()?;
        let expires_at_ms = u64::try_from(retain_until)
            .ok()
            .and_then(|value| value.checked_mul(1_000))
            .ok_or(Error::Unexpected)?;
        let update = UpstreamCutoff {
            cutoff: previous
                .as_ref()
                .map_or(cutoff, |previous| cutoff.max(previous.cutoff)),
            expires_at_ms: previous.as_ref().map_or(expires_at_ms, |previous| {
                expires_at_ms.max(previous.expires_at_ms)
            }),
        };
        Ok((key, encode(&update)?, update.expires_at_ms))
    }

    fn create_session(
        &self,
        previous: Option<&str>,
        id: &str,
        record: &SessionRecord,
        seconds: u64,
    ) -> Result<LoginSessionCreate, Error> {
        let key = self.key("session", &[id.as_bytes()]);
        let previous = previous.map(|id| self.key("session", &[id.as_bytes()]));
        let expires_at_ms = deadline(seconds)?;
        let raw = encode(&SessionWire::new(record, expires_at_ms))?;
        self.volatile.with_key(&key, |db| {
            if db.get(&key)?.is_some() {
                return Ok(LoginSessionCreate::Collision);
            }
            // Prepare both OP scopes before changing any state.
            let updates = record
                .upstream()
                .map(|upstream| {
                    upstream
                        .keys()
                        .map(|scope| self.upstream_update(db, scope, 0, upstream.expires_at))
                        .collect::<Result<Vec<_>, Error>>()
                })
                .transpose()?;
            for (key, raw, deadline) in updates.into_iter().flatten() {
                set_until(db, &key, raw, deadline);
            }
            set_until(db, &key, raw, expires_at_ms);
            if let Some(previous) = previous.filter(|previous| previous != &key) {
                db.del(&[&previous]);
            }
            Ok(LoginSessionCreate::Created)
        })
    }
}

impl LoginSessionPort for TenantState {
    fn create<'a>(
        &'a self,
        id: &'a str,
        record: &'a SessionRecord,
        seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        Box::pin(async move {
            self.create_session(None, id, record, seconds)
                .map_err(Into::into)
        })
    }

    fn create_replacing<'a>(
        &'a self,
        previous: Option<&'a str>,
        id: &'a str,
        record: &'a SessionRecord,
        seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        Box::pin(async move {
            self.create_session(previous, id, record, seconds)
                .map_err(Into::into)
        })
    }

    fn revoke_upstream<'a>(
        &'a self,
        scope: &'a str,
        cutoff: i64,
        retain_until: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.volatile
                .with(|db| -> Result<(), Error> {
                    let (key, raw, deadline) =
                        self.upstream_update(db, scope, cutoff, retain_until)?;
                    set_until(db, &key, raw, deadline);
                    Ok(())
                })
                .map_err(Into::into)
        })
    }
}

impl SessionStorePort for TenantState {
    fn load<'a>(&'a self, id: &'a SessionId) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async move {
            let key = self.key("session", &[id.as_str().as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(None);
                    };
                    let wire: SessionWire<'_> = decode(&raw)?;
                    let now = now_ms();
                    if wire.expires_at_ms <= now {
                        return Ok(None);
                    }
                    let version = SessionVersion::from_storage(raw.into_owned().into_boxed_slice());
                    if let Some(upstream) = &wire.upstream {
                        if upstream.expires_at <= (now / 1_000) as i64 {
                            return Ok(None);
                        }
                        for scope in upstream.keys() {
                            let key = self.key("upstream-session", &[scope.as_bytes()]);
                            let Some(raw) = db.get(&key)? else {
                                return Ok(None);
                            };
                            let cutoff: UpstreamCutoff = decode(&raw)?;
                            if cutoff.expires_at_ms <= now || cutoff.cutoff >= upstream.started_at {
                                return Ok(None);
                            }
                        }
                    }
                    Ok(Some(SessionSnapshot::new(wire.into_record()?, version)))
                })
                .map_err(Into::into)
        })
    }

    fn delete<'a>(&'a self, id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let key = self.key("session", &[id.as_str().as_bytes()]);
            Ok(self.volatile.with_key(&key, |db| db.del(&[&key]) == 1))
        })
    }

    fn rotate<'a>(
        &'a self,
        old: &'a SessionId,
        expected: &'a SessionVersion,
        new: &'a SessionId,
        replacement: &'a SessionRecord,
        seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async move {
            let old = self.key("session", &[old.as_str().as_bytes()]);
            let new = self.key("session", &[new.as_str().as_bytes()]);
            let expires_at_ms = deadline(seconds)?;
            let raw = encode(&SessionWire::new(replacement, expires_at_ms))?;
            self.volatile
                .with_key(&old, |db| -> Result<_, Error> {
                    let Some(current) = db.get(&old)? else {
                        return Ok(SessionRotationOutcome::Conflict);
                    };
                    if current.as_ref() != expected.storage_bytes()
                        || decode::<SessionDeadline>(&current)?.expires_at_ms <= now_ms()
                    {
                        return Ok(SessionRotationOutcome::Conflict);
                    }
                    if db.get(&new)?.is_some() {
                        return Ok(SessionRotationOutcome::Collision);
                    }
                    set_until(db, &new, raw, expires_at_ms);
                    db.del(&[&old]);
                    Ok(SessionRotationOutcome::Applied)
                })
                .map_err(Into::into)
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        id: &'a SessionId,
        expected: &'a SessionVersion,
        replacement: &'a SessionRecord,
    ) -> RepositoryFuture<'a, SessionUpdateOutcome> {
        Box::pin(async move {
            let key = self.key("session", &[id.as_str().as_bytes()]);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    let Some(raw) = db.get(&key)? else {
                        return Ok(SessionUpdateOutcome::Missing);
                    };
                    let expires_at_ms = decode::<SessionDeadline>(&raw)?.expires_at_ms;
                    if expires_at_ms <= now_ms() {
                        return Ok(SessionUpdateOutcome::Missing);
                    }
                    if raw.as_ref() != expected.storage_bytes() {
                        return Ok(SessionUpdateOutcome::Conflict);
                    }
                    let raw = encode(&SessionWire::new(replacement, expires_at_ms))?;
                    set_until(db, &key, raw, expires_at_ms);
                    Ok(SessionUpdateOutcome::Applied)
                })
                .map_err(Into::into)
        })
    }
}
