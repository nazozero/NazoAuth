use std::borrow::Cow;

use nazo_identity::{UserId, session::SessionRecord};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyConnection, command, keys};

const ROTATE_SESSION_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then
  return 'conflict'
end
if redis.call('EXISTS', KEYS[2]) == 1 then
  return 'collision'
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('DEL', KEYS[1])
return 'ok'
"#;

const CREATE_REPLACING_SESSION_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 'collision'
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
if #KEYS == 2 and KEYS[1] ~= KEYS[2] then
  redis.call('DEL', KEYS[2])
end
return 'created'
"#;

const COMPARE_AND_SET_SESSION_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  return 'missing'
end
if current ~= ARGV[1] then
  return 'conflict'
end
redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
return 'ok'
"#;

#[derive(Deserialize, Serialize)]
struct SessionWireRecord<'a> {
    user_id: Uuid,
    authorization_epoch: i64,
    auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_time_micros: Option<i64>,
    amr: Cow<'a, [String]>,
    pending_mfa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oidc_sid: Option<Cow<'a, str>>,
    #[serde(default, skip_serializing_if = "<[String]>::is_empty")]
    logged_in_client_ids: Cow<'a, [String]>,
}

impl<'a> From<&'a SessionRecord> for SessionWireRecord<'a> {
    fn from(value: &'a SessionRecord) -> Self {
        Self {
            user_id: value.user_id().as_uuid(),
            authorization_epoch: value.authorization_epoch(),
            auth_time: value.auth_time(),
            auth_time_micros: value.auth_time_micros(),
            amr: Cow::Borrowed(value.amr()),
            pending_mfa: value.pending_mfa(),
            oidc_sid: value.oidc_sid().map(Cow::Borrowed),
            logged_in_client_ids: Cow::Borrowed(value.logged_in_client_ids()),
        }
    }
}

impl TryFrom<SessionWireRecord<'_>> for SessionRecord {
    type Error = Error;

    fn try_from(value: SessionWireRecord<'_>) -> Result<Self, Self::Error> {
        let user_id = UserId::new(value.user_id).map_err(|error| {
            Error::corrupt_data(format!("invalid stored session user: {error}"))
        })?;
        let mut record = Self::new(
            user_id,
            value.authorization_epoch,
            value.auth_time,
            value.amr.into_owned(),
            value.pending_mfa,
            value.oidc_sid.map(Cow::into_owned),
        );
        if !record.restore_auth_time_micros(value.auth_time_micros) {
            return Err(Error::corrupt_data(
                "inconsistent stored authentication precision",
            ));
        }
        for client_id in value.logged_in_client_ids.into_owned() {
            record.add_logged_in_client(client_id);
        }
        Ok(record)
    }
}

#[derive(Clone, Debug)]
pub struct StoredSession {
    value: SessionRecord,
    raw: String,
}

impl StoredSession {
    pub fn value(&self) -> &SessionRecord {
        &self.value
    }
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    connection: ValkeyConnection,
}

impl SessionStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn store(
        &self,
        session_id: &str,
        record: &SessionRecord,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
            Error::protocol(format!("failed to serialize session record: {error}"))
        })?;
        command::set_ex(
            &self.connection,
            keys::session(session_id),
            raw,
            ttl_seconds,
        )
        .await
    }

    pub async fn load(&self, session_id: &str) -> Result<Option<StoredSession>, Error> {
        command::get(&self.connection, keys::session(session_id))
            .await?
            .map(|raw| {
                let wire: SessionWireRecord = serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed stored session payload: {error}"))
                })?;
                Ok(StoredSession {
                    value: wire.try_into()?,
                    raw,
                })
            })
            .transpose()
    }

    pub async fn delete(&self, session_id: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::session(session_id)).await
    }
}

impl nazo_identity::ports::LoginSessionPort for SessionStore {
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::LoginSessionCreate> {
        Box::pin(async move {
            let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "failed to serialize session record: {error}"
                ))
            })?;
            command::set_ex_nx(
                &self.connection,
                keys::session(session_id),
                raw,
                ttl_seconds,
            )
            .await
            .map(|created| {
                if created {
                    nazo_identity::ports::LoginSessionCreate::Created
                } else {
                    nazo_identity::ports::LoginSessionCreate::Collision
                }
            })
            .map_err(crate::identity_repository_error)
        })
    }

    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::LoginSessionCreate> {
        Box::pin(async move {
            let raw = serde_json::to_string(&SessionWireRecord::from(record)).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "failed to serialize session record: {error}"
                ))
            })?;
            let mut keys = vec![keys::session(session_id)];
            if let Some(previous_session_id) = previous_session_id {
                keys.push(keys::session(previous_session_id));
            }
            let reply = command::eval_string(
                &self.connection,
                CREATE_REPLACING_SESSION_SCRIPT,
                keys,
                vec![raw, ttl_seconds.to_string()],
            )
            .await
            .map_err(crate::identity_repository_error)?;
            match reply.as_str() {
                "created" => Ok(nazo_identity::ports::LoginSessionCreate::Created),
                "collision" => Ok(nazo_identity::ports::LoginSessionCreate::Collision),
                other => Err(nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "unexpected login session create reply {other:?}"
                ))),
            }
        })
    }
}

impl nazo_identity::ports::SessionStorePort for SessionStore {
    fn load<'a>(
        &'a self,
        session_id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::SessionSnapshot>> {
        Box::pin(async move {
            SessionStore::load(self, session_id.as_str())
                .await
                .map(|stored| {
                    stored.map(|stored| {
                        nazo_identity::SessionSnapshot::new(
                            stored.value,
                            nazo_identity::SessionVersion::from_storage(
                                stored.raw.into_bytes().into_boxed_slice(),
                            ),
                        )
                    })
                })
                .map_err(crate::identity_repository_error)
        })
    }

    fn delete<'a>(
        &'a self,
        session_id: &'a nazo_identity::SessionId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            SessionStore::delete(self, session_id.as_str())
                .await
                .map(|deleted| deleted > 0)
                .map_err(crate::identity_repository_error)
        })
    }

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a nazo_identity::SessionId,
        expected: &'a nazo_identity::SessionVersion,
        new_session_id: &'a nazo_identity::SessionId,
        replacement: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::SessionRotationOutcome> {
        Box::pin(async move {
            let replacement = serde_json::to_string(&SessionWireRecord::from(replacement))
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Unexpected(format!(
                        "failed to serialize replacement session: {error}"
                    ))
                })?;
            let reply = command::eval_string(
                &self.connection,
                ROTATE_SESSION_SCRIPT,
                vec![
                    keys::session(old_session_id.as_str()),
                    keys::session(new_session_id.as_str()),
                ],
                vec![
                    expected.storage_bytes().to_vec(),
                    replacement.into_bytes(),
                    ttl_seconds.to_string().into_bytes(),
                ],
            )
            .await
            .map_err(crate::identity_repository_error)?;
            match reply.as_str() {
                "ok" => Ok(nazo_identity::SessionRotationOutcome::Applied),
                "conflict" => Ok(nazo_identity::SessionRotationOutcome::Conflict),
                "collision" => Ok(nazo_identity::SessionRotationOutcome::Collision),
                other => Err(nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "unexpected session rotation reply {other:?}"
                ))),
            }
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        session_id: &'a nazo_identity::SessionId,
        expected: &'a nazo_identity::SessionVersion,
        replacement: &'a SessionRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::SessionUpdateOutcome> {
        Box::pin(async move {
            let replacement = serde_json::to_string(&SessionWireRecord::from(replacement))
                .map_err(|error| {
                    nazo_identity::ports::RepositoryError::Unexpected(format!(
                        "failed to serialize replacement session: {error}"
                    ))
                })?;
            let reply = command::eval_string(
                &self.connection,
                COMPARE_AND_SET_SESSION_SCRIPT,
                vec![keys::session(session_id.as_str())],
                vec![expected.storage_bytes().to_vec(), replacement.into_bytes()],
            )
            .await
            .map_err(crate::identity_repository_error)?;
            match reply.as_str() {
                "ok" => Ok(nazo_identity::SessionUpdateOutcome::Applied),
                "conflict" => Ok(nazo_identity::SessionUpdateOutcome::Conflict),
                "missing" => Ok(nazo_identity::SessionUpdateOutcome::Missing),
                other => Err(nazo_identity::ports::RepositoryError::Unexpected(format!(
                    "unexpected session compare-and-set reply {other:?}"
                ))),
            }
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/session.rs"]
mod tests;
