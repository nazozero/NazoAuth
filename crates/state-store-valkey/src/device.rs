use fred::prelude::LuaInterface;
use nazo_auth::DeviceAuthorizationState;
use nazo_auth::{
    DeviceAtomicResult, DeviceCreateResult, DeviceStatePortError, DeviceStateReplacement,
    DeviceStateStorePort, DeviceStateVersion, StoredDeviceAuthorization,
};

use crate::{Error, ValkeyConnection, command, keys};

const CREATE_DEVICE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return 'device_collision' end
if redis.call('EXISTS', KEYS[2]) == 1 then return 'user_collision' end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return 'applied'
"#;
const SNAPSHOT_DEVICE_SCRIPT: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then return false end
return {value, redis.call('PEXPIRETIME', KEYS[1])}
"#;
const COMPARE_SET_DEVICE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
if #KEYS == 2 and redis.call('GET', KEYS[2]) ~= ARGV[3] then return 'conflict' end
local deadline = redis.call('PEXPIRETIME', KEYS[1])
if deadline == -2 then return 'deadline_elapsed' end
if deadline == -1 then return 'invalid_deadline' end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now >= deadline then redis.call('DEL', KEYS[1]); return 'deadline_elapsed' end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], deadline)
return 'applied'
"#;
const COMPLETE_DEVICE_DECISION_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'conflict' end
if redis.call('GET', KEYS[2]) ~= ARGV[3] then return 'conflict' end
local deadline = redis.call('PEXPIRETIME', KEYS[1])
if deadline == -2 then redis.call('DEL', KEYS[2]); return 'deadline_elapsed' end
if deadline == -1 then return 'invalid_deadline' end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if now >= deadline then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
  return 'deadline_elapsed'
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('PEXPIREAT', KEYS[1], deadline)
redis.call('DEL', KEYS[2])
return 'applied'
"#;
const DELETE_USER_CODE_IF_MATCHES_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 'conflict' end
redis.call('DEL', KEYS[1])
return 'applied'
"#;

#[derive(Clone, Debug)]
pub struct DeviceStore {
    connection: ValkeyConnection,
}
impl DeviceStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    pub async fn create(
        &self,
        device_code: &str,
        user_code: &str,
        state: &DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> Result<DeviceCreateResult, Error> {
        let raw = serialize_state(state)?;
        let device_hash = blake3::hash(device_code.as_bytes()).to_hex().to_string();
        let reply = command::eval_string(
            &self.connection,
            CREATE_DEVICE_SCRIPT,
            vec![
                keys::device_code_hash(&device_hash),
                keys::device_user_code(user_code),
            ],
            vec![raw, device_hash, ttl_seconds.to_string()],
        )
        .await?;
        match reply.as_str() {
            "applied" => Ok(DeviceCreateResult::Applied),
            "device_collision" => Ok(DeviceCreateResult::DeviceCodeCollision),
            "user_collision" => Ok(DeviceCreateResult::UserCodeCollision),
            other => Err(Error::unexpected(format!(
                "unexpected device create result {other:?}"
            ))),
        }
    }

    pub async fn load_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.load_snapshot(keys::device_code(device_code))
            .await
            .map(|stored| stored.map(StoredDeviceAuthorization::into_state))
    }
    pub async fn load_by_device_hash(
        &self,
        device_hash: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.load_snapshot(keys::device_code_hash(device_hash))
            .await
            .map(|stored| stored.map(StoredDeviceAuthorization::into_state))
    }
    pub async fn resolve_user_code(&self, user_code: &str) -> Result<Option<String>, Error> {
        command::get(&self.connection, keys::device_user_code(user_code)).await
    }
    async fn load_snapshot(
        &self,
        key: String,
    ) -> Result<Option<StoredDeviceAuthorization<DeviceStateVersion>>, Error> {
        let snapshot: Option<(String, i64)> = self
            .connection
            .client
            .eval(
                SNAPSHOT_DEVICE_SCRIPT,
                self.connection.state_keys(vec![key]),
                Vec::<String>::new(),
            )
            .await
            .map_err(Error::from_fred)?;
        let Some((raw, deadline)) = snapshot else {
            return Ok(None);
        };
        if deadline == -2 {
            return Ok(None);
        }
        if deadline == -1 {
            return Err(Error::protocol("device state has no absolute expiry"));
        }
        let value = serde_json::from_str(&raw)
            .map_err(|error| Error::protocol(format!("malformed device state: {error}")))?;
        Ok(Some(StoredDeviceAuthorization::new(
            value,
            DeviceStateVersion::new(raw),
        )))
    }
    async fn replace_snapshot(
        &self,
        key: String,
        expected: &DeviceStateVersion,
        replacement: String,
        user_code_mapping: Option<(&str, &str)>,
    ) -> Result<DeviceAtomicResult, Error> {
        let mut keys = vec![key];
        let mut arguments = vec![expected.comparison_token().to_owned(), replacement];
        if let Some((user_code, device_hash)) = user_code_mapping {
            keys.push(keys::device_user_code(user_code));
            arguments.push(device_hash.to_owned());
        }
        let reply =
            command::eval_string(&self.connection, COMPARE_SET_DEVICE_SCRIPT, keys, arguments)
                .await?;
        parse_atomic_result(&reply)
    }

    async fn complete_decision_snapshot(
        &self,
        device_hash: &str,
        user_code: &str,
        expected: &DeviceStateVersion,
        replacement: &DeviceAuthorizationState,
    ) -> Result<DeviceAtomicResult, Error> {
        let replacement = serialize_state(replacement)?;
        let reply = command::eval_string(
            &self.connection,
            COMPLETE_DEVICE_DECISION_SCRIPT,
            vec![
                keys::device_code_hash(device_hash),
                keys::device_user_code(user_code),
            ],
            vec![
                expected.comparison_token().to_owned(),
                replacement,
                device_hash.to_owned(),
            ],
        )
        .await?;
        parse_atomic_result(&reply)
    }
}

impl DeviceStateStorePort for DeviceStore {
    type Version = DeviceStateVersion;

    fn create<'a>(
        &'a self,
        device_code: &'a str,
        user_code: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceCreateResult> {
        Box::pin(async move {
            DeviceStore::create(self, device_code, user_code, state, ttl_seconds)
                .await
                .map_err(port_error)
        })
    }

    fn load_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.load_snapshot(keys::device_code(device_code))
                .await
                .map_err(port_error)
        })
    }

    fn load_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.load_snapshot(keys::device_code_hash(device_hash))
                .await
                .map_err(port_error)
        })
    }

    fn resolve_user_code<'a>(
        &'a self,
        user_code: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, Option<String>> {
        Box::pin(async move {
            DeviceStore::resolve_user_code(self, user_code)
                .await
                .map_err(port_error)
        })
    }

    fn replace_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_snapshot(
                keys::device_code(device_code),
                version,
                serialize_state(replacement).map_err(port_error)?,
                None,
            )
            .await
            .map_err(port_error)
        })
    }

    fn replace_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceStateReplacement<Self::Version>> {
        Box::pin(async move {
            let raw = serialize_state(replacement).map_err(port_error)?;
            let result = self
                .replace_snapshot(
                    keys::device_code_hash(device_hash),
                    version,
                    raw.clone(),
                    None,
                )
                .await
                .map_err(port_error)?;
            Ok(match result {
                DeviceAtomicResult::Applied => {
                    DeviceStateReplacement::Applied(DeviceStateVersion::new(raw))
                }
                DeviceAtomicResult::Conflict => DeviceStateReplacement::Conflict,
                DeviceAtomicResult::DeadlineElapsed => DeviceStateReplacement::DeadlineElapsed,
            })
        })
    }

    fn claim_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.replace_snapshot(
                keys::device_code_hash(device_hash),
                version,
                serialize_state(replacement).map_err(port_error)?,
                Some((user_code, device_hash)),
            )
            .await
            .map_err(port_error)
        })
    }

    fn complete_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            self.complete_decision_snapshot(device_hash, user_code, version, replacement)
                .await
                .map_err(port_error)
        })
    }

    fn delete_user_code_if_matches<'a>(
        &'a self,
        user_code: &'a str,
        device_hash: &'a str,
    ) -> nazo_auth::DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            command::eval_string(
                &self.connection,
                DELETE_USER_CODE_IF_MATCHES_SCRIPT,
                vec![keys::device_user_code(user_code)],
                vec![device_hash.to_owned()],
            )
            .await
            .map_err(port_error)
            .and_then(|reply| parse_atomic_result(&reply).map_err(port_error))
        })
    }
}

fn serialize_state(state: &DeviceAuthorizationState) -> Result<String, Error> {
    serde_json::to_string(state)
        .map_err(|error| Error::protocol(format!("failed to serialize device state: {error}")))
}

fn parse_atomic_result(reply: &str) -> Result<DeviceAtomicResult, Error> {
    match reply {
        "applied" => Ok(DeviceAtomicResult::Applied),
        "conflict" => Ok(DeviceAtomicResult::Conflict),
        "deadline_elapsed" => Ok(DeviceAtomicResult::DeadlineElapsed),
        "invalid_deadline" => Err(Error::protocol("device state has no absolute expiry")),
        other => Err(Error::unexpected(format!(
            "unexpected device atomic result {other:?}"
        ))),
    }
}

fn port_error(error: Error) -> DeviceStatePortError {
    match error.kind() {
        crate::ErrorKind::Timeout | crate::ErrorKind::Unavailable => {
            DeviceStatePortError::Unavailable
        }
        crate::ErrorKind::Protocol | crate::ErrorKind::CorruptData => {
            DeviceStatePortError::CorruptData
        }
        crate::ErrorKind::UnexpectedResult => DeviceStatePortError::Unexpected,
    }
}
