use nazo_auth::DeviceAuthorizationState;

use crate::{Error, ValkeyConnection, command, keys};

const CREATE_DEVICE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return 'device_collision' end
if redis.call('EXISTS', KEYS[2]) == 1 then return 'user_collision' end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return 'applied'
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceCreateResult {
    Applied,
    DeviceCodeCollision,
    UserCodeCollision,
}

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
        let raw = serde_json::to_string(state).map_err(|error| {
            Error::protocol(format!("failed to serialize device state: {error}"))
        })?;
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
        self.load_key(keys::device_code(device_code)).await
    }
    pub async fn load_by_device_hash(
        &self,
        device_hash: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.load_key(keys::device_code_hash(device_hash)).await
    }
    pub async fn take_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceAuthorizationState>, Error> {
        self.take_key(keys::device_code(device_code)).await
    }
    pub async fn resolve_user_code(&self, user_code: &str) -> Result<Option<String>, Error> {
        command::get(&self.connection, keys::device_user_code(user_code)).await
    }
    pub async fn delete_user_code(&self, user_code: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::device_user_code(user_code)).await
    }
    pub async fn store_device_hash(
        &self,
        device_hash: &str,
        state: &DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(state).map_err(|error| {
            Error::protocol(format!("failed to serialize device state: {error}"))
        })?;
        command::set_ex_string(
            &self.connection,
            keys::device_code_hash(device_hash),
            raw,
            ttl_seconds,
        )
        .await
    }
    async fn load_key(&self, key: String) -> Result<Option<DeviceAuthorizationState>, Error> {
        command::get(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw)
                    .map_err(|error| Error::protocol(format!("malformed device state: {error}")))
            })
            .transpose()
    }
    async fn take_key(&self, key: String) -> Result<Option<DeviceAuthorizationState>, Error> {
        command::take(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    Error::protocol(format!("malformed consumed device state: {error}"))
                })
            })
            .transpose()
    }
}
