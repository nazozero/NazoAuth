use kevy_store::SetCondition;
use nazo_auth::{
    DeviceAtomicResult, DeviceAuthorizationState, DeviceCreateResult, DeviceStateFuture,
    DeviceStatePortError, DeviceStateReplacement, DeviceStateStorePort, DeviceStateVersion,
    StoredDeviceAuthorization,
};
use serde::{Deserialize, Serialize};

use crate::{
    Error, TenantState,
    storage::{deadline, decode, encode, now_ms, set_until},
};

// The deadline is owned by the original creation, including after the domain
// state becomes Consumed and no longer contains its authorization payload.
#[derive(Deserialize, Serialize)]
struct DeviceRecord<T> {
    expires_at_ms: u64,
    state: T,
}

fn port_error(error: Error) -> DeviceStatePortError {
    match error {
        Error::Unavailable => DeviceStatePortError::Unavailable,
        Error::CorruptData => DeviceStatePortError::CorruptData,
        Error::Unexpected => DeviceStatePortError::Unexpected,
    }
}

impl TenantState {
    fn device_key(&self, hash: &str) -> Vec<u8> {
        self.key("device", &[hash.as_bytes()])
    }

    fn device_snapshot(
        &self,
        hash: &str,
    ) -> Result<Option<StoredDeviceAuthorization<DeviceStateVersion>>, Error> {
        let key = self.device_key(hash);
        self.volatile.with_key(&key, |store| {
            let Some(raw) = store.get(&key)? else {
                return Ok(None);
            };
            let record: DeviceRecord<DeviceAuthorizationState> = decode(&raw)?;
            if now_ms() >= record.expires_at_ms {
                return Ok(None);
            }
            let version = std::str::from_utf8(&raw)
                .map_err(|_| Error::CorruptData)?
                .to_owned();
            Ok(Some(StoredDeviceAuthorization::new(
                record.state,
                DeviceStateVersion::new(version),
            )))
        })
    }

    fn replace_device(
        &self,
        hash: &str,
        version: &DeviceStateVersion,
        replacement: (Vec<u8>, u64),
        user_code: Option<&str>,
        complete: bool,
    ) -> Result<DeviceAtomicResult, Error> {
        let key = self.device_key(hash);
        let user_key = user_code.map(|code| self.key("device_user", &[code.as_bytes()]));
        let (raw, expires_at_ms) = replacement;
        self.volatile.with_key(&key, |store| {
            let Some(current) = store.get(&key)? else {
                return Ok(DeviceAtomicResult::Conflict);
            };
            if current.as_ref() != version.comparison_token().as_bytes() {
                return Ok(DeviceAtomicResult::Conflict);
            }
            if let Some(user_key) = &user_key
                && store.get(user_key)?.as_deref() != Some(hash.as_bytes())
            {
                return Ok(DeviceAtomicResult::Conflict);
            }
            if now_ms() >= expires_at_ms {
                store.del(&[&key]);
                if complete && let Some(user_key) = &user_key {
                    store.del(&[user_key]);
                }
                return Ok(DeviceAtomicResult::DeadlineElapsed);
            }
            set_until(store, &key, raw, expires_at_ms);
            if complete && let Some(user_key) = &user_key {
                store.del(&[user_key]);
            }
            Ok(DeviceAtomicResult::Applied)
        })
    }
}

fn replacement_record(
    version: &DeviceStateVersion,
    state: &DeviceAuthorizationState,
) -> Result<(Vec<u8>, u64), Error> {
    // The old payload is irrelevant to CAS. Read only its expiry metadata.
    #[derive(Deserialize)]
    struct Deadline {
        expires_at_ms: u64,
    }
    let Deadline { expires_at_ms } = decode(version.comparison_token().as_bytes())?;
    Ok((
        encode(&DeviceRecord {
            expires_at_ms,
            state,
        })?,
        expires_at_ms,
    ))
}

impl DeviceStateStorePort for TenantState {
    type Version = DeviceStateVersion;

    fn create<'a>(
        &'a self,
        device_code: &'a str,
        user_code: &'a str,
        state: &'a DeviceAuthorizationState,
        ttl_seconds: u64,
    ) -> DeviceStateFuture<'a, DeviceCreateResult> {
        Box::pin(async move {
            let hash = blake3::hash(device_code.as_bytes()).to_hex();
            let key = self.device_key(hash.as_str());
            let user_key = self.key("device_user", &[user_code.as_bytes()]);
            self.volatile
                .with_key(&key, |store| {
                    if store.exists(&[&key]) != 0 {
                        return Ok(DeviceCreateResult::DeviceCodeCollision);
                    }
                    if store.exists(&[&user_key]) != 0 {
                        return Ok(DeviceCreateResult::UserCodeCollision);
                    }
                    let expires_at_ms = deadline(ttl_seconds)?;
                    let raw = encode(&DeviceRecord {
                        expires_at_ms,
                        state,
                    })?;
                    // All fallible work precedes both writes. The backend uses
                    // one shard, so the mapping and state publish together.
                    set_until(store, &key, raw, expires_at_ms);
                    store.set_slice(&user_key, hash.as_bytes(), None, SetCondition::Always);
                    store.expire_at_unix_ms(&user_key, expires_at_ms);
                    Ok(DeviceCreateResult::Applied)
                })
                .map_err(port_error)
        })
    }

    fn load_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move {
            self.device_snapshot(blake3::hash(device_code.as_bytes()).to_hex().as_str())
                .map_err(port_error)
        })
    }

    fn load_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, Option<StoredDeviceAuthorization<Self::Version>>> {
        Box::pin(async move { self.device_snapshot(device_hash).map_err(port_error) })
    }

    fn resolve_user_code<'a>(
        &'a self,
        user_code: &'a str,
    ) -> DeviceStateFuture<'a, Option<String>> {
        Box::pin(async move {
            let key = self.key("device_user", &[user_code.as_bytes()]);
            self.volatile
                .with_key(&key, |store| {
                    store
                        .get(&key)?
                        .map(|raw| {
                            std::str::from_utf8(&raw)
                                .map(str::to_owned)
                                .map_err(|_| Error::CorruptData)
                        })
                        .transpose()
                })
                .map_err(port_error)
        })
    }

    fn replace_by_device_code<'a>(
        &'a self,
        device_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            let replacement = replacement_record(version, replacement).map_err(port_error)?;
            self.replace_device(
                blake3::hash(device_code.as_bytes()).to_hex().as_str(),
                version,
                replacement,
                None,
                false,
            )
            .map_err(port_error)
        })
    }

    fn replace_by_device_hash<'a>(
        &'a self,
        device_hash: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceStateReplacement<Self::Version>> {
        Box::pin(async move {
            let replacement = replacement_record(version, replacement).map_err(port_error)?;
            let next_version = String::from_utf8(replacement.0.clone())
                .map_err(|_| DeviceStatePortError::Unexpected)?;
            let outcome = self
                .replace_device(device_hash, version, replacement, None, false)
                .map_err(port_error)?;
            Ok(match outcome {
                DeviceAtomicResult::Applied => {
                    DeviceStateReplacement::Applied(DeviceStateVersion::new(next_version))
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
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            let replacement = replacement_record(version, replacement).map_err(port_error)?;
            self.replace_device(device_hash, version, replacement, Some(user_code), false)
                .map_err(port_error)
        })
    }

    fn complete_decision<'a>(
        &'a self,
        device_hash: &'a str,
        user_code: &'a str,
        version: &'a Self::Version,
        replacement: &'a DeviceAuthorizationState,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            let replacement = replacement_record(version, replacement).map_err(port_error)?;
            self.replace_device(device_hash, version, replacement, Some(user_code), true)
                .map_err(port_error)
        })
    }

    fn delete_user_code_if_matches<'a>(
        &'a self,
        user_code: &'a str,
        device_hash: &'a str,
    ) -> DeviceStateFuture<'a, DeviceAtomicResult> {
        Box::pin(async move {
            let key = self.key("device_user", &[user_code.as_bytes()]);
            self.volatile
                .with_key(&key, |store| {
                    if store.get(&key)?.as_deref() != Some(device_hash.as_bytes()) {
                        return Ok(DeviceAtomicResult::Conflict);
                    }
                    store.del(&[&key]);
                    Ok(DeviceAtomicResult::Applied)
                })
                .map_err(port_error)
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/device.rs"]
mod tests;
