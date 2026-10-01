use chrono::{DateTime, SecondsFormat, Utc};
use nazo_auth::{
    AuthorizationCodeState, AuthorizationStateSnapshot, CodePayload, ConsentPayload,
    DecisionMaterialDiscardError, DecisionMaterialDiscardOutcome, PushedAuthorizationRequest,
};

use crate::{Error, ValkeyConnection, command, keys};

// Preserve the sequential cleanup contract inside one command. A consent
// failure leaves PAR untouched; a PAR failure never restores deleted consent.
// This script does not grant, consume, or compensate durable authority.
const DISCARD_DECISION_MATERIAL_SCRIPT: &str = r#"
local function discard(key, expected)
  local current = redis.pcall('GET', key)
  if type(current) == 'table' and current.err then
    return 'error'
  end
  if not current or current ~= expected then
    return 'missing_or_changed'
  end
  local deleted = redis.pcall('DEL', key)
  if type(deleted) == 'table' and deleted.err then
    return 'error'
  end
  if deleted ~= 1 then
    return 'error'
  end
  return 'discarded'
end
local consent = discard(KEYS[1], ARGV[1])
if consent ~= 'discarded' then
  return 'consent_' .. consent
end
if #KEYS == 2 then
  local par = discard(KEYS[2], ARGV[2])
  if par ~= 'discarded' then
    return 'par_' .. par
  end
end
return 'discarded'
"#;

const BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status == 'pending' then
  if type(state.payload) ~= 'table' then
    return 'malformed'
  end
  state.status = 'consuming'
  state.consuming_at = ARGV[1]
  redis.call('SET', KEYS[1], cjson.encode(state), 'KEEPTTL')
  return 'consuming|' .. cjson.encode(state.payload)
end
if state.status == 'consuming' then
  return 'busy'
end
if state.status == 'consumed' then
  return 'consumed|' .. raw
end
if state.status == 'failed' then
  return 'failed'
end
return 'malformed'
"#;

const MARK_AUTHORIZATION_CODE_SCRIPT: &str = r#"
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
local ok, state = pcall(cjson.decode, raw)
if not ok or type(state) ~= 'table' or type(state.status) ~= 'string' then
  return 'malformed'
end
if state.status ~= 'consuming' then
  return state.status
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 'ok'
"#;

#[derive(Debug)]
pub enum AuthorizationCodeBegin {
    Consuming(CodePayload),
    Busy,
    Consumed(AuthorizationCodeState),
    Failed,
    Missing,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationTransition {
    Applied,
    Missing,
    Malformed,
    Pending,
    Consuming,
    Consumed,
    Failed,
}

/// A completed immutable preparation write may still reject an existing identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum AuthorizationPreparationWrite {
    Stored,
    Conflict,
}

#[derive(Clone, Debug)]
pub struct AuthorizationStore {
    connection: ValkeyConnection,
}

impl AuthorizationStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    /// Stores the initial immutable consent preparation. Even an identical
    /// retry is rejected while the identity exists; changed material requires
    /// a new request ID and cannot extend the original preparation's TTL.
    pub async fn store_consent(
        &self,
        request_id: &str,
        payload: &ConsentPayload,
        ttl_seconds: u64,
    ) -> Result<AuthorizationPreparationWrite, Error> {
        self.store_preparation(keys::consent(request_id), payload, ttl_seconds)
            .await
    }

    pub async fn load_consent(&self, request_id: &str) -> Result<Option<ConsentPayload>, Error> {
        self.load_json(keys::consent(request_id)).await
    }

    pub async fn load_consent_snapshot(
        &self,
        request_id: &str,
    ) -> Result<Option<AuthorizationStateSnapshot<ConsentPayload>>, Error> {
        self.load_snapshot(keys::consent(request_id)).await
    }

    /// Removes transient material only. Deletion is not an authorization
    /// decision, consumption fence, or cancellation of an observed preparation.
    pub async fn take_consent(&self, request_id: &str) -> Result<Option<ConsentPayload>, Error> {
        self.take_json(keys::consent(request_id)).await
    }

    /// Best-effort cleanup after a durable decision; this does not authorize
    /// or cancel a decision, including one already holding a snapshot.
    pub async fn compare_and_delete_consent(
        &self,
        request_id: &str,
        expected: &str,
    ) -> Result<bool, Error> {
        self.compare_delete(keys::consent(request_id), expected)
            .await
    }

    /// One round trip, preserving the raw-version and partial-cleanup contract.
    /// A transport failure has an unknown outcome, even if a key was removed.
    pub async fn discard_decision_material(
        &self,
        request_id: &str,
        expected_consent: &str,
        pushed_request: Option<(&str, &str)>,
    ) -> Result<DecisionMaterialDiscardOutcome, DecisionMaterialDiscardError<Error>> {
        let mut state_keys = vec![keys::consent(request_id)];
        let mut expected_versions = vec![expected_consent.to_owned()];
        if let Some((request_uri, expected)) = pushed_request {
            state_keys.push(keys::par(request_uri));
            expected_versions.push(expected.to_owned());
        }
        let reply = command::eval_string(
            &self.connection,
            DISCARD_DECISION_MATERIAL_SCRIPT,
            state_keys,
            expected_versions,
        )
        .await
        .map_err(DecisionMaterialDiscardError::ConsentOrUnknown)?;
        parse_decision_material_discard_reply(&reply)
    }

    /// Removes transient material only, without revoking durable authority.
    pub async fn delete_consent(&self, request_id: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::consent(request_id)).await
    }

    /// Stores the initial immutable PAR preparation. An existing request URI
    /// cannot be replaced or have its TTL refreshed, even after a preview.
    /// Changed material requires a newly generated request URI.
    pub async fn store_par(
        &self,
        request_uri: &str,
        payload: &PushedAuthorizationRequest,
        ttl_seconds: u64,
    ) -> Result<AuthorizationPreparationWrite, Error> {
        self.store_preparation(keys::par(request_uri), payload, ttl_seconds)
            .await
    }

    pub async fn load_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationStateSnapshot<PushedAuthorizationRequest>>, Error> {
        self.load_snapshot(keys::par(request_uri)).await
    }

    /// Best-effort cleanup after a durable decision, never its consumption
    /// authority or a cancellation mechanism.
    pub async fn compare_and_delete_par(
        &self,
        request_uri: &str,
        expected: &str,
    ) -> Result<bool, Error> {
        self.compare_delete(keys::par(request_uri), expected).await
    }

    pub async fn store_authorization_code_hash(
        &self,
        code_hash: &str,
        state: &AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        self.store_json(keys::authorization_code_hash(code_hash), state, ttl_seconds)
            .await
    }

    pub async fn load_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeState>, Error> {
        self.load_json(keys::authorization_code(code)).await
    }

    pub async fn load_authorization_code_hash(
        &self,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCodeState>, Error> {
        self.load_json(keys::authorization_code_hash(code_hash))
            .await
    }

    pub async fn delete_authorization_code_hash(&self, code_hash: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::authorization_code_hash(code_hash)).await
    }

    pub async fn begin_authorization_code(
        &self,
        code_hash: &str,
        consuming_at: DateTime<Utc>,
    ) -> Result<AuthorizationCodeBegin, Error> {
        let reply = command::eval_string(
            &self.connection,
            BEGIN_AUTHORIZATION_CODE_CONSUMPTION_SCRIPT,
            vec![keys::authorization_code_hash(code_hash)],
            vec![consuming_at.to_rfc3339_opts(SecondsFormat::Millis, true)],
        )
        .await?;
        parse_authorization_code_begin_reply(&reply)
    }

    pub async fn mark_authorization_code(
        &self,
        code_hash: &str,
        replacement: &AuthorizationCodeState,
        ttl_seconds: u64,
    ) -> Result<AuthorizationTransition, Error> {
        let raw = serde_json::to_string(replacement).map_err(|error| {
            Error::protocol(format!("failed to serialize authorization code: {error}"))
        })?;
        let reply = command::eval_string(
            &self.connection,
            MARK_AUTHORIZATION_CODE_SCRIPT,
            vec![keys::authorization_code_hash(code_hash)],
            vec![raw, ttl_seconds.to_string()],
        )
        .await?;
        match reply.as_str() {
            "ok" => Ok(AuthorizationTransition::Applied),
            "missing" => Ok(AuthorizationTransition::Missing),
            "malformed" => Ok(AuthorizationTransition::Malformed),
            "pending" => Ok(AuthorizationTransition::Pending),
            "consuming" => Ok(AuthorizationTransition::Consuming),
            "consumed" => Ok(AuthorizationTransition::Consumed),
            "failed" => Ok(AuthorizationTransition::Failed),
            other => Err(Error::unexpected(format!(
                "unexpected authorization-code transition {other:?}"
            ))),
        }
    }

    pub async fn store_reauth_nonce(
        &self,
        nonce: &str,
        started_at: i64,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        command::set_ex_string(
            &self.connection,
            keys::reauth_nonce(nonce),
            started_at.to_string(),
            ttl_seconds,
        )
        .await
    }

    pub async fn take_reauth_nonce(&self, nonce: &str) -> Result<Option<i64>, Error> {
        command::take(&self.connection, keys::reauth_nonce(nonce))
            .await?
            .map(|raw| {
                raw.parse().map_err(|error| {
                    Error::corrupt_data(format!("malformed reauth timestamp: {error}"))
                })
            })
            .transpose()
    }

    async fn store_preparation<T: serde::Serialize + ?Sized>(
        &self,
        key: String,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<AuthorizationPreparationWrite, Error> {
        let raw = serde_json::to_string(value).map_err(|error| {
            Error::protocol(format!(
                "failed to serialize authorization preparation: {error}"
            ))
        })?;
        if command::set_ex_nx_string(&self.connection, key, raw, ttl_seconds).await? {
            Ok(AuthorizationPreparationWrite::Stored)
        } else {
            Ok(AuthorizationPreparationWrite::Conflict)
        }
    }

    async fn store_json<T: serde::Serialize + ?Sized>(
        &self,
        key: String,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(value).map_err(|error| {
            Error::protocol(format!("failed to serialize authorization state: {error}"))
        })?;
        command::set_ex_string(&self.connection, key, raw, ttl_seconds).await
    }

    async fn load_json<T: serde::de::DeserializeOwned>(
        &self,
        key: String,
    ) -> Result<Option<T>, Error> {
        command::get(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed authorization state: {error}"))
                })
            })
            .transpose()
    }

    async fn load_snapshot<T: serde::de::DeserializeOwned>(
        &self,
        key: String,
    ) -> Result<Option<AuthorizationStateSnapshot<T>>, Error> {
        command::get(&self.connection, key)
            .await?
            .map(|raw| {
                let payload = serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed authorization state: {error}"))
                })?;
                Ok(AuthorizationStateSnapshot {
                    payload,
                    version: raw,
                })
            })
            .transpose()
    }

    async fn take_json<T: serde::de::DeserializeOwned>(
        &self,
        key: String,
    ) -> Result<Option<T>, Error> {
        command::take(&self.connection, key)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    Error::corrupt_data(format!("malformed consumed authorization state: {error}"))
                })
            })
            .transpose()
    }

    async fn compare_delete(&self, key: String, expected: &str) -> Result<bool, Error> {
        command::compare_delete(&self.connection, key, expected)
            .await
            .map(|outcome| matches!(outcome, command::CompareDelete::Deleted))
    }
}

fn parse_decision_material_discard_reply(
    reply: &str,
) -> Result<DecisionMaterialDiscardOutcome, DecisionMaterialDiscardError<Error>> {
    match reply {
        "discarded" => Ok(DecisionMaterialDiscardOutcome::Discarded),
        "consent_missing_or_changed" => {
            Ok(DecisionMaterialDiscardOutcome::ConsentMissingOrChanged)
        }
        "par_missing_or_changed" => Ok(DecisionMaterialDiscardOutcome::ParMissingOrChanged),
        "consent_error" => Err(DecisionMaterialDiscardError::ConsentOrUnknown(
            Error::protocol("consent preparation cleanup failed"),
        )),
        "par_error" => Err(DecisionMaterialDiscardError::PushedRequest(Error::protocol(
            "pushed request preparation cleanup failed",
        ))),
        _ => Err(DecisionMaterialDiscardError::ConsentOrUnknown(
            Error::unexpected("unexpected preparation cleanup reply; outcome is unknown"),
        )),
    }
}

fn parse_authorization_code_begin_reply(reply: &str) -> Result<AuthorizationCodeBegin, Error> {
    if let Some(raw) = reply.strip_prefix("consuming|") {
        return serde_json::from_str(raw)
            .map(AuthorizationCodeBegin::Consuming)
            .map_err(|error| {
                Error::corrupt_data(format!("malformed consuming authorization code: {error}"))
            });
    }
    if let Some(raw) = reply.strip_prefix("consumed|") {
        return serde_json::from_str(raw)
            .map(AuthorizationCodeBegin::Consumed)
            .map_err(|error| {
                Error::corrupt_data(format!("malformed consumed authorization code: {error}"))
            });
    }
    match reply {
        "busy" => Ok(AuthorizationCodeBegin::Busy),
        "failed" => Ok(AuthorizationCodeBegin::Failed),
        "missing" => Ok(AuthorizationCodeBegin::Missing),
        "malformed" => Ok(AuthorizationCodeBegin::Malformed),
        other => Err(Error::unexpected(format!(
            "unexpected authorization-code begin reply {other:?}"
        ))),
    }
}

#[cfg(test)]
#[path = "../tests/unit/authorization.rs"]
mod tests;
