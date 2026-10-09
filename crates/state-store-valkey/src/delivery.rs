use chrono::{DateTime, Utc};
use nazo_identity::{
    UserId,
    ports::{
        DeliveryConsume, DeliveryPublish, DeliveryRecord, DeliveryStage, DeliveryStageResult,
        DeliveryStorePort, RepositoryFuture,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyConnection, command, keys};

const STAGE_SCRIPT: &str = r#"
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
if tonumber(ARGV[2]) <= now_ms then return 'expired' end
local result = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PXAT', ARGV[2])
if result then return 'created' end
return 'existing'
"#;

const PUBLISH_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then return 'missing_or_changed' end
if redis.call('PTTL', KEYS[1]) <= 0 then return 'missing_or_changed' end
redis.call('SET', KEYS[1], ARGV[2], 'XX', 'KEEPTTL')
return 'published'
"#;

/// Private storage metadata is separate from the disclosed payload.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryEnvelope {
    attempt_id: Uuid,
    expires_at: DateTime<Utc>,
    secret_binding: Option<String>,
    value: serde_json::Value,
}

impl DeliveryEnvelope {
    fn encode(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::protocol("invalid client delivery envelope"))
    }

    fn record(self, raw: String) -> DeliveryRecord {
        DeliveryRecord {
            value: self.value,
            opaque_version: raw,
            attempt_id: self.attempt_id,
            expires_at: self.expires_at,
            secret_binding: self.secret_binding,
        }
    }
}

fn decode(raw: &str) -> Result<DeliveryEnvelope, Error> {
    serde_json::from_str(raw).map_err(|_| Error::protocol("malformed client delivery envelope"))
}

fn parse_delivery(raw: String) -> Result<Option<DeliveryRecord>, Error> {
    let envelope = decode(&raw)?;
    if envelope.expires_at <= Utc::now() {
        return Ok(None);
    }
    Ok(Some(envelope.record(raw)))
}

#[derive(Clone, Debug)]
pub struct DeliveryStore {
    connection: ValkeyConnection,
}

impl DeliveryStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }

    async fn stage_record(
        &self,
        user: UserId,
        token: &str,
        stage: DeliveryStage,
    ) -> Result<DeliveryStageResult, Error> {
        if stage.attempt_id.is_nil() || stage.value["delivery_state"] != "staged" {
            return Err(Error::protocol(
                "client delivery must start as an owned unpublished stage",
            ));
        }
        let envelope = DeliveryEnvelope {
            attempt_id: stage.attempt_id,
            expires_at: stage.expires_at,
            secret_binding: stage.secret_binding,
            value: stage.value,
        };
        let raw = envelope.encode()?;
        match command::eval_string(
            &self.connection,
            STAGE_SCRIPT,
            vec![keys::client_delivery(user, token)],
            vec![
                raw.clone(),
                envelope.expires_at.timestamp_millis().to_string(),
            ],
        )
        .await?
        .as_str()
        {
            "created" => Ok(DeliveryStageResult::Created(envelope.record(raw))),
            "existing" => Ok(DeliveryStageResult::Existing),
            "expired" => Ok(DeliveryStageResult::Expired),
            _ => Err(Error::unexpected("unexpected client delivery stage reply")),
        }
    }

    async fn publish_record(
        &self,
        user: UserId,
        token: &str,
        expected: &DeliveryRecord,
        approved_client_id: Uuid,
    ) -> Result<DeliveryPublish, Error> {
        let mut envelope = decode(&expected.opaque_version)?;
        if envelope.value["delivery_state"] != "staged"
            || envelope.expires_at <= Utc::now()
            || envelope.attempt_id != expected.attempt_id
        {
            return Ok(DeliveryPublish::MissingOrChanged);
        }
        envelope.value["delivery_state"] = serde_json::json!("committed");
        envelope.value["approved_client_id"] = serde_json::json!(approved_client_id);
        let raw = envelope.encode()?;
        match command::eval_string(
            &self.connection,
            PUBLISH_SCRIPT,
            vec![keys::client_delivery(user, token)],
            vec![expected.opaque_version.clone(), raw],
        )
        .await?
        .as_str()
        {
            "published" => Ok(DeliveryPublish::Published),
            "missing_or_changed" => Ok(DeliveryPublish::MissingOrChanged),
            _ => Err(Error::unexpected(
                "unexpected client delivery publish reply",
            )),
        }
    }

    async fn load_record(
        &self,
        user: UserId,
        token: &str,
    ) -> Result<Option<DeliveryRecord>, Error> {
        match command::get(&self.connection, keys::client_delivery(user, token)).await? {
            Some(raw) => parse_delivery(raw),
            None => Ok(None),
        }
    }

    async fn load_records(
        &self,
        lookups: &[(UserId, &str)],
    ) -> Result<Vec<Option<DeliveryRecord>>, Error> {
        command::get_many(
            &self.connection,
            lookups
                .iter()
                .map(|(user, token)| keys::client_delivery(*user, token))
                .collect(),
        )
        .await?
        .into_iter()
        .map(|raw| raw.map(parse_delivery).transpose().map(Option::flatten))
        .collect()
    }

    async fn retire_record(
        &self,
        user: UserId,
        token: &str,
        expected: &DeliveryRecord,
    ) -> Result<bool, Error> {
        Ok(command::compare_delete(
            &self.connection,
            keys::client_delivery(user, token),
            &expected.opaque_version,
        )
        .await?
            == command::CompareDelete::Deleted)
    }

    async fn consume_record(
        &self,
        user: UserId,
        token: &str,
        expected: &DeliveryRecord,
    ) -> Result<DeliveryConsume, Error> {
        let envelope = decode(&expected.opaque_version)?;
        if envelope.value["delivery_state"] != "committed" || envelope.expires_at <= Utc::now() {
            return Ok(DeliveryConsume::MissingOrChanged);
        }
        if !self.retire_record(user, token, expected).await? {
            return Ok(DeliveryConsume::MissingOrChanged);
        }
        Ok(DeliveryConsume::Consumed(envelope.value))
    }
}

impl DeliveryStorePort for DeliveryStore {
    fn stage<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult> {
        Box::pin(async move {
            self.stage_record(user, token, stage)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn publish<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        approved_client_id: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish> {
        Box::pin(async move {
            self.publish_record(user, token, expected, approved_client_id)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn load<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        Box::pin(async move {
            self.load_record(user, token)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        Box::pin(async move {
            self.load_records(lookups)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn retire<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.retire_record(user, token, expected)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn consume<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        Box::pin(async move {
            self.consume_record(user, token, expected)
                .await
                .map_err(crate::identity_repository_error)
        })
    }
}
