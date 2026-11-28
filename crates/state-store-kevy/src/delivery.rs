use jiff::Timestamp;
use nazo_identity::{
    UserId,
    ports::{
        DeliveryConsume, DeliveryPublish, DeliveryRecord, DeliveryStage, DeliveryStageResult,
        DeliveryStorePort, RepositoryFuture,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, TenantState,
    storage::{decode, encode, set_until},
};

#[derive(Serialize, Deserialize)]
struct Envelope {
    attempt_id: Uuid,
    expires_at: Timestamp,
    secret_binding: Option<String>,
    value: serde_json::Value,
}

impl Envelope {
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

fn record(raw: &[u8]) -> Result<Option<DeliveryRecord>, Error> {
    let envelope: Envelope = decode(raw)?;
    if envelope.expires_at <= Timestamp::now() {
        return Ok(None);
    }
    let raw = std::str::from_utf8(raw)
        .map_err(|_| Error::CorruptData)?
        .to_owned();
    Ok(Some(envelope.record(raw)))
}

impl TenantState {
    fn delivery_key(&self, user: UserId, token: &str) -> Vec<u8> {
        self.key("delivery", &[user.as_uuid().as_bytes(), token.as_bytes()])
    }
}

impl DeliveryStorePort for TenantState {
    fn stage<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult> {
        Box::pin(async move {
            if stage.attempt_id.is_nil() || stage.value["delivery_state"] != "staged" {
                return Err(Error::Unexpected.into());
            }
            let key = self.delivery_key(user, token);
            let envelope = Envelope {
                attempt_id: stage.attempt_id,
                expires_at: stage.expires_at,
                secret_binding: stage.secret_binding,
                value: stage.value,
            };
            let raw = String::from_utf8(encode(&envelope)?).map_err(|_| Error::Unexpected)?;
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    if envelope.expires_at <= Timestamp::now() {
                        return Ok(DeliveryStageResult::Expired);
                    }
                    if db.get(&key)?.is_some() {
                        return Ok(DeliveryStageResult::Existing);
                    }
                    set_until(
                        db,
                        &key,
                        raw.as_bytes().to_vec(),
                        envelope.expires_at.as_millisecond() as u64,
                    );
                    Ok(DeliveryStageResult::Created(envelope.record(raw)))
                })
                .map_err(Into::into)
        })
    }

    fn publish<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        client: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish> {
        Box::pin(async move {
            if expected.value["delivery_state"] != "staged" {
                return Ok(DeliveryPublish::MissingOrChanged);
            }
            let key = self.delivery_key(user, token);
            let mut envelope = Envelope {
                attempt_id: expected.attempt_id,
                expires_at: expected.expires_at,
                secret_binding: expected.secret_binding.clone(),
                value: expected.value.clone(),
            };
            envelope.value["delivery_state"] = serde_json::json!("committed");
            envelope.value["approved_client_id"] = serde_json::json!(client);
            let raw = encode(&envelope)?;
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    if expected.expires_at <= Timestamp::now()
                        || db.get(&key)?.as_deref() != Some(expected.opaque_version.as_bytes())
                    {
                        return Ok(DeliveryPublish::MissingOrChanged);
                    }
                    set_until(db, &key, raw, expected.expires_at.as_millisecond() as u64);
                    Ok(DeliveryPublish::Published)
                })
                .map_err(Into::into)
        })
    }

    fn load<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        Box::pin(async move {
            self.volatile
                .get_with(&self.delivery_key(user, token), |raw| {
                    raw.map(record).transpose().map(Option::flatten)
                })
                .map_err(|_| Error::Unavailable)?
                .map_err(Into::into)
        })
    }

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        Box::pin(async move {
            self.volatile
                .with(|db| -> Result<_, Error> {
                    lookups
                        .iter()
                        .map(|(user, token)| {
                            db.get(&self.delivery_key(*user, token))?
                                .as_deref()
                                .map(record)
                                .transpose()
                                .map(Option::flatten)
                        })
                        .collect()
                })
                .map_err(Into::into)
        })
    }

    fn retire<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.compare_delete(
                &self.delivery_key(user, token),
                expected.opaque_version.as_bytes(),
            )
            .map_err(Into::into)
        })
    }

    fn consume<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        Box::pin(async move {
            let key = self.delivery_key(user, token);
            self.volatile
                .with_key(&key, |db| -> Result<_, Error> {
                    if expected.value["delivery_state"] != "committed"
                        || expected.expires_at <= Timestamp::now()
                        || db.get(&key)?.as_deref() != Some(expected.opaque_version.as_bytes())
                    {
                        return Ok(DeliveryConsume::MissingOrChanged);
                    }
                    db.del(&[&key]);
                    Ok(DeliveryConsume::Consumed)
                })
                .map_err(Into::into)
        })
    }
}
