use nazo_identity::UserId;
use serde_json::Value;

use crate::{Error, ValkeyConnection, command, keys};

#[derive(Clone, Debug)]
pub struct StoredDelivery {
    value: Value,
    raw: String,
}

impl StoredDelivery {
    pub fn value(&self) -> &Value {
        &self.value
    }
}

#[derive(Debug, PartialEq)]
pub enum DeliveryConsume {
    Consumed(Value),
    MissingOrChanged,
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

    pub async fn store(
        &self,
        user_id: UserId,
        token: &str,
        payload: &Value,
        ttl_seconds: u64,
    ) -> Result<(), Error> {
        let raw = serde_json::to_string(payload).map_err(|error| {
            Error::protocol(format!("failed to serialize client delivery: {error}"))
        })?;
        command::set_ex_string(
            &self.connection,
            keys::client_delivery(user_id, token),
            raw,
            ttl_seconds,
        )
        .await
    }

    pub async fn load(
        &self,
        user_id: UserId,
        token: &str,
    ) -> Result<Option<StoredDelivery>, Error> {
        command::get(&self.connection, keys::client_delivery(user_id, token))
            .await?
            .map(parse_delivery)
            .transpose()
    }

    pub async fn load_many(
        &self,
        deliveries: &[(UserId, &str)],
    ) -> Result<Vec<Option<StoredDelivery>>, Error> {
        command::get_many(
            &self.connection,
            deliveries
                .iter()
                .map(|(user_id, token)| keys::client_delivery(*user_id, token))
                .collect(),
        )
        .await?
        .into_iter()
        .map(|raw| raw.map(parse_delivery).transpose())
        .collect()
    }

    pub async fn consume(
        &self,
        user_id: UserId,
        token: &str,
        expected: &StoredDelivery,
    ) -> Result<DeliveryConsume, Error> {
        let Some(raw) =
            command::take(&self.connection, keys::client_delivery(user_id, token)).await?
        else {
            return Ok(DeliveryConsume::MissingOrChanged);
        };
        if raw != expected.raw {
            return Ok(DeliveryConsume::MissingOrChanged);
        }
        let value = serde_json::from_str(&raw).map_err(|error| {
            Error::protocol(format!("malformed consumed client delivery: {error}"))
        })?;
        Ok(DeliveryConsume::Consumed(value))
    }

    pub async fn delete(&self, user_id: UserId, token: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::client_delivery(user_id, token)).await
    }
}

fn parse_delivery(raw: String) -> Result<StoredDelivery, Error> {
    let value = serde_json::from_str(&raw)
        .map_err(|error| Error::protocol(format!("malformed client delivery: {error}")))?;
    Ok(StoredDelivery { value, raw })
}
