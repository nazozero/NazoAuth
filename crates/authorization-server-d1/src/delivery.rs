//! Durable, encrypted one-time delivery for approved client credentials.
use crate::{
    D1Provider,
    db::DbError,
    persistence::{NOW, digest, encode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_identity::{
    UserId,
    ports::{
        DeliveryConsume, DeliveryPublish, DeliveryRecord, DeliveryStage, DeliveryStageResult,
        DeliveryStorePort, RepositoryError, RepositoryFuture,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    attempt_id: Uuid,
    expires_at: jiff::Timestamp,
    secret_binding: Option<String>,
    value: Value,
}
#[derive(Deserialize)]
struct Row {
    attempt_id: Uuid,
    version: String,
    ciphertext: String,
    expires_at: i64,
}
impl Envelope {
    fn expected(record: &DeliveryRecord) -> Self {
        Self {
            attempt_id: record.attempt_id,
            expires_at: record.expires_at,
            secret_binding: record.secret_binding.clone(),
            value: record.value.clone(),
        }
    }
    fn record(self, version: String) -> DeliveryRecord {
        DeliveryRecord {
            value: self.value,
            opaque_version: version,
            attempt_id: self.attempt_id,
            expires_at: self.expires_at,
            secret_binding: self.secret_binding,
        }
    }
}
impl D1Provider {
    fn delivery_aad(&self, user: UserId, token: &str) -> Vec<u8> {
        let mut aad = b"nazo-client-delivery-v1\0".to_vec();
        aad.extend_from_slice(self.tenant_id.as_bytes());
        aad.extend_from_slice(user.as_uuid().as_bytes());
        aad.extend_from_slice(digest(token).as_bytes());
        aad
    }
    fn protect_delivery(
        &self,
        user: UserId,
        token: &str,
        value: &Envelope,
    ) -> Result<(String, String), RepositoryError> {
        let key = self
            .data_encryption_key
            .as_ref()
            .ok_or(RepositoryError::Unavailable)?;
        let plaintext = Zeroizing::new(encode(value)?);
        let version = digest(&plaintext);
        let nonce = rand::random::<[u8; 12]>();
        let encrypted = nazo_crypto::aead::encrypt_prefixed(
            key,
            &nonce,
            &self.delivery_aad(user, token),
            plaintext.as_bytes(),
            &nonce,
        )
        .map_err(|_| DbError::Unavailable)?;
        Ok((URL_SAFE_NO_PAD.encode(encrypted), version))
    }
    fn decode_delivery(
        &self,
        user: UserId,
        token: &str,
        row: Row,
    ) -> Result<Option<DeliveryRecord>, RepositoryError> {
        let key = self
            .data_encryption_key
            .as_ref()
            .ok_or(RepositoryError::Unavailable)?;
        let mut encrypted = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(row.ciphertext)
                .map_err(|_| DbError::CorruptData)?,
        );
        let plaintext = nazo_crypto::aead::decrypt_nonce_prefixed(
            key,
            &self.delivery_aad(user, token),
            &mut encrypted,
        )
        .map_err(|_| DbError::CorruptData)?;
        let envelope: Envelope =
            serde_json::from_slice(plaintext).map_err(|_| DbError::CorruptData)?;
        if envelope.attempt_id != row.attempt_id
            || envelope.expires_at.as_microsecond() != row.expires_at
            || digest(std::str::from_utf8(plaintext).map_err(|_| DbError::CorruptData)?)
                != row.version
        {
            return Err(DbError::CorruptData.into());
        }
        if envelope.expires_at <= jiff::Timestamp::now() {
            return Ok(None);
        }
        Ok(Some(envelope.record(row.version)))
    }
    fn delivery_matches(record: &DeliveryRecord) -> Result<bool, RepositoryError> {
        Ok(digest(&encode(&Envelope::expected(record))?) == record.opaque_version)
    }
}
impl DeliveryStorePort for D1Provider {
    fn stage<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        stage: DeliveryStage,
    ) -> RepositoryFuture<'a, DeliveryStageResult> {
        Box::pin(async move {
            if stage.attempt_id.is_nil() || stage.value["delivery_state"] != "staged" {
                return Err(RepositoryError::Consistency(
                    "delivery must start as an owned unpublished stage".into(),
                ));
            }
            // The authenticated envelope retains the original deadline; D1's
            // indexed projection uses microseconds without extending it.
            let envelope = Envelope {
                attempt_id: stage.attempt_id,
                expires_at: stage.expires_at,
                secret_binding: stage.secret_binding,
                value: stage.value,
            };
            let (ciphertext, version) = self.protect_delivery(user, token, &envelope)?;
            let mut result=self.database.batch(vec![
                crate::db::Statement::new(format!("INSERT INTO nazo_client_deliveries(tenant_id,user_id,token_hash,attempt_id,version,ciphertext,expires_at)
                    SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE ?7>{NOW} ON CONFLICT(tenant_id,user_id,token_hash) DO UPDATE SET attempt_id=excluded.attempt_id,version=excluded.version,ciphertext=excluded.ciphertext,expires_at=excluded.expires_at WHERE nazo_client_deliveries.expires_at<={NOW} RETURNING version"),vec![json!(self.tenant_id),json!(user),json!(digest(token)),json!(envelope.attempt_id),json!(version),json!(ciphertext),json!(envelope.expires_at.as_microsecond())]),
                crate::db::Statement::new(format!("SELECT ?1>{NOW} AS live"),vec![json!(envelope.expires_at.as_microsecond())]),
            ]).await?;
            let live = result
                .pop()
                .and_then(|mut r| r.rows.pop())
                .and_then(|r| r["live"].as_i64())
                .ok_or(RepositoryError::Unavailable)?;
            let created = !result
                .pop()
                .ok_or(RepositoryError::Unavailable)?
                .rows
                .is_empty();
            Ok(if created {
                DeliveryStageResult::Created(envelope.record(version))
            } else if live == 0 {
                DeliveryStageResult::Expired
            } else {
                DeliveryStageResult::Existing
            })
        })
    }
    fn publish<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
        approved: Uuid,
    ) -> RepositoryFuture<'a, DeliveryPublish> {
        Box::pin(async move {
            if expected.value["delivery_state"] != "staged"
                || expected.expires_at <= jiff::Timestamp::now()
                || !Self::delivery_matches(expected)?
            {
                return Ok(DeliveryPublish::MissingOrChanged);
            }
            let mut envelope = Envelope::expected(expected);
            envelope.value["delivery_state"] = json!("committed");
            envelope.value["approved_client_id"] = json!(approved);
            let (ciphertext, version) = self.protect_delivery(user, token, &envelope)?;
            let changed=self.database.query::<Value>(&format!("UPDATE nazo_client_deliveries SET ciphertext=?5,version=?6 WHERE tenant_id=?1 AND user_id=?2 AND token_hash=?3 AND version=?4 AND attempt_id=?7 AND expires_at=?8 AND expires_at>{NOW} RETURNING version"),vec![json!(self.tenant_id),json!(user),json!(digest(token)),json!(expected.opaque_version),json!(ciphertext),json!(version),json!(expected.attempt_id),json!(expected.expires_at.as_microsecond())]).await?;
            Ok(if changed.is_empty() {
                DeliveryPublish::MissingOrChanged
            } else {
                DeliveryPublish::Published
            })
        })
    }
    fn load<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        Box::pin(async move {
            self.database.query::<Row>(&format!("SELECT * FROM nazo_client_deliveries WHERE tenant_id=?1 AND user_id=?2 AND token_hash=?3 AND expires_at>{NOW}"),vec![json!(self.tenant_id),json!(user),json!(digest(token))]).await?.into_iter().next().map(|row|self.decode_delivery(user,token,row)).transpose().map(Option::flatten)
        })
    }
    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct Indexed {
                index: usize,
                #[serde(flatten)]
                row: Row,
            }
            let keys: Vec<_> = lookups
                .iter()
                .map(|(user, token)| json!([user, digest(token)]))
                .collect();
            let rows=self.database.query::<Indexed>(&format!("SELECT CAST(q.key AS INTEGER) AS 'index',d.* FROM json_each(?2) q JOIN nazo_client_deliveries d ON d.tenant_id=?1 AND d.user_id=json_extract(q.value,'$[0]') AND d.token_hash=json_extract(q.value,'$[1]') AND d.expires_at>{NOW} ORDER BY CAST(q.key AS INTEGER)"),vec![json!(self.tenant_id),json!(encode(&keys)?)]).await?;
            let mut result = vec![None; lookups.len()];
            for row in rows {
                let &(user, token) = lookups.get(row.index).ok_or(DbError::CorruptData)?;
                result[row.index] = self.decode_delivery(user, token, row.row)?;
            }
            Ok(result)
        })
    }
    fn retire<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            if expected.value["delivery_state"] != "staged" || !Self::delivery_matches(expected)? {
                return Ok(false);
            }
            Ok(!self.database.query::<Value>(&format!("DELETE FROM nazo_client_deliveries WHERE tenant_id=?1 AND user_id=?2 AND token_hash=?3 AND version=?4 AND attempt_id=?5 AND expires_at>{NOW} RETURNING version"),vec![json!(self.tenant_id),json!(user),json!(digest(token)),json!(expected.opaque_version),json!(expected.attempt_id)]).await?.is_empty())
        })
    }
    fn consume<'a>(
        &'a self,
        user: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        Box::pin(async move {
            if expected.value["delivery_state"] != "committed"
                || expected.expires_at <= jiff::Timestamp::now()
                || !Self::delivery_matches(expected)?
            {
                return Ok(DeliveryConsume::MissingOrChanged);
            }
            let rows=self.database.query::<Value>(&format!("DELETE FROM nazo_client_deliveries WHERE tenant_id=?1 AND user_id=?2 AND token_hash=?3 AND version=?4 AND attempt_id=?5 AND expires_at=?6 AND expires_at>{NOW} RETURNING version"),vec![json!(self.tenant_id),json!(user),json!(digest(token)),json!(expected.opaque_version),json!(expected.attempt_id),json!(expected.expires_at.as_microsecond())]).await?;
            Ok(if rows.is_empty() {
                DeliveryConsume::MissingOrChanged
            } else {
                DeliveryConsume::Consumed
            })
        })
    }
}
