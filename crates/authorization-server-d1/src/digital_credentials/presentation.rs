use super::{EncryptedStore, decode, encode, presentation_aad, timestamp};
use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::NOW,
};
use jiff::Timestamp;
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationCreateIdempotency, PresentationCreateOutcome,
    PresentationResult, PresentationStoreError as Error, PresentationStoreFuture,
    PresentationStorePort, PresentationTransaction, RequestMethod,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

// An unbound transaction retains the native static-trust path. A partially
// bound or retired policy never becomes an unbound transaction.
const TRUST: &str =
    "((t.trust_id IS NULL AND t.trust_resource IS NULL AND t.trust_digest IS NULL) OR
    (t.trust_id IS NOT NULL AND t.trust_resource IS NOT NULL AND t.trust_digest IS NOT NULL AND
     EXISTS(SELECT 1 FROM nazo_vc_trust_policies p WHERE p.tenant_id=t.tenant_id
       AND p.id=t.trust_id AND p.resource_id=t.trust_resource AND p.resource_digest=t.trust_digest
       AND p.source='operator-managed' AND p.active=1)))";

impl From<DbError> for Error {
    fn from(error: DbError) -> Self {
        match error {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::InvalidTransition,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PresentationStore(EncryptedStore);

#[derive(Serialize, Deserialize)]
struct RequestRecord {
    client_id_prefix: ClientIdPrefix,
    request_method: RequestMethod,
    wallet_authorization_endpoint: String,
    request: AuthorizationRequest,
    request_object: Option<String>,
    request_uri: Option<String>,
}

#[derive(Deserialize)]
struct Row {
    id: Uuid,
    record: String,
    request_sha256: String,
    canonical_request: String,
    trust_id: Option<Uuid>,
    trust_resource: Option<String>,
    trust_digest: Option<String>,
    private_key_ciphertext: Option<String>,
    created_at: i64,
    expires_at: i64,
}

impl PresentationStore {
    pub(crate) fn new(provider: D1Provider, data_key: [u8; 32]) -> Self {
        Self(EncryptedStore::new(provider, data_key))
    }

    fn transaction(&self, row: Row, include_key: bool) -> Result<PresentationTransaction, Error> {
        let record: RequestRecord = decode(&row.record)?;
        let private_key = if include_key {
            row.private_key_ciphertext
                .map(|value| {
                    let aad = presentation_aad(
                        b"nazo-openid4vp-ephemeral-v2",
                        self.0.provider.tenant_id,
                        row.id,
                    );
                    self.0
                        .open(&aad, &value)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| DbError::CorruptData)
                })
                .transpose()?
        } else {
            None
        };
        Ok(PresentationTransaction {
            id: row.id,
            client_id_prefix: record.client_id_prefix,
            request_method: record.request_method,
            wallet_authorization_endpoint: record.wallet_authorization_endpoint,
            request: record.request,
            request_object: record.request_object,
            request_uri: record.request_uri,
            openid4vc_trust_policy_binding_id: row.trust_id,
            openid4vc_trust_policy_resource_id: row.trust_resource,
            openid4vc_trust_policy_digest: row.trust_digest,
            response_encryption_private_key: private_key,
            created_at: timestamp(row.created_at)?,
            expires_at: timestamp(row.expires_at)?,
        })
    }

    fn idempotent(
        &self,
        row: Row,
        binding: PresentationCreateIdempotency<'_>,
    ) -> Result<PresentationTransaction, Error> {
        if row.request_sha256 != binding.request_sha256
            || row.canonical_request != binding.canonical_request
        {
            return Err(Error::IdempotencyConflict);
        }
        self.transaction(row, false)
    }
}

impl PresentationStorePort for PresentationStore {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
        binding: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<PresentationCreateOutcome, Error>> {
        Box::pin(async move {
            let tenant = self.0.provider.tenant_id;
            let private_key = transaction
                .response_encryption_private_key
                .as_ref()
                .map(|key| {
                    self.0.seal(
                        &presentation_aad(b"nazo-openid4vp-ephemeral-v2", tenant, transaction.id),
                        key,
                    )
                })
                .transpose()?;
            let record = encode(&RequestRecord {
                client_id_prefix: transaction.client_id_prefix,
                request_method: transaction.request_method,
                wallet_authorization_endpoint: transaction.wallet_authorization_endpoint.clone(),
                request: transaction.request.clone(),
                request_object: transaction.request_object.clone(),
                request_uri: transaction.request_uri.clone(),
            })?;
            let state_hash = blake3::hash(transaction.request.state.as_bytes())
                .to_hex()
                .to_string();
            let trust = "((?8 IS NULL AND ?9 IS NULL AND ?10 IS NULL) OR (?8 IS NOT NULL AND ?9 IS NOT NULL AND ?10 IS NOT NULL AND EXISTS(SELECT 1 FROM nazo_vc_trust_policies p WHERE p.tenant_id=?1 AND p.id=?8 AND p.resource_id=?9 AND p.resource_digest=?10 AND p.active=1 AND p.source='operator-managed')))";
            let mut result = self.0.provider.database.batch(vec![
                Statement::new(format!("DELETE FROM nazo_vp_transactions WHERE tenant_id=?1 AND request_jti=?2 AND expires_at<={NOW}"),vec![json!(tenant),json!(binding.request_jti)]),
                Statement::new(format!("INSERT INTO nazo_vp_transactions(tenant_id,id,request_jti,request_sha256,canonical_request,record,state_hash,trust_id,trust_resource,trust_digest,private_key_ciphertext,created_at,expires_at)
                    SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13 WHERE {trust} AND ?13>{NOW}
                    ON CONFLICT(tenant_id,request_jti) DO NOTHING RETURNING id"),vec![json!(tenant),json!(transaction.id),json!(binding.request_jti),json!(binding.request_sha256),json!(binding.canonical_request),json!(record),json!(state_hash),json!(transaction.openid4vc_trust_policy_binding_id),json!(transaction.openid4vc_trust_policy_resource_id),json!(transaction.openid4vc_trust_policy_digest),json!(private_key),json!(transaction.created_at.as_microsecond()),json!(transaction.expires_at.as_microsecond())]),
                Statement::new(format!("SELECT * FROM nazo_vp_transactions WHERE tenant_id=?1 AND request_jti=?2 AND expires_at>{NOW}"),vec![json!(tenant),json!(binding.request_jti)]),
            ]).await?;
            let retained = result.pop().ok_or(Error::Unavailable)?.rows.pop();
            let created = !result.pop().ok_or(Error::Unavailable)?.rows.is_empty();
            if created {
                return Ok(PresentationCreateOutcome::Created);
            }
            let row: Row = serde_json::from_value(retained.ok_or(Error::InvalidTransition)?)
                .map_err(|_| Error::InvalidTransition)?;
            Ok(PresentationCreateOutcome::Existing(Box::new(
                self.idempotent(row, binding)?,
            )))
        })
    }

    fn find_by_create_request<'a>(
        &'a self,
        binding: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, Error>> {
        Box::pin(async move {
            self.0.provider.database.query::<Row>(&format!("SELECT * FROM nazo_vp_transactions WHERE tenant_id=?1 AND request_jti=?2 AND expires_at>{NOW}"),vec![json!(self.0.provider.tenant_id),json!(binding.request_jti)])
                .await?.into_iter().next().map(|row| self.idempotent(row,binding)).transpose()
        })
    }

    fn request<'a>(
        &'a self,
        id: Uuid,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, Error>> {
        Box::pin(async move {
            self.0.provider.database.query::<Row>(&format!("SELECT t.* FROM nazo_vp_transactions t WHERE t.tenant_id=?1 AND t.id=?2 AND t.completed_at IS NULL AND t.expires_at>?3 AND {TRUST}"),vec![json!(self.0.provider.tenant_id),json!(id),json!(now.as_microsecond())])
                .await?.into_iter().next().map(|row| self.transaction(row,true)).transpose()
        })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        id: Uuid,
        nonce: &'a str,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            Ok(!self.0.provider.database.query::<Value>(&format!("UPDATE nazo_vp_transactions AS t SET record=json_set(record,'$.request.wallet_nonce',?4) WHERE t.tenant_id=?1 AND t.id=?2 AND t.completed_at IS NULL AND t.expires_at>?3 AND t.expires_at>{NOW} AND {TRUST} RETURNING id"),vec![json!(self.0.provider.tenant_id),json!(id),json!(now.as_microsecond()),json!(nonce)]).await?.is_empty())
        })
    }

    fn complete<'a>(
        &'a self,
        id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            if result.transaction_id != id
                || result.completed_at.as_microsecond() != now.as_microsecond()
            {
                return Err(Error::InvalidTransition);
            }
            let aad = presentation_aad(b"nazo-openid4vp-result-v2", self.0.provider.tenant_id, id);
            let ciphertext = self.0.seal(&aad, encode(result)?.as_bytes())?;
            // SQLite evaluates its clock only after the D1 transaction owns the
            // write lock. The caller's verification clock cannot extend expiry.
            Ok(!self.0.provider.database.query::<Value>(&format!("UPDATE nazo_vp_transactions AS t SET completed_at=?4,result_ciphertext=?5,private_key_ciphertext=NULL WHERE t.tenant_id=?1 AND t.id=?2 AND t.state_hash=?3 AND t.completed_at IS NULL AND t.expires_at>?4 AND t.expires_at>{NOW} AND {TRUST} RETURNING id"),vec![json!(self.0.provider.tenant_id),json!(id),json!(state_hash),json!(now.as_microsecond()),json!(ciphertext)]).await?.is_empty())
        })
    }

    fn result<'a>(
        &'a self,
        id: Uuid,
        now: Timestamp,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationResult>, Error>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct ResultRow {
                result_ciphertext: Option<String>,
                completed_at: Option<i64>,
            }
            let row = self.0.provider.database.query::<ResultRow>(&format!("SELECT t.result_ciphertext,t.completed_at FROM nazo_vp_transactions t WHERE t.tenant_id=?1 AND t.id=?2 AND t.expires_at>?3 AND {TRUST}"),vec![json!(self.0.provider.tenant_id),json!(id),json!(now.as_microsecond())]).await?.into_iter().next();
            let Some(row) = row else { return Ok(None) };
            let Some(ciphertext) = row.result_ciphertext else {
                return if row.completed_at.is_none() {
                    Ok(None)
                } else {
                    Err(Error::InvalidTransition)
                };
            };
            let plaintext = self.0.open(
                &presentation_aad(b"nazo-openid4vp-result-v2", self.0.provider.tenant_id, id),
                &ciphertext,
            )?;
            let result: PresentationResult =
                serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidTransition)?;
            if result.transaction_id != id
                || Some(result.completed_at.as_microsecond()) != row.completed_at
            {
                return Err(Error::InvalidTransition);
            }
            Ok(Some(result))
        })
    }
}
