use super::{EncryptedStore, decode, encode, timestamp};
use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::NOW,
};
use jiff::{SignedDuration, Timestamp};
use nazo_openid4vci::*;
use nazo_persistence::Openid4vciStore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

impl From<DbError> for CredentialStoreError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::Unavailable => Self::Unavailable,
            DbError::CorruptData => Self::InvalidTransition,
        }
    }
}

#[derive(Clone)]
pub(crate) struct IssuerStore {
    store: EncryptedStore,
    verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
}

#[derive(Serialize, Deserialize)]
struct AccessRecord {
    authorization_id: Option<Uuid>,
    mtls_x5t_s256: Option<String>,
    proof_origin: CredentialProofOrigin,
    token_id: Uuid,
    tenant_id: Uuid,
    subject_id: Uuid,
    client_id: String,
    configuration_ids: Vec<String>,
    credential_identifiers: Vec<CredentialIdentifier>,
    dpop_jkt: Option<String>,
    expires_at: Timestamp,
}
impl From<&CredentialAccess> for AccessRecord {
    fn from(access: &CredentialAccess) -> Self {
        Self {
            authorization_id: access.authorization_id,
            mtls_x5t_s256: access.mtls_x5t_s256.clone(),
            proof_origin: access.proof_origin,
            token_id: access.token_id,
            tenant_id: access.tenant_id,
            subject_id: access.subject_id,
            client_id: access.client_id.clone(),
            configuration_ids: access.configuration_ids.clone(),
            credential_identifiers: access.credential_identifiers.clone(),
            dpop_jkt: access.dpop_jkt.clone(),
            expires_at: access.expires_at,
        }
    }
}
impl From<AccessRecord> for CredentialAccess {
    fn from(access: AccessRecord) -> Self {
        Self {
            authorization_id: access.authorization_id,
            mtls_x5t_s256: access.mtls_x5t_s256,
            proof_origin: access.proof_origin,
            token_id: access.token_id,
            tenant_id: access.tenant_id,
            subject_id: access.subject_id,
            client_id: access.client_id,
            configuration_ids: access.configuration_ids,
            credential_identifiers: access.credential_identifiers,
            dpop_jkt: access.dpop_jkt,
            expires_at: access.expires_at,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct OfferSnapshot {
    id: Uuid,
    tenant_id: Uuid,
    subject_id: Option<Uuid>,
    configuration_ids: String,
    code_hash: Option<String>,
    tx_code_hash: Option<String>,
    expires_at: i64,
}
#[derive(Deserialize)]
struct OfferRow {
    #[serde(flatten)]
    snapshot: OfferSnapshot,
    grants_ciphertext: String,
}

#[derive(Deserialize)]
struct AccessRow {
    token_id: Uuid,
    tenant_id: Uuid,
    subject_id: Uuid,
    client_id: String,
    record: String,
    expires_at: i64,
}
impl AccessRow {
    fn access(&self) -> Result<CredentialAccess, CredentialStoreError> {
        let access: CredentialAccess = decode::<AccessRecord>(&self.record)?.into();
        if access.tenant_id != self.tenant_id
            || access.token_id != self.token_id
            || access.subject_id != self.subject_id
            || access.client_id != self.client_id
            || access.expires_at.as_microsecond() != self.expires_at
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(access)
    }
}

// The shared continuation predicate owns authorization policy. SQL compares
// these complete snapshots again before a lease or terminal mutation commits.
struct Continuation {
    original: CredentialAccess,
    original_record: String,
    current_record: String,
    current_expires: i64,
}

#[derive(Serialize, Deserialize)]
struct DeferredRecord {
    authorization_id: Option<Uuid>,
    selection: Option<CredentialSelection>,
    configuration_id: String,
    format: nazo_digital_credentials::CredentialFormat,
    holder_bindings: Vec<Option<nazo_digital_credentials::HolderBinding>>,
}
#[derive(Deserialize)]
struct DeferredRow {
    id: Uuid,
    transaction_hash: String,
    token_id: Uuid,
    record: String,
    payload_ciphertext: String,
    ready_at: i64,
    expires_at: i64,
    claim_id: Option<String>,
    claim_expires_at: Option<i64>,
}
#[derive(Deserialize)]
struct ResponseRow {
    issuance_id: Uuid,
    token_id: Uuid,
    request_digest: String,
    selection: String,
    body_ciphertext: String,
    encoding: String,
    status: u16,
    dpop_nonce: Option<String>,
    expires_at: i64,
}

enum Completion<'a> {
    Immediate,
    Nonce(&'a str, &'a str),
    Deferred(&'a str, Uuid, &'a str),
}

impl IssuerStore {
    pub(crate) fn new(
        provider: D1Provider,
        key: [u8; 32],
        verifier: Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> Self {
        Self {
            store: EncryptedStore::new(provider, key),
            verifier,
        }
    }
    fn tenant(&self) -> Uuid {
        self.store.provider.tenant_id
    }
    fn access_record(&self, access: &CredentialAccess) -> Result<String, CredentialStoreError> {
        self.store.provider.require_tenant(access.tenant_id)?;
        if access.configuration_ids.is_empty()
            || access.token_id.is_nil()
            || access.subject_id.is_nil()
            || access.client_id.is_empty()
            || (access.dpop_jkt.is_some() && access.mtls_x5t_s256.is_some())
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(encode(&AccessRecord::from(access))?)
    }
    fn upsert_clause() -> &'static str {
        " ON CONFLICT(tenant_id,token_hash) DO UPDATE SET record=excluded.record,expires_at=excluded.expires_at,mutation_id=excluded.mutation_id
          WHERE nazo_vci_access.token_id=excluded.token_id AND nazo_vci_access.subject_id=excluded.subject_id AND nazo_vci_access.client_id=excluded.client_id
          AND json_extract(nazo_vci_access.record,'$.authorization_id') IS json_extract(excluded.record,'$.authorization_id')
          AND json_extract(nazo_vci_access.record,'$.proof_origin')=json_extract(excluded.record,'$.proof_origin')
          AND (json_extract(nazo_vci_access.record,'$.authorization_id') IS NULL OR json_extract(nazo_vci_access.record,'$.dpop_jkt') IS json_extract(excluded.record,'$.dpop_jkt'))
          AND (json_extract(nazo_vci_access.record,'$.mtls_x5t_s256') IS json_extract(excluded.record,'$.mtls_x5t_s256')
               OR (json_extract(nazo_vci_access.record,'$.authorization_id') IS NULL AND json_extract(nazo_vci_access.record,'$.mtls_x5t_s256') IS NULL))"
    }
    fn access_params(&self, hash: &str, access: &CredentialAccess, record: String) -> Vec<Value> {
        vec![
            json!(self.tenant()),
            json!(access.token_id),
            json!(hash),
            json!(access.subject_id),
            json!(access.client_id),
            json!(record),
            json!(access.expires_at.as_microsecond()),
        ]
    }
    async fn continuation(
        &self,
        original: Uuid,
        current: Uuid,
        selection: Option<&CredentialSelection>,
        now: Timestamp,
    ) -> Result<Option<Continuation>, CredentialStoreError> {
        let rows=self.store.provider.database.query::<AccessRow>(
            "SELECT * FROM nazo_vci_access WHERE tenant_id=?1 AND token_id IN (?2,?3) AND (token_id<>?3 OR (revoked_at IS NULL AND expires_at>?4))",
            vec![json!(self.tenant()),json!(original),json!(current),json!(now.as_microsecond())]).await?;
        let Some(original_row) = rows.iter().find(|r| r.token_id == original) else {
            return Ok(None);
        };
        let Some(current_row) = rows.iter().find(|r| r.token_id == current) else {
            return Ok(None);
        };
        let original = original_row.access()?;
        let current = current_row.access()?;
        if !current.continues_access(&original, selection, now) {
            return Ok(None);
        }
        Ok(Some(Continuation {
            original,
            original_record: original_row.record.clone(),
            current_record: current_row.record.clone(),
            current_expires: current_row.expires_at,
        }))
    }
    fn continuation_fence(
        tenant: usize,
        original: usize,
        current: usize,
        original_record: usize,
        current_record: usize,
    ) -> String {
        format!("EXISTS(SELECT 1 FROM nazo_vci_access o JOIN nazo_vci_access c ON c.tenant_id=o.tenant_id WHERE o.tenant_id=?{tenant} AND o.token_id=?{original} AND c.token_id=?{current}
            AND o.record=?{original_record} AND c.record=?{current_record} AND c.revoked_at IS NULL AND c.expires_at>{NOW})")
    }
    fn response_statement(
        &self,
        response: &StoredCredentialResponse,
        mutation: Uuid,
        condition: &str,
        mut extra: Vec<Value>,
    ) -> Result<Statement, CredentialStoreError> {
        if !matches!(response.status, 200 | 202) {
            return Err(CredentialStoreError::InvalidTransition);
        }
        let encrypted = self
            .store
            .seal(response.issuance_id.as_bytes(), &response.body)?;
        let mut params = vec![
            json!(self.tenant()),
            json!(response.issuance_id),
            json!(response.token_id),
            json!(response.request_digest),
            json!(encode(&response.selection)?),
            json!(encrypted),
            json!(match response.encoding {
                CredentialResponseEncoding::Json => "json",
                CredentialResponseEncoding::Jwt => "jwt",
            }),
            json!(response.status),
            json!(response.dpop_nonce),
            json!(response.expires_at.as_microsecond()),
            json!(mutation),
        ];
        params.append(&mut extra);
        Ok(Statement::new(format!("INSERT INTO nazo_vci_responses(tenant_id,issuance_id,token_id,request_digest,selection,body_ciphertext,encoding,status,dpop_nonce,expires_at,mutation_id)
            SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11 WHERE {condition}"),params))
    }
    fn notification_statement(
        &self,
        handle: &NotificationHandle,
        issuance: Uuid,
        mutation: Uuid,
    ) -> Result<Statement, CredentialStoreError> {
        Ok(Statement::new("INSERT INTO nazo_vci_notifications(tenant_id,notification_id,token_id,selection,expires_at)
            SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?6 AND mutation_id=?7)",
            vec![json!(self.tenant()),json!(handle.notification_id),json!(handle.token_id),json!(encode(&handle.selection)?),json!(handle.expires_at.as_microsecond()),json!(issuance),json!(mutation)]))
    }
    fn validate_handle(
        handle: &NotificationHandle,
        response: &StoredCredentialResponse,
    ) -> Result<(), CredentialStoreError> {
        if handle.token_id != response.token_id || handle.selection != response.selection {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(())
    }

    async fn complete_response(
        &self,
        completion: Completion<'_>,
        handle: &NotificationHandle,
        response: &StoredCredentialResponse,
        now: Timestamp,
    ) -> Result<bool, CredentialStoreError> {
        Self::validate_handle(handle, response)?;
        let mutation = Uuid::new_v4();
        let live = format!(
            "?10>{NOW} AND EXISTS(SELECT 1 FROM nazo_vci_access a WHERE a.tenant_id=?1 AND a.token_id=?3 AND a.revoked_at IS NULL AND a.expires_at>{NOW})"
        );
        let (condition,extra,consume,finished)=match completion {
            Completion::Immediate=>(live,vec![],None,"?6 IS NULL".to_owned()),
            Completion::Nonce(hash,claim)=>(format!("{live} AND EXISTS(SELECT 1 FROM nazo_vci_nonces WHERE tenant_id=?1 AND nonce_hash=?12 AND claim_id=?13 AND consumed_at IS NULL AND expires_at>MAX(?14,{NOW}))"),
                vec![json!(hash),json!(claim),json!(now.as_microsecond())],
                Some(Statement::new(format!("UPDATE nazo_vci_nonces SET consumed_at=MAX(?5,created_at,{NOW}),claim_id=NULL,claim_expires_at=NULL WHERE tenant_id=?1 AND nonce_hash=?2 AND claim_id=?3 AND consumed_at IS NULL AND EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?4 AND mutation_id=?6)"),vec![json!(self.tenant()),json!(hash),json!(claim),json!(response.issuance_id),json!(now.as_microsecond()),json!(mutation)])),
                "EXISTS(SELECT 1 FROM nazo_vci_nonces WHERE tenant_id=?1 AND nonce_hash=?6 AND consumed_at IS NOT NULL AND claim_id IS NULL)".to_owned()),
            Completion::Deferred(hash,token,claim)=>{
                if token!=response.token_id {return Err(CredentialStoreError::InvalidTransition);}
                (format!("{live} AND EXISTS(SELECT 1 FROM nazo_vci_deferred WHERE tenant_id=?1 AND transaction_hash=?12 AND claim_id=?13 AND claim_token_id=?3 AND consumed_at IS NULL AND expires_at>MAX(?14,{NOW}))"),
                vec![json!(hash),json!(claim),json!(now.as_microsecond())],
                Some(Statement::new(format!("UPDATE nazo_vci_deferred SET consumed_at=MAX(?5,ready_at,{NOW}),claim_id=NULL,claim_expires_at=NULL,claim_token_id=NULL WHERE tenant_id=?1 AND transaction_hash=?2 AND claim_id=?3 AND claim_token_id=?7 AND consumed_at IS NULL AND EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?4 AND mutation_id=?6)"),vec![json!(self.tenant()),json!(hash),json!(claim),json!(response.issuance_id),json!(now.as_microsecond()),json!(mutation),json!(token)])),
                "EXISTS(SELECT 1 FROM nazo_vci_deferred WHERE tenant_id=?1 AND transaction_hash=?6 AND consumed_at IS NOT NULL AND claim_id IS NULL)".to_owned())
            }
        };
        let target = extra.first().cloned().unwrap_or(Value::Null);
        let mut statements = vec![
            self.response_statement(response, mutation, &condition, extra)?,
            self.notification_statement(handle, response.issuance_id, mutation)?,
        ];
        if let Some(consume) = consume {
            statements.push(consume);
        }
        statements.push(Statement::new(format!("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?2 AND mutation_id=?3) OR
            (EXISTS(SELECT 1 FROM nazo_vci_notifications WHERE tenant_id=?1 AND notification_id=?4 AND token_id=?5) AND ({finished})) THEN 1 ELSE json('credential atomicity failure') END AS checked"),
            vec![json!(self.tenant()),json!(response.issuance_id),json!(mutation),json!(handle.notification_id),json!(handle.token_id),target]));
        statements.push(Statement::new("SELECT issuance_id FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?2 AND mutation_id=?3",vec![json!(self.tenant()),json!(response.issuance_id),json!(mutation)]));
        Ok(!self
            .store
            .provider
            .database
            .batch(statements)
            .await?
            .pop()
            .ok_or(CredentialStoreError::Unavailable)?
            .rows
            .is_empty())
    }

    async fn store_deferred(
        &self,
        credential: &DeferredCredential,
        nonce: Option<(&str, &str)>,
        response: &StoredCredentialResponse,
        now: Timestamp,
    ) -> Result<(), CredentialStoreError> {
        self.store
            .provider
            .require_tenant(credential.access.tenant_id)?;
        if credential.access.token_id != response.token_id
            || credential.selection != response.selection
            || credential
                .selection
                .as_ref()
                .is_some_and(|s| s.configuration_id != credential.configuration_id)
            || credential.holder_bindings.is_empty()
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        let mutation = Uuid::new_v4();
        let payload = self.store.seal(
            credential.id.as_bytes(),
            encode(&credential.payload)?.as_bytes(),
        )?;
        let record = encode(&DeferredRecord {
            authorization_id: credential.access.authorization_id,
            selection: credential.selection.clone(),
            configuration_id: credential.configuration_id.clone(),
            format: credential.format,
            holder_bindings: credential.holder_bindings.clone(),
        })?;
        let mut condition = format!(
            "?10>{NOW} AND EXISTS(SELECT 1 FROM nazo_vci_access a WHERE a.tenant_id=?1 AND a.token_id=?3 AND a.record=?12 AND a.revoked_at IS NULL AND a.expires_at>{NOW})"
        );
        let mut extra = vec![json!(self.access_record(&credential.access)?)];
        if let Some((hash, claim)) = nonce {
            condition.push_str(&format!(" AND EXISTS(SELECT 1 FROM nazo_vci_nonces WHERE tenant_id=?1 AND nonce_hash=?13 AND claim_id=?14 AND consumed_at IS NULL AND expires_at>MAX(?15,{NOW}))"));
            extra.extend([json!(hash), json!(claim), json!(now.as_microsecond())]);
        }
        let mut statements=vec![self.response_statement(response,mutation,&condition,extra)?,
            Statement::new("INSERT INTO nazo_vci_deferred(tenant_id,id,transaction_hash,token_id,record,payload_ciphertext,ready_at,expires_at)
                SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?9 AND mutation_id=?10)",vec![json!(self.tenant()),json!(credential.id),json!(credential.transaction_hash),json!(credential.access.token_id),json!(record),json!(payload),json!(credential.ready_at.as_microsecond()),json!(credential.expires_at.as_microsecond()),json!(response.issuance_id),json!(mutation)])];
        if let Some((hash, claim)) = nonce {
            statements.push(Statement::new(format!("UPDATE nazo_vci_nonces SET consumed_at=MAX(?5,created_at,{NOW}),claim_id=NULL,claim_expires_at=NULL WHERE tenant_id=?1 AND nonce_hash=?2 AND claim_id=?3 AND consumed_at IS NULL AND EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?4 AND mutation_id=?6)"),vec![json!(self.tenant()),json!(hash),json!(claim),json!(response.issuance_id),json!(now.as_microsecond()),json!(mutation)]));
        }
        statements.push(Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?2 AND mutation_id=?3) OR
            (EXISTS(SELECT 1 FROM nazo_vci_deferred WHERE tenant_id=?1 AND id=?4 AND record=?5 AND payload_ciphertext=?6) AND (?7 IS NULL OR EXISTS(SELECT 1 FROM nazo_vci_nonces WHERE tenant_id=?1 AND nonce_hash=?7 AND consumed_at IS NOT NULL AND claim_id IS NULL))) THEN 1 ELSE json('credential atomicity failure') END AS checked",vec![json!(self.tenant()),json!(response.issuance_id),json!(mutation),json!(credential.id),json!(record),json!(payload),json!(nonce.map(|v|v.0))]));
        statements.push(Statement::new("SELECT issuance_id FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?2 AND mutation_id=?3",vec![json!(self.tenant()),json!(response.issuance_id),json!(mutation)]));
        if self
            .store
            .provider
            .database
            .batch(statements)
            .await?
            .pop()
            .ok_or(CredentialStoreError::Unavailable)?
            .rows
            .is_empty()
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(())
    }
}

impl Openid4vciStore for IssuerStore {
    fn insert_offer<'a>(
        &'a self,
        offer: &'a StoredCredentialOffer,
        issuer_state: Option<&'a str>,
        code: Option<&'a str>,
        tx_code: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.store.provider.require_tenant(offer.tenant_id)?;
            let encrypted = self
                .store
                .seal(offer.id.as_bytes(), encode(&offer.grants)?.as_bytes())?;
            self.store.provider.database.query::<Value>(&format!("INSERT INTO nazo_vci_offers(tenant_id,id,subject_id,configuration_ids,grants_ciphertext,issuer_state_hash,code_hash,tx_code_hash,created_at,expires_at)
                VALUES(?1,?2,?3,?4,?5,?6,?7,?8,{NOW},?9)"),vec![json!(offer.tenant_id),json!(offer.id),json!(offer.subject_id),json!(encode(&offer.credential_configuration_ids)?),json!(encrypted),json!(issuer_state),json!(code),json!(tx_code),json!(offer.expires_at.as_microsecond())]).await?;
            Ok(())
        })
    }
}

impl AuthorizationOfferPort for IssuerStore {
    fn resolve_authorization_offer<'a>(
        &'a self,
        tenant: Uuid,
        issuer_state: &'a str,
        subject: Uuid,
        client: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        Box::pin(async move {
            self.store.provider.require_tenant(tenant)?;
            let row=self.store.provider.database.query::<OfferSnapshot>("SELECT * FROM nazo_vci_offers WHERE tenant_id=?1 AND issuer_state_hash=?2 AND subject_id=?3 AND expires_at>?4",vec![json!(tenant),json!(issuer_state),json!(subject),json!(now.as_microsecond())]).await?.into_iter().next();
            row.map(|row| {
                Ok(CredentialAuthorization {
                    tenant_id: tenant,
                    subject_id: subject,
                    client_id: client.to_owned(),
                    configuration_ids: decode(&row.configuration_ids)?,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + SignedDuration::from_mins(10))
                        .min(timestamp(row.expires_at)?),
                })
            })
            .transpose()
        })
    }
}

impl CredentialStorePort for IssuerStore {
    fn upsert_access<'a>(
        &'a self,
        hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let record = self.access_record(access)?;
            let rows=self.store.provider.database.query::<Value>(&format!("INSERT INTO nazo_vci_access(tenant_id,token_id,token_hash,subject_id,client_id,record,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE ?7>{NOW} {} RETURNING token_id",Self::upsert_clause()),self.access_params(hash,access,record)).await?;
            if rows.len() != 1 {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Ok(())
        })
    }
    fn persist_pre_authorized_access<'a>(
        &'a self,
        prepared: &'a [u8],
        hash: &'a str,
        access: &'a CredentialAccess,
        registered: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let snapshot: OfferSnapshot = serde_json::from_slice(prepared)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let record = self.access_record(access)?;
            if snapshot.tenant_id != self.tenant()
                || snapshot.subject_id != Some(access.subject_id)
                || decode::<Vec<String>>(&snapshot.configuration_ids)? != access.configuration_ids
                || !access.credential_identifiers.is_empty()
                || access.expires_at.as_microsecond() > snapshot.expires_at
                || registered.is_some_and(|v| v != access.client_id)
                || access.proof_origin
                    != if registered.is_some() {
                        CredentialProofOrigin::RegisteredClient
                    } else {
                        CredentialProofOrigin::AnonymousPreAuthorized
                    }
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            let mutation = Uuid::new_v4();
            let mut params = self.access_params(hash, access, record);
            params.extend([
                json!(mutation),
                json!(snapshot.id),
                json!(snapshot.code_hash),
                json!(snapshot.tx_code_hash),
                json!(snapshot.configuration_ids),
                json!(snapshot.expires_at),
                json!(registered),
            ]);
            let admitted = "o.tenant_id=?1 AND o.id=?9 AND o.subject_id=?4 AND o.code_hash IS ?10 AND o.tx_code_hash IS ?11 AND o.configuration_ids=?12 AND o.expires_at=?13 AND o.consumed_at IS NULL";
            let mut results=self.store.provider.database.batch(vec![
                Statement::new(format!("INSERT INTO nazo_vci_access(tenant_id,token_id,token_hash,subject_id,client_id,record,expires_at,mutation_id)
                    SELECT ?1,?2,?3,?4,?5,?6,?7,?8 FROM nazo_vci_offers o WHERE {admitted} AND o.expires_at>{NOW} AND ?7>{NOW}
                    AND EXISTS(SELECT 1 FROM nazo_users WHERE tenant_id=?1 AND id=?4 AND active=1)
                    AND (?14 IS NULL OR EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND client_id=?14 AND active=1)) {}",Self::upsert_clause()),params),
                Statement::new(format!("UPDATE nazo_vci_offers SET consumed_at=MAX({NOW},created_at),grants_ciphertext='',tx_code_hash=NULL WHERE tenant_id=?1 AND id=?2 AND consumed_at IS NULL AND EXISTS(SELECT 1 FROM nazo_vci_access WHERE tenant_id=?1 AND token_id=?3 AND mutation_id=?4)"),vec![json!(self.tenant()),json!(snapshot.id),json!(access.token_id),json!(mutation)]),
                Statement::new("SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM nazo_vci_access WHERE tenant_id=?1 AND token_id=?3 AND mutation_id=?4) OR EXISTS(SELECT 1 FROM nazo_vci_offers WHERE tenant_id=?1 AND id=?2 AND consumed_at IS NOT NULL AND grants_ciphertext='' AND tx_code_hash IS NULL) THEN 1 ELSE json('invalid transition') END AS accepted",vec![json!(self.tenant()),json!(snapshot.id),json!(access.token_id),json!(mutation)]),
                Statement::new("SELECT EXISTS(SELECT 1 FROM nazo_vci_access WHERE tenant_id=?1 AND token_id=?2 AND mutation_id=?3) AS accepted, (?4 IS NULL OR EXISTS(SELECT 1 FROM nazo_clients WHERE tenant_id=?1 AND client_id=?4 AND active=1)) AS client_active",vec![json!(self.tenant()),json!(access.token_id),json!(mutation),json!(registered)]),
            ]).await?;
            let row = results
                .pop()
                .and_then(|mut r| r.rows.pop())
                .ok_or(CredentialStoreError::Unavailable)?;
            if row["client_active"].as_i64() != Some(1) {
                return Err(CredentialStoreError::ClientInactive);
            }
            if row["accepted"].as_i64() != Some(1) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Ok(())
        })
    }
    fn offer<'a>(
        &'a self,
        tenant: Uuid,
        id: Uuid,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async move {
            self.store.provider.require_tenant(tenant)?;
            let row=self.store.provider.database.query::<OfferRow>("SELECT * FROM nazo_vci_offers WHERE tenant_id=?1 AND id=?2 AND consumed_at IS NULL AND expires_at>?3",vec![json!(tenant),json!(id),json!(now.as_microsecond())]).await?.into_iter().next();
            row.map(|row| {
                let plaintext = self.store.open(id.as_bytes(), &row.grants_ciphertext)?;
                Ok(StoredCredentialOffer {
                    id,
                    tenant_id: tenant,
                    subject_id: row.snapshot.subject_id,
                    credential_configuration_ids: decode(&row.snapshot.configuration_ids)?,
                    grants: serde_json::from_slice(&plaintext)
                        .map_err(|_| CredentialStoreError::InvalidTransition)?,
                    expires_at: timestamp(row.snapshot.expires_at)?,
                })
            })
            .transpose()
        })
    }
    fn prepare_pre_authorized_offer<'a>(
        &'a self,
        tenant: Uuid,
        code: &'a str,
        tx_code: Option<&'a str>,
        client: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<PreparedPreAuthorizedOffer>, CredentialStoreError>>
    {
        Box::pin(async move {
            self.store.provider.require_tenant(tenant)?;
            let row=self.store.provider.database.query::<OfferSnapshot>("SELECT * FROM nazo_vci_offers WHERE tenant_id=?1 AND code_hash=?2 AND consumed_at IS NULL AND expires_at>?3",vec![json!(tenant),json!(code),json!(now.as_microsecond())]).await?.into_iter().next();
            let Some(row) = row else { return Ok(None) };
            let Some(subject) = row.subject_id else {
                return Ok(None);
            };
            let ids = decode(&row.configuration_ids)?;
            let accepted = match (&row.tx_code_hash, tx_code) {
                (None, None) => true,
                (Some(hash), Some(presented)) => self
                    .verifier
                    .verify_secret(
                        presented.to_owned(),
                        nazo_identity::PasswordHash::new(hash)
                            .map_err(|_| CredentialStoreError::InvalidTransition)?,
                    )
                    .await
                    .map_err(|_| CredentialStoreError::Unavailable)?,
                _ => false,
            };
            if !accepted {
                return Ok(None);
            }
            Ok(Some(PreparedPreAuthorizedOffer {
                commit_token: serde_json::to_vec(&row)
                    .map_err(|_| CredentialStoreError::InvalidTransition)?,
                authorization: CredentialAuthorization {
                    tenant_id: tenant,
                    subject_id: subject,
                    client_id: client.to_owned(),
                    configuration_ids: ids,
                    credential_identifiers: Vec::new(),
                    expires_at: (now + SignedDuration::from_mins(10))
                        .min(timestamp(row.expires_at)?),
                },
            }))
        })
    }
    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.store.provider.database.query::<Value>(&format!("INSERT INTO nazo_vci_nonces(tenant_id,nonce_hash,created_at,expires_at) VALUES(?1,?2,{NOW},?3) ON CONFLICT(tenant_id,nonce_hash) DO NOTHING"),vec![json!(self.tenant()),json!(nonce.nonce_hash),json!(nonce.expires_at.as_microsecond())]).await?;
            Ok(())
        })
    }
    fn claim_nonce<'a>(
        &'a self,
        hash: &'a str,
        claim: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Ok(!self.store.provider.database.query::<Value>(&format!("UPDATE nazo_vci_nonces SET claim_id=?3,claim_expires_at=MAX(?4,{NOW})+300000000 WHERE tenant_id=?1 AND nonce_hash=?2 AND consumed_at IS NULL AND expires_at>MAX(?4,{NOW}) AND (claim_id IS NULL OR claim_expires_at<=MAX(?4,{NOW})) RETURNING nonce_hash"),vec![json!(self.tenant()),json!(hash),json!(claim),json!(now.as_microsecond())]).await?.is_empty())
        })
    }
    fn release_nonce<'a>(
        &'a self,
        hash: &'a str,
        claim: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Ok(!self.store.provider.database.query::<Value>("UPDATE nazo_vci_nonces SET claim_id=NULL,claim_expires_at=NULL WHERE tenant_id=?1 AND nonce_hash=?2 AND claim_id=?3 AND consumed_at IS NULL RETURNING nonce_hash",vec![json!(self.tenant()),json!(hash),json!(claim)]).await?.is_empty())
        })
    }
    fn resolve_access<'a>(
        &'a self,
        hash: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async move {
            self.store.provider.database.query::<AccessRow>("SELECT * FROM nazo_vci_access WHERE tenant_id=?1 AND token_hash=?2 AND revoked_at IS NULL AND expires_at>?3",vec![json!(self.tenant()),json!(hash),json!(now.as_microsecond())]).await?.into_iter().next().map(|row|row.access()).transpose()
        })
    }
    fn find_response<'a>(
        &'a self,
        id: Uuid,
        token: Uuid,
        digest: &'a str,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async move {
            let row=self.store.provider.database.query::<ResponseRow>("SELECT * FROM nazo_vci_responses WHERE tenant_id=?1 AND issuance_id=?2 AND request_digest=?3 AND expires_at>?4",vec![json!(self.tenant()),json!(id),json!(digest),json!(now.as_microsecond())]).await?.into_iter().next();
            let Some(row) = row else { return Ok(None) };
            let selection: Option<CredentialSelection> = decode(&row.selection)?;
            if self
                .continuation(row.token_id, token, selection.as_ref(), now)
                .await?
                .is_none()
            {
                return Ok(None);
            }
            let body = self
                .store
                .open(row.issuance_id.as_bytes(), &row.body_ciphertext)?;
            let encoding = match row.encoding.as_str() {
                "json" => CredentialResponseEncoding::Json,
                "jwt" => CredentialResponseEncoding::Jwt,
                _ => return Err(CredentialStoreError::InvalidTransition),
            };
            if !matches!(row.status, 200 | 202) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Ok(Some(StoredCredentialResponse {
                selection,
                issuance_id: row.issuance_id,
                token_id: row.token_id,
                request_digest: row.request_digest,
                body: bytes::Bytes::copy_from_slice(&body),
                encoding,
                status: row.status,
                dpop_nonce: row.dpop_nonce,
                expires_at: timestamp(row.expires_at)?,
            }))
        })
    }
    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        hash: &'a str,
        claim: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.complete_response(Completion::Nonce(hash, claim), handle, response, now)
                .await
        })
    }
    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if self
                .complete_response(Completion::Immediate, handle, response, now)
                .await?
            {
                Ok(())
            } else {
                Err(CredentialStoreError::InvalidTransition)
            }
        })
    }
    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        hash: &'a str,
        claim: &'a str,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.store_deferred(credential, Some((hash, claim)), response, now)
                .await
        })
    }
    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move { self.store_deferred(credential, None, response, now).await })
    }
    fn claim_ready_deferred<'a>(
        &'a self,
        hash: &'a str,
        token: Uuid,
        claim: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<DeferredClaimOutcome, CredentialStoreError>> {
        Box::pin(async move {
            let row=self.store.provider.database.query::<DeferredRow>("SELECT * FROM nazo_vci_deferred WHERE tenant_id=?1 AND transaction_hash=?2 AND consumed_at IS NULL",vec![json!(self.tenant()),json!(hash)]).await?.into_iter().next();
            let Some(row) = row else {
                return Ok(DeferredClaimOutcome::Invalid);
            };
            let record: DeferredRecord = decode(&row.record)?;
            let now = Timestamp::now();
            let Some(continuation) = self
                .continuation(row.token_id, token, record.selection.as_ref(), now)
                .await?
            else {
                return Ok(DeferredClaimOutcome::Invalid);
            };
            let now = Timestamp::now();
            if row.expires_at <= now.as_microsecond()
                || continuation.current_expires <= now.as_microsecond()
                || record.authorization_id != continuation.original.authorization_id
                || record
                    .selection
                    .as_ref()
                    .is_some_and(|s| s.configuration_id != record.configuration_id)
            {
                return Ok(DeferredClaimOutcome::Invalid);
            }
            if row.ready_at > now.as_microsecond() {
                return Ok(DeferredClaimOutcome::Pending {
                    retry_at: timestamp(row.ready_at)?,
                });
            }
            if row.claim_id.is_some() {
                let expiry = row
                    .claim_expires_at
                    .ok_or(CredentialStoreError::InvalidTransition)?;
                if expiry > now.as_microsecond() {
                    return Ok(DeferredClaimOutcome::Busy {
                        retry_at: timestamp(expiry)?,
                    });
                }
            }
            let plaintext = self
                .store
                .open(row.id.as_bytes(), &row.payload_ciphertext)?;
            let payload = serde_json::from_slice(&plaintext)
                .map_err(|_| CredentialStoreError::InvalidTransition)?;
            let fence = Self::continuation_fence(1, 6, 3, 7, 8);
            let admitted=self.store.provider.database.query::<Value>(&format!("UPDATE nazo_vci_deferred SET claim_id=?4,claim_token_id=?3,claim_expires_at={NOW}+300000000
                WHERE tenant_id=?1 AND transaction_hash=?2 AND id=?5 AND token_id=?6 AND record=?9 AND ready_at=?10 AND expires_at=?11 AND payload_ciphertext=?12
                AND consumed_at IS NULL AND ready_at<={NOW} AND expires_at>{NOW} AND (claim_id IS NULL OR claim_expires_at<={NOW}) AND {fence} RETURNING id"),
                vec![json!(self.tenant()),json!(hash),json!(token),json!(claim),json!(row.id),json!(row.token_id),json!(continuation.original_record),json!(continuation.current_record),json!(row.record),json!(row.ready_at),json!(row.expires_at),json!(row.payload_ciphertext)]).await?;
            if admitted.is_empty() {
                return Ok(DeferredClaimOutcome::Invalid);
            }
            Ok(DeferredClaimOutcome::Claimed(Box::new(
                DeferredCredential {
                    selection: record.selection,
                    id: row.id,
                    transaction_hash: row.transaction_hash,
                    access: continuation.original,
                    configuration_id: record.configuration_id,
                    format: record.format,
                    holder_bindings: record.holder_bindings,
                    payload,
                    ready_at: timestamp(row.ready_at)?,
                    expires_at: timestamp(row.expires_at)?,
                },
            )))
        })
    }
    fn release_deferred<'a>(
        &'a self,
        hash: &'a str,
        token: Uuid,
        claim: &'a str,
        _now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Ok(!self.store.provider.database.query::<Value>("UPDATE nazo_vci_deferred SET claim_id=NULL,claim_expires_at=NULL,claim_token_id=NULL WHERE tenant_id=?1 AND transaction_hash=?2 AND claim_token_id=?3 AND claim_id=?4 AND consumed_at IS NULL RETURNING id",vec![json!(self.tenant()),json!(hash),json!(token),json!(claim)]).await?.is_empty())
        })
    }
    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        hash: &'a str,
        token: Uuid,
        claim: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: Timestamp,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.complete_response(
                Completion::Deferred(hash, token, claim),
                handle,
                response,
                now,
            )
            .await
        })
    }
    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            #[derive(Deserialize)]
            struct Handle {
                token_id: Uuid,
                selection: String,
            }
            let row=self.store.provider.database.query::<Handle>("SELECT token_id,selection FROM nazo_vci_notifications WHERE tenant_id=?1 AND notification_id=?2 AND expires_at>?3",vec![json!(self.tenant()),json!(notification.notification_id),json!(notification.occurred_at.as_microsecond())]).await?.into_iter().next();
            let Some(row) = row else { return Ok(false) };
            let selection: Option<CredentialSelection> = decode(&row.selection)?;
            let Some(continuation) = self
                .continuation(
                    row.token_id,
                    notification.token_id,
                    selection.as_ref(),
                    notification.occurred_at,
                )
                .await?
            else {
                return Ok(false);
            };
            let event = match notification.event {
                NotificationEvent::CredentialAccepted => "credential_accepted",
                NotificationEvent::CredentialFailure => "credential_failure",
                NotificationEvent::CredentialDeleted => "credential_deleted",
            };
            let fence = Self::continuation_fence(1, 3, 4, 8, 9);
            Ok(!self.store.provider.database.query::<Value>(&format!("UPDATE nazo_vci_notifications SET event=?5,description=?6,occurred_at=COALESCE(occurred_at,?7)
                WHERE tenant_id=?1 AND notification_id=?2 AND token_id=?3 AND selection=?10 AND expires_at>MAX(?7,{NOW})
                AND (event IS NULL OR (event=?5 AND description IS ?6)) AND {fence} RETURNING notification_id"),
                vec![json!(self.tenant()),json!(notification.notification_id),json!(row.token_id),json!(notification.token_id),json!(event),json!(notification.description),json!(notification.occurred_at.as_microsecond()),json!(continuation.original_record),json!(continuation.current_record),json!(row.selection)]).await?.is_empty())
        })
    }
}
