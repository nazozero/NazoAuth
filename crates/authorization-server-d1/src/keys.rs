use crate::{
    D1Provider,
    db::{DbError, Statement},
    persistence::encode,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct KeyRow {
    revision: i64,
    metadata: String,
    material: String,
    wrapping_key_id: String,
}
impl KeyRow {
    fn into_domain(self) -> Result<PersistedSigningKeyset, DbError> {
        Ok(PersistedSigningKeyset {
            revision: self.revision,
            public_metadata: serde_json::from_str(&self.metadata)
                .map_err(|_| DbError::CorruptData)?,
            encrypted_private_material: STANDARD
                .decode(self.material)
                .map_err(|_| DbError::CorruptData)?,
            wrapping_key_id: self.wrapping_key_id,
        })
    }
}
impl SigningKeyRepository for D1Provider {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move {
            self.database.query::<KeyRow>("SELECT revision,metadata,material,wrapping_key_id FROM nazo_signing_keys WHERE tenant_id=?1", vec![json!(self.tenant_id)]).await?.into_iter().next().map(|row| row.into_domain().map_err(Into::into)).transpose()
        })
    }
    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            let results = self.database.batch(vec![Statement::new("INSERT INTO nazo_signing_keys(tenant_id,revision,metadata,material,wrapping_key_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(tenant_id) DO NOTHING RETURNING revision",vec![json!(self.tenant_id),json!(candidate.revision),json!(encode(&candidate.public_metadata)?),json!(STANDARD.encode(&candidate.encrypted_private_material)),json!(candidate.wrapping_key_id)]),Statement::new("SELECT revision,metadata,material,wrapping_key_id FROM nazo_signing_keys WHERE tenant_id=?1",vec![json!(self.tenant_id)])]).await?;
            if !results[0].rows.is_empty() {
                return Ok(SigningKeysetCreateResult::Created(candidate));
            }
            let row: KeyRow = serde_json::from_value(
                results
                    .into_iter()
                    .nth(1)
                    .and_then(|result| result.rows.into_iter().next())
                    .ok_or(DbError::CorruptData)?,
            )?;
            Ok(SigningKeysetCreateResult::Existing(row.into_domain()?))
        })
    }
    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            let results = self.database.batch(vec![Statement::new("UPDATE nazo_signing_keys SET revision=?3,metadata=?4,material=?5,wrapping_key_id=?6 WHERE tenant_id=?1 AND revision=?2 RETURNING revision",vec![json!(self.tenant_id),json!(expected_revision),json!(candidate.revision),json!(encode(&candidate.public_metadata)?),json!(STANDARD.encode(&candidate.encrypted_private_material)),json!(candidate.wrapping_key_id)]),Statement::new("SELECT revision,metadata,material,wrapping_key_id FROM nazo_signing_keys WHERE tenant_id=?1",vec![json!(self.tenant_id)])]).await?;
            if !results[0].rows.is_empty() {
                return Ok(SigningKeysetCompareAndSwapResult::Applied(candidate));
            }
            let row: KeyRow = serde_json::from_value(
                results
                    .into_iter()
                    .nth(1)
                    .and_then(|result| result.rows.into_iter().next())
                    .ok_or(DbError::CorruptData)?,
            )?;
            Ok(SigningKeysetCompareAndSwapResult::Conflict(
                row.into_domain()?,
            ))
        })
    }
}
