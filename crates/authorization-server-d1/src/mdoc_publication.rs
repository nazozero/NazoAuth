use crate::{D1Provider, db::Statement, persistence::NOW};
use nazo_key_management::{MdocCrlPublication, MdocCrlPublicationStore};
use serde_json::json;

// Compare the public authority as a JSON structure, not field-order-sensitive
// text. JWT key rotations and wrapping-key reseals can replace the containing
// keyset generation without changing this authority. Missing/null projections
// never satisfy admission.
const AUTHORITY_MATCHES: &str = "EXISTS(
    SELECT 1 FROM nazo_signing_keys k WHERE k.tenant_id=?1
      AND json_type(k.metadata,'$.openid4vc.public')='object'
      AND NOT EXISTS(
        SELECT fullkey,type,atom FROM json_tree(json_extract(k.metadata,'$.openid4vc.public'))
        EXCEPT SELECT fullkey,type,atom FROM json_tree(?9))
      AND NOT EXISTS(
        SELECT fullkey,type,atom FROM json_tree(?9)
        EXCEPT SELECT fullkey,type,atom FROM json_tree(json_extract(k.metadata,'$.openid4vc.public')))
)";

impl MdocCrlPublicationStore for D1Provider {
    fn accept_verified_publication<'a>(
        &'a self,
        publication: &'a MdocCrlPublication,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.require_tenant(publication.tenant_id)?;
            anyhow::ensure!(
                !publication.issuer.is_empty() && publication.issuer.len() <= 8192,
                "CRL issuer is invalid"
            );
            let authority_hash = blake3::hash(&serde_json::to_vec(&publication.authority)?)
                .to_hex()
                .to_string();
            let params = vec![
                json!(self.tenant_id),
                json!(hex::encode(publication.issuer_id)),
                json!(publication.issuer),
                json!(publication.number.to_fixed_hex()),
                json!(hex::encode(publication.der_sha256)),
                json!(authority_hash),
                json!(publication.this_update.as_microsecond()),
                json!(publication.next_update.as_microsecond()),
                json!(serde_json::to_string(&publication.authority)?),
            ];
            let admission = format!("{AUTHORITY_MATCHES} AND ?7<={NOW} AND {NOW}<?8");
            self.database
                .batch(vec![
                    Statement::new(
                        format!(
                            "INSERT INTO nazo_mdoc_crl_publications(
                        tenant_id,issuer_id,issuer,number_hex,der_sha256,authority_hash,
                        this_update,next_update,accepted_at)
                     SELECT ?1,?2,?3,?4,?5,?6,?7,?8,{NOW} WHERE {admission}
                     ON CONFLICT(tenant_id,issuer_id) DO UPDATE SET
                        issuer=excluded.issuer,number_hex=excluded.number_hex,
                        der_sha256=excluded.der_sha256,authority_hash=excluded.authority_hash,
                        this_update=excluded.this_update,next_update=excluded.next_update,
                        accepted_at=excluded.accepted_at
                     WHERE excluded.number_hex>nazo_mdoc_crl_publications.number_hex
                       AND excluded.this_update>=nazo_mdoc_crl_publications.this_update"
                        ),
                        params.clone(),
                    ),
                    // Inspect final stored evidence in the same transaction. A
                    // suppressed INSERT/UPDATE is not a successful publication ACK.
                    Statement::new(
                        format!(
                            "SELECT CASE WHEN {admission} AND EXISTS(
                        SELECT 1 FROM nazo_mdoc_crl_publications
                        WHERE tenant_id=?1 AND issuer_id=?2 AND issuer=?3
                          AND number_hex=?4 AND der_sha256=?5 AND authority_hash=?6
                          AND this_update=?7 AND next_update=?8)
                     THEN 1 ELSE json_extract('CRL publication was not accepted','$') END"
                        ),
                        params,
                    ),
                ])
                .await?;
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/mdoc_publication.rs"]
mod tests;
