use crate::D1Provider;
use futures_util::future::BoxFuture;
use nazo_identity::{TenantId, UserId, ports::RepositoryError};
use nazo_persistence::{
    ClientTrustPolicy, Openid4vcSubjectStore, Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
struct PolicyRow {
    id: Uuid,
    resource_id: String,
    resource_digest: String,
    material: String,
}

fn invalid() -> RepositoryError {
    RepositoryError::Consistency("stored OpenID4VC trust policy is invalid".into())
}

fn validate_identity(resource: &str, digest: &str) -> Result<(), RepositoryError> {
    if resource.is_empty()
        || resource.len() > 255
        || resource.trim() != resource
        || resource.chars().any(char::is_control)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    Ok(())
}

impl PolicyRow {
    fn record(self) -> Result<Openid4vcTrustPolicyRecord, RepositoryError> {
        validate_identity(&self.resource_id, &self.resource_digest)?;
        let material = serde_json::from_str(&self.material).map_err(|_| invalid())?;
        nazo_operator_protocol::validate_openid4vc_trust_policy(&material)
            .map_err(|_| invalid())?;
        Ok(Openid4vcTrustPolicyRecord {
            id: self.id,
            resource_id: self.resource_id,
            resource_digest: self.resource_digest,
            material,
        })
    }
}

impl Openid4vcSubjectStore for D1Provider {
    fn is_active(
        &self,
        tenant: TenantId,
        subject: UserId,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>> {
        Box::pin(async move {
            self.require_tenant(tenant.as_uuid())?;
            Ok(!self
                .database
                .query::<Value>(
                    "SELECT id FROM nazo_users WHERE tenant_id=?1 AND id=?2 AND active=1",
                    vec![json!(tenant.as_uuid()), json!(subject.as_uuid())],
                )
                .await?
                .is_empty())
        })
    }
}

impl Openid4vcTrustPolicyStore for D1Provider {
    fn for_client<'a>(
        &'a self,
        tenant: Uuid,
        client: &'a str,
    ) -> BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>> {
        Box::pin(async move {
            self.require_tenant(tenant)?;
            if client.is_empty()
                || client.len() > 255
                || client.trim() != client
                || client.chars().any(char::is_control)
            {
                return Err(invalid());
            }
            #[derive(Deserialize)]
            struct Row {
                client_active: i64,
                has_binding: i64,
                policy: Option<String>,
            }
            let row=self.database.query::<Row>("SELECT c.active AS client_active,
                EXISTS(SELECT 1 FROM nazo_vc_trust_clients h WHERE h.tenant_id=c.tenant_id AND h.client_id=c.id) AS has_binding,
                CASE WHEN p.id IS NOT NULL THEN json_object('id',p.id,'resource_id',p.resource_id,'resource_digest',p.resource_digest,'material',p.material) ELSE NULL END AS policy
                FROM nazo_clients c LEFT JOIN nazo_vc_trust_clients b ON b.tenant_id=c.tenant_id AND b.client_id=c.id AND b.active=1
                LEFT JOIN nazo_vc_trust_policies p ON p.tenant_id=b.tenant_id AND p.id=b.policy_id AND p.active=1 AND p.source='operator-managed'
                WHERE c.tenant_id=?1 AND c.client_id=?2",vec![json!(tenant),json!(client)]).await?.into_iter().next();
            let Some(row) = row else {
                return Ok(ClientTrustPolicy::Unbound);
            };
            if row.has_binding == 0 {
                return Ok(ClientTrustPolicy::Unbound);
            }
            if row.client_active != 1 {
                return Ok(ClientTrustPolicy::BoundInactive);
            }
            let Some(policy) = row.policy else {
                return Ok(ClientTrustPolicy::BoundInactive);
            };
            let policy: PolicyRow = serde_json::from_str(&policy).map_err(|_| invalid())?;
            Ok(ClientTrustPolicy::Active(Box::new(policy.record()?)))
        })
    }

    fn active_for_origin<'a>(
        &'a self,
        tenant: Uuid,
        resource: &'a str,
        origin: &'a str,
        digest: &'a str,
    ) -> BoxFuture<'a, Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>> {
        Box::pin(async move {
            self.require_tenant(tenant)?;
            validate_identity(resource, digest)?;
            if origin.len() > 2048
                || origin.trim() != origin
                || !origin.starts_with("https://")
                || origin.chars().any(char::is_control)
            {
                return Err(invalid());
            }
            self.database.query::<PolicyRow>("SELECT p.* FROM nazo_vc_trust_policies p WHERE p.tenant_id=?1 AND p.resource_id=?2 AND p.resource_digest=?3 AND p.active=1 AND p.source='operator-managed' AND EXISTS(SELECT 1 FROM json_each(json_extract(p.material,'$.wallet_authorization_origins')) o WHERE o.type='text' AND o.value=?4)",vec![json!(tenant),json!(resource),json!(digest),json!(origin)]).await?.into_iter().next().map(PolicyRow::record).transpose()
        })
    }
}
