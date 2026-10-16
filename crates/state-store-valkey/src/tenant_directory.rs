use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use fred::prelude::{KeysInterface, LuaInterface};
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId, canonical_tenant_host,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyClient};

const CACHE_SCHEMA_VERSION: u8 = 2;
const CACHE_INTEGRITY_MARKER: &str = "nazo-tenant-directory-cache-v2";
const SNAPSHOT_KEY: &str = "tenant-directory:snapshot";

const PUBLISH_AUTHORITATIVE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return 'unchanged'
end
redis.call('SET', KEYS[1], ARGV[1])
return 'stored'
"#;

/// Deployment-wide cache for the public tenant routing directory.
#[derive(Clone)]
pub struct TenantDirectoryCache {
    client: ValkeyClient,
    validated: Arc<Mutex<Option<ValidatedDirectorySnapshot>>>,
}

impl TenantDirectoryCache {
    #[must_use]
    pub fn new(client: &ValkeyClient) -> Self {
        Self {
            client: client.clone(),
            validated: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn load(&self) -> Result<Option<Arc<TenantDirectorySnapshot>>, Error> {
        let snapshot: Option<String> = self
            .client
            .client
            .get(self.client.deployment_key(SNAPSHOT_KEY))
            .await
            .map_err(Error::from_fred)?;
        snapshot
            .map(|encoded| {
                let mut validated = self
                    .validated
                    .lock()
                    .expect("tenant directory cache mutex is not poisoned");
                decode_cached_snapshot(encoded, &mut validated)
            })
            .transpose()
    }

    /// Repairs the cache from a database-authoritative snapshot, including an
    /// ahead-of-database poisoned value. Consumers use this only as a hint.
    pub async fn publish_authoritative(
        &self,
        snapshot: &TenantDirectorySnapshot,
    ) -> Result<bool, Error> {
        let encoded = encode_snapshot(snapshot)?;
        let reply: String = self
            .client
            .client
            .eval(
                PUBLISH_AUTHORITATIVE_SCRIPT,
                vec![self.client.deployment_key(SNAPSHOT_KEY)],
                vec![encoded],
            )
            .await
            .map_err(Error::from_fred)?;
        match reply.as_str() {
            "stored" => Ok(true),
            "unchanged" => Ok(false),
            other => Err(Error::unexpected(format!(
                "unexpected tenant directory CAS reply {other:?}"
            ))),
        }
    }
}

// Keep one validated wire value. Every load still reads Valkey, so deletion,
// corruption and same-revision replacement are observed on the next poll.
struct ValidatedDirectorySnapshot {
    encoded: String,
    snapshot: Arc<TenantDirectorySnapshot>,
}

fn decode_cached_snapshot(
    encoded: String,
    validated: &mut Option<ValidatedDirectorySnapshot>,
) -> Result<Arc<TenantDirectorySnapshot>, Error> {
    if let Some(previous) = validated
        && previous.encoded == encoded
    {
        return Ok(previous.snapshot.clone());
    }
    let snapshot = Arc::new(decode_snapshot(&encoded)?);
    *validated = Some(ValidatedDirectorySnapshot {
        encoded,
        snapshot: snapshot.clone(),
    });
    Ok(snapshot)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedDirectorySnapshot<S> {
    schema_version: u8,
    integrity: S,
    revision: String,
    tenants: Vec<CachedDirectoryBinding<S>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedDirectoryBinding<S> {
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    runtime_revision: String,
    issuer: S,
    external_host: S,
}

fn encode_snapshot(snapshot: &TenantDirectorySnapshot) -> Result<String, Error> {
    validate_bindings(&snapshot.tenants, Error::unexpected)?;
    let wire = CachedDirectorySnapshot {
        schema_version: CACHE_SCHEMA_VERSION,
        integrity: CACHE_INTEGRITY_MARKER,
        revision: snapshot.revision.to_string(),
        tenants: snapshot
            .tenants
            .iter()
            .map(|binding| CachedDirectoryBinding {
                tenant_id: binding.tenant.tenant_id.as_uuid(),
                realm_id: binding.tenant.realm_id.as_uuid(),
                organization_id: binding.tenant.organization_id.as_uuid(),
                runtime_revision: binding.runtime_revision.to_string(),
                issuer: binding.issuer.as_str(),
                external_host: binding.external_host.as_str(),
            })
            .collect(),
    };
    serde_json::to_string(&wire)
        .map_err(|error| Error::unexpected(format!("failed to encode tenant directory: {error}")))
}

fn decode_snapshot(encoded: &str) -> Result<TenantDirectorySnapshot, Error> {
    let wire: CachedDirectorySnapshot<String> = serde_json::from_str(encoded).map_err(|error| {
        Error::corrupt_data(format!("cached tenant directory JSON is invalid: {error}"))
    })?;
    if wire.schema_version != CACHE_SCHEMA_VERSION {
        return Err(Error::corrupt_data(
            "cached tenant directory schema version is unsupported",
        ));
    }
    if wire.integrity != CACHE_INTEGRITY_MARKER {
        return Err(Error::corrupt_data(
            "cached tenant directory integrity marker is invalid",
        ));
    }
    let revision = wire.revision.parse::<u64>().map_err(|_| {
        Error::corrupt_data("cached tenant directory revision is not a canonical u64")
    })?;
    if wire.revision != revision.to_string() {
        return Err(Error::corrupt_data(
            "cached tenant directory revision is not canonical",
        ));
    }
    let tenants = wire
        .tenants
        .into_iter()
        .map(|binding| {
            let runtime_revision = binding.runtime_revision.parse::<u64>().map_err(|_| {
                Error::corrupt_data("cached tenant runtime revision is not a canonical u64")
            })?;
            if binding.runtime_revision != runtime_revision.to_string() {
                return Err(Error::corrupt_data(
                    "cached tenant runtime revision is not canonical",
                ));
            }
            Ok(TenantDirectoryBinding {
                tenant: TenantContext {
                    tenant_id: TenantId::new(binding.tenant_id).map_err(|_| {
                        Error::corrupt_data("cached tenant directory contains a nil tenant id")
                    })?,
                    realm_id: RealmId::new(binding.realm_id).map_err(|_| {
                        Error::corrupt_data("cached tenant directory contains a nil realm id")
                    })?,
                    organization_id: OrganizationId::new(binding.organization_id).map_err(
                        |_| {
                            Error::corrupt_data(
                                "cached tenant directory contains a nil organization id",
                            )
                        },
                    )?,
                },
                runtime_revision,
                issuer: binding.issuer,
                external_host: binding.external_host,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    validate_bindings(&tenants, Error::corrupt_data)?;
    Ok(TenantDirectorySnapshot { revision, tenants })
}

fn validate_bindings(
    tenants: &[TenantDirectoryBinding],
    invalid: fn(String) -> Error,
) -> Result<(), Error> {
    let mut tenant_ids = HashSet::with_capacity(tenants.len());
    let mut issuers = HashSet::with_capacity(tenants.len());
    let mut hosts = HashSet::with_capacity(tenants.len());
    for binding in tenants {
        if binding.runtime_revision == 0 {
            return Err(invalid(
                "tenant runtime revision must be positive".to_owned(),
            ));
        }
        nazo_auth::validate_issuer_url(&binding.issuer)
            .map_err(|error| invalid(format!("tenant directory issuer is invalid: {error}")))?;
        let host = canonical_tenant_host(&binding.external_host).map_err(|error| {
            invalid(format!(
                "tenant directory external host is invalid: {error}"
            ))
        })?;
        if host != binding.external_host {
            return Err(invalid(
                "tenant directory external host is not canonical".to_owned(),
            ));
        }
        if !tenant_ids.insert(binding.tenant.tenant_id) {
            return Err(invalid(
                "tenant directory contains a duplicate tenant id".to_owned(),
            ));
        }
        if !issuers.insert(binding.issuer.as_str()) {
            return Err(invalid(
                "tenant directory contains a duplicate issuer".to_owned(),
            ));
        }
        if !hosts.insert(binding.external_host.as_str()) {
            return Err(invalid(
                "tenant directory contains a duplicate external host".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/tenant_directory.rs"]
mod tests;
