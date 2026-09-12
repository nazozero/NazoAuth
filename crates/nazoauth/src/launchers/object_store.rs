use std::{collections::HashMap, path::PathBuf, sync::Arc};

use nazo_identity::{TenantId, ports::AvatarStorageError};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};
use serde::Deserialize;

use crate::{
    bootstrap::{
        ServerAvatarObjectStoreBindings, ServerAvatarObjectStoreProvider,
        ServerAvatarStorageCapability,
    },
    cli::{AvatarObjectStoreLauncher as ServerAvatarObjectStoreLauncher, LauncherFuture},
    config::{ConfigSource, ServerConfigExtension},
};

/// Composition marker for the existing server-multipart local avatar path.
/// It deliberately has no direct-object implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalAvatarObjectStoreProvider;

impl ServerAvatarObjectStoreProvider for LocalAvatarObjectStoreProvider {
    fn for_tenant(&self, _tenant_id: TenantId) -> ServerAvatarStorageCapability {
        ServerAvatarStorageCapability::Local { directory: None }
    }
}

/// Binds one S3 bucket configuration to disjoint tenant object namespaces.
#[derive(Clone)]
pub struct S3AvatarObjectStoreProvider {
    config: S3AvatarObjectStoreConfig,
}

impl S3AvatarObjectStoreProvider {
    pub fn new(config: S3AvatarObjectStoreConfig) -> Result<Self, AvatarStorageError> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl ServerAvatarObjectStoreProvider for S3AvatarObjectStoreProvider {
    fn for_tenant(&self, tenant_id: TenantId) -> ServerAvatarStorageCapability {
        let store = S3AvatarObjectStore::new(self.config.clone(), tenant_id)
            .expect("provider configuration was validated before tenant binding");
        ServerAvatarStorageCapability::Direct(Arc::new(store))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum TenantStorageConfig {
    Local { directory: PathBuf },
    S3(S3AvatarObjectStoreConfig),
}

struct TenantAvatarObjectStoreProvider {
    default: Option<Arc<dyn ServerAvatarObjectStoreProvider>>,
    overrides: HashMap<TenantId, ServerAvatarStorageCapability>,
}

impl TenantAvatarObjectStoreProvider {
    fn new(
        default: Option<Arc<dyn ServerAvatarObjectStoreProvider>>,
        overrides_json: &str,
    ) -> anyhow::Result<Self> {
        let configurations: HashMap<TenantId, TenantStorageConfig> =
            serde_json::from_str(overrides_json)
                .map_err(|_| anyhow::anyhow!("AVATAR_TENANT_STORAGE_JSON must map tenant UUIDs to complete local or s3 configurations"))?;
        let mut overrides = HashMap::new();
        for (tenant_id, configuration) in configurations {
            let capability = match configuration {
                TenantStorageConfig::Local { directory } => {
                    anyhow::ensure!(
                        directory.is_absolute(),
                        "tenant avatar storage directory must be absolute"
                    );
                    ServerAvatarStorageCapability::Local {
                        directory: Some(directory.join(tenant_id.as_uuid().to_string())),
                    }
                }
                TenantStorageConfig::S3(config) => ServerAvatarStorageCapability::Direct(Arc::new(
                    S3AvatarObjectStore::new(config, tenant_id)?,
                )),
            };
            overrides.insert(tenant_id, capability);
        }
        Ok(Self { default, overrides })
    }

    fn from_config(source: &ConfigSource) -> anyhow::Result<Self> {
        let default: Option<Arc<dyn ServerAvatarObjectStoreProvider>> =
            match source.optional_string("AVATAR_OBJECT_STORE").as_deref() {
                None => None,
                Some("local") => Some(Arc::new(LocalAvatarObjectStoreProvider)),
                Some("s3") => Some(Arc::new(S3AvatarObjectStoreProvider::new(
                    S3AvatarObjectStoreConfig {
                        endpoint: source.required_string("AVATAR_S3_ENDPOINT")?,
                        region: source.required_string("AVATAR_S3_REGION")?,
                        bucket: source.required_string("AVATAR_S3_BUCKET")?,
                        access_key: source.required_string("AVATAR_S3_ACCESS_KEY")?,
                        secret_key: source.required_string("AVATAR_S3_SECRET_KEY")?,
                        path_style: source.bool("AVATAR_S3_PATH_STYLE", true)?,
                    },
                )?)),
                Some(_) => anyhow::bail!("AVATAR_OBJECT_STORE must be local or s3 when configured"),
            };
        Self::new(default, &source.string("AVATAR_TENANT_STORAGE_JSON", "{}"))
    }
}

impl ServerAvatarObjectStoreProvider for TenantAvatarObjectStoreProvider {
    fn for_tenant(&self, tenant_id: TenantId) -> ServerAvatarStorageCapability {
        self.overrides.get(&tenant_id).cloned().unwrap_or_else(|| {
            self.default
                .as_ref()
                .map_or(ServerAvatarStorageCapability::Disabled, |provider| {
                    provider.for_tenant(tenant_id)
                })
        })
    }
}

/// Concrete object-store launcher. S3 settings are parsed only in this crate;
/// the authorization server receives a tenant-bound generic capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct AvatarObjectStoreLauncher;

impl ServerAvatarObjectStoreLauncher for AvatarObjectStoreLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::configuration_only(
            "# Optional shared avatar storage; omit to require tenant-specific storage.\n# AVATAR_OBJECT_STORE: \"local\"\n".to_owned(),
            vec![
                "AVATAR_OBJECT_STORE",
                "AVATAR_S3_ACCESS_KEY",
                "AVATAR_S3_BUCKET",
                "AVATAR_S3_ENDPOINT",
                "AVATAR_S3_PATH_STYLE",
                "AVATAR_S3_REGION",
                "AVATAR_S3_SECRET_KEY",
                "AVATAR_TENANT_STORAGE_JSON",
            ],
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        _deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerAvatarObjectStoreBindings> {
        Box::pin(async move {
            Ok(ServerAvatarObjectStoreBindings::new(Arc::new(
                TenantAvatarObjectStoreProvider::from_config(source)?,
            )))
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/launchers/tenant_configuration.rs"]
mod tenant_configuration_tests;
