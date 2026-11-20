use std::sync::Arc;

use anyhow::{Context, ensure};
use nazo_key_management::{KeyManager, KeySettings, SigningKeyWrappingKeyRing};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazoauth::capabilities::{
    Capabilities, PasswordServices, ServerPersistenceBindings, ServerTransientStateBindings,
};

use crate::{
    WorkerConfiguration,
    services::{Passwords, Unavailable},
};

/// One prepared application graph per Worker isolate. Authoritative security
/// state remains in D1; the cache contains configuration and parsed key material.
pub struct WorkerApplication {
    pub configuration: WorkerConfiguration,
    pub application: nazoauth::NazoAuth,
    pub keys: KeyManager,
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub cookie_secure: bool,
}

impl WorkerApplication {
    pub async fn build(
        configuration: WorkerConfiguration,
        database: Database,
        pepper: String,
        wrapping_keys: SigningKeyWrappingKeyRing,
        dummy_password_hash: String,
    ) -> anyhow::Result<Self> {
        let settings = configuration.application(pepper)?;
        let session_cookie_name = settings.session.session_cookie_name.clone();
        let csrf_cookie_name = settings.session.csrf_cookie_name.clone();
        let cookie_secure = settings.session.cookie_secure;
        nazo_crypto::password::validate_argon2id_phc(&dummy_password_hash, 19_456, 2, 1)
            .context("dummy verifier must use the deployment's Argon2id password policy")?;
        let tenant = configuration.tenant.tenant_id.as_uuid();
        let provider = Arc::new(D1Provider::new(database, configuration.tenant.tenant_id));
        let desired = provider.runtime_modules(tenant).read_all_desired().await?;
        for module in nazo_runtime_modules::ModuleId::ALL {
            let state = desired
                .iter()
                .find(|state| state.module_id == module)
                .context("runtime module profile has not been provisioned")?;
            ensure!(
                state.mode.is_enabled() == configuration.modules.contains(&module),
                "persisted module {module:?} differs from the deployment profile"
            );
        }
        let repository = provider.signing_key_repository(tenant);
        ensure!(
            repository.load().await?.is_some(),
            "provision signing keys before serving requests"
        );
        let keys = KeyManager::load_or_create_database(
            key_settings(),
            None,
            tenant,
            repository,
            wrapping_keys,
        )
        .await?;
        let capabilities = Capabilities {
            persistence: ServerPersistenceBindings::new(provider.clone()),
            transient_state: ServerTransientStateBindings::new(provider.clone()),
            keys: keys.clone(),
            audit: provider,
            passwords: PasswordServices {
                verifier: Arc::new(Passwords),
                hasher: Arc::new(Passwords),
                mfa: Arc::new(Unavailable),
                dummy_hash: dummy_password_hash,
            },
            documents: Arc::new(Unavailable),
            email: Arc::new(Unavailable),
            federation_http: Arc::new(Unavailable),
            module_lifecycle: Arc::new(Unavailable),
            scim_events: Arc::new(Unavailable),
            certificate_verifier: None,
        };
        let application = nazoauth::NazoAuthBuilder::new(
            settings,
            capabilities,
            uuid::Uuid::new_v4().to_string(),
        )
        .build()
        .await?;
        Ok(Self {
            configuration,
            application,
            keys,
            session_cookie_name,
            csrf_cookie_name,
            cookie_secure,
        })
    }
}

pub fn key_settings() -> KeySettings {
    KeySettings {
        rotation_interval: jiff::SignedDuration::from_hours(24 * 30),
        prepublish_window: jiff::SignedDuration::from_hours(24),
        verification_grace: jiff::SignedDuration::from_hours(24),
    }
}
