use std::sync::Arc;

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_key_management::{KeyManager, KeySettings, SigningKeyWrappingKeyRing};
use nazo_oauth_server::ports::persistence::ServerPersistenceProvider;
use nazo_oauth_server_d1::{D1Provider, Database};
use nazoauth::capabilities::{
    Capabilities, PasswordServices, ServerPersistenceBindings, ServerTransientStateBindings,
};

use crate::{
    WorkerConfiguration, WorkerSecrets,
    outbound::Outbound,
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
    pub ciba_ping: nazo_oauth_server::workers::ciba_ping::CibaPingDeliveryWorker,
    pub backchannel_logout: nazo_oauth_server::workers::backchannel_logout::BackchannelLogoutWorker,
}

impl WorkerApplication {
    pub async fn build(
        configuration: WorkerConfiguration,
        database: Database,
        pepper: String,
        wrapping_keys: SigningKeyWrappingKeyRing,
        dummy_password_hash: String,
        dynamic_client_registration_initial_access_token: Option<String>,
        secrets: WorkerSecrets,
    ) -> anyhow::Result<Self> {
        ensure!(
            secrets
                .openid4vc_import
                .as_ref()
                .is_none_or(|import| import.material.iaca_private_materials.is_empty()),
            "IACA private keys must remain outside the Worker"
        );
        let mut settings = configuration.application(pepper)?;
        if configuration
            .modules
            .contains(&nazo_runtime_modules::ModuleId::DynamicClientRegistration)
        {
            ensure!(
                dynamic_client_registration_initial_access_token
                    .as_ref()
                    .is_some_and(|token| token.len() >= 32),
                "dynamic client registration requires an initial access token of at least 32 bytes"
            );
            settings
                .modules
                .dynamic_client_registration_initial_access_token =
                dynamic_client_registration_initial_access_token;
        }
        let session_cookie_name = settings.session.session_cookie_name.clone();
        let csrf_cookie_name = settings.session.csrf_cookie_name.clone();
        let cookie_secure = settings.session.cookie_secure;
        nazo_crypto::password::validate_argon2id_phc(&dummy_password_hash, 19_456, 2, 1)
            .context("dummy verifier must use the deployment's Argon2id password policy")?;
        let outbound = Outbound::new(&configuration.services.outbound_origins)?;
        let email: Arc<dyn nazo_identity::ports::VerificationEmailDeliveryPort> =
            if let Some(relay) = &configuration.services.email_relay {
                let token = secrets
                    .email_relay_token
                    .context("email relay requires its secret token")?;
                ensure!(
                    token.len() >= 16 && !relay.from.trim().is_empty(),
                    "invalid email relay configuration"
                );
                settings.identity.email.delivery_enabled = true;
                Arc::new(crate::services::EmailRelay {
                    client: outbound.clone(),
                    configuration: relay.clone(),
                    token: zeroize::Zeroizing::new(token),
                })
            } else {
                Arc::new(Unavailable)
            };
        if let Some(providers) = secrets.federation_provider_configs {
            settings.identity.federation.providers =
                nazoauth::config::FederationProviderRegistry::from_json(&serde_json::to_string(
                    &providers,
                )?)?;
        }
        settings.identity.federation.saml_gateway =
            secrets
                .saml_gateway
                .map(|gateway| nazoauth::config::SamlGatewaySettings {
                    issuer: gateway.issuer,
                    audience: gateway.audience,
                    secret: gateway.secret,
                });
        let data_key = secrets
            .data_encryption_key
            .as_ref()
            .map(|encoded| {
                let decoded = zeroize::Zeroizing::new(STANDARD.decode(encoded)?);
                let key: [u8; 32] = decoded
                    .as_slice()
                    .try_into()
                    .context("data encryption key must contain 32 bytes")?;
                Ok::<_, anyhow::Error>(key)
            })
            .transpose()?;
        settings.openid4vc.data_encryption_key = data_key;
        settings.openid4vc.issuer_management_token = secrets.issuer_management_token;
        settings.openid4vc.verifier_management_token = secrets.verifier_management_token;
        settings
            .openid4vc
            .credential_configurations
            .clone_from(&configuration.services.credential_configurations);
        settings
            .openid4vc
            .deferred_credential_configurations
            .clone_from(&configuration.services.deferred_credential_configurations);
        settings
            .openid4vc
            .wallet_authorization_origins
            .clone_from(&configuration.services.wallet_authorization_origins);
        settings
            .openid4vc
            .client_attestation_jwks
            .clone_from(&configuration.services.client_attestation_jwks);
        settings
            .openid4vc
            .key_attestation_jwks
            .clone_from(&configuration.services.key_attestation_jwks);
        settings
            .openid4vc
            .client_attestation_issuer
            .clone_from(&configuration.services.client_attestation_issuer);
        settings.modules.enable_openid4vci_issuer = configuration
            .modules
            .contains(&nazo_runtime_modules::ModuleId::Openid4vciIssuer);
        settings.modules.enable_openid4vp_verifier = configuration
            .modules
            .contains(&nazo_runtime_modules::ModuleId::Openid4vpVerifier);
        settings.modules.register_openid4vci_routes = settings.modules.enable_openid4vci_issuer;
        settings.modules.register_openid4vp_routes = settings.modules.enable_openid4vp_verifier;
        if settings.modules.enable_openid4vp_verifier {
            settings.openid4vc.revocation_policy =
                nazoauth::config::Openid4vcRevocationPolicy::Required;
        }
        settings.validate()?;
        let tenant = configuration.tenant.tenant_id.as_uuid();
        let mut provider = D1Provider::new(database, configuration.tenant.tenant_id);
        if let Some(data_key) = data_key {
            provider = provider.with_data_encryption_key(data_key);
        }
        let provider = Arc::new(provider);
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
        let keys =
            KeyManager::load_database(key_settings(), tenant, repository, wrapping_keys).await?;
        if let Some(import) = secrets.openid4vc_import {
            import_openid4vc(&keys, import).await?;
        }
        let ciba_ping = nazo_oauth_server::workers::ciba_ping::CibaPingDeliveryWorker::new(
            nazo_oauth_server::ports::transient_state::ServerTransientStateProvider::ciba_ping_deliveries(provider.as_ref()), Arc::new(outbound.clone()));
        let backchannel_logout =
            nazo_oauth_server::workers::backchannel_logout::BackchannelLogoutWorker::from_port(
                provider.logout_delivery_store(),
                Arc::new(outbound.clone()),
            );
        let scim_events = crate::services::ScimPoll(nazo_scim_events::EventPublisher::new(
            provider.scim_event_store(),
            nazo_oauth_server::domain::scim::ServerScimEventSigner::new(keys.clone()),
            configuration.issuer.clone(),
        ));
        let capabilities = Capabilities {
            persistence: ServerPersistenceBindings::new(provider.clone()),
            transient_state: ServerTransientStateBindings::new(provider.clone()),
            keys: keys.clone(),
            audit: provider.clone(),
            passwords: PasswordServices {
                verifier: Arc::new(Passwords),
                hasher: Arc::new(Passwords),
                mfa: Arc::new(Passwords),
                dummy_hash: dummy_password_hash,
            },
            documents: Arc::new(outbound.clone()),
            email,
            federation_http: Arc::new(outbound),
            module_lifecycle: Arc::new(Unavailable),
            scim_events: Arc::new(scim_events),
            certificate_verifier: None,
        };
        let mut builder = nazoauth::NazoAuthBuilder::new(
            settings,
            capabilities,
            uuid::Uuid::new_v4().to_string(),
        )
        .with_avatar_storage(provider.as_ref().clone());
        if !configuration.services.mdoc_crls.is_empty() {
            builder = builder.with_mdoc_crls(crate::mdoc_crls::PresignedMdocCrls::new(
                keys.clone(),
                provider.clone(),
                tenant,
                &configuration.issuer,
                &configuration.services.mdoc_crls,
            )?);
        }
        let application = builder.build().await?;
        Ok(Self {
            configuration,
            application,
            keys,
            session_cookie_name,
            csrf_cookie_name,
            cookie_secure,
            ciba_ping,
            backchannel_logout,
        })
    }
}

async fn import_openid4vc(
    keys: &KeyManager,
    import: crate::config::WorkerOpenid4vcImport,
) -> anyhow::Result<()> {
    let current = keys.database_openid4vc_state().await?;
    // Repeated cold starts may observe the same completed operator operation.
    // A different generation is never overwritten by refreshing the CAS input.
    if current.material.as_ref() == Some(&import.material) {
        return Ok(());
    }
    ensure!(
        current.revision == import.expected_revision,
        "OpenID4VC import generation changed"
    );
    let expected = import.material.clone();
    match keys
        .database_commit_openid4vc(
            import.expected_revision,
            import.material,
            import.signing_key_pem,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            let winner = keys.database_openid4vc_state().await?;
            if winner.material.as_ref() == Some(&expected) {
                keys.refresh().await?;
                Ok(())
            } else {
                Err(error.context("OpenID4VC import failed"))
            }
        }
    }
}

pub fn key_settings() -> KeySettings {
    KeySettings {
        rotation_interval: jiff::SignedDuration::from_hours(24 * 30),
        prepublish_window: jiff::SignedDuration::from_hours(24),
        verification_grace: jiff::SignedDuration::from_hours(24),
    }
}
