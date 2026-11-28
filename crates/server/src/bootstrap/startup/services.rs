use super::configuration::StartupConfiguration;
use super::*;
pub(super) mod factory;

/// Construct actual native I/O capabilities. The neutral facade alone owns
/// application service assembly; tests can replace semantic ports here.
pub(crate) fn application_capabilities(
    settings: &Settings,
    persistence: &nazo_oauth_server::ports::persistence::ServerPersistenceBindings,
    transient_state: &nazo_oauth_server::ports::transient_state::ServerTransientStateBindings,
    keyset: nazo_key_management::KeyManager,
) -> anyhow::Result<nazoauth::capabilities::Capabilities> {
    use nazoauth::capabilities::{Capabilities, PasswordServices};
    let tenant = settings.tenant.context.tenant_id;
    Ok(Capabilities {
        persistence: persistence.clone(),
        transient_state: transient_state.clone(),
        keys: keyset.clone(),
        audit: Arc::new(crate::adapters::audit::TenantSecurityAudit::new(tenant)),
        passwords: PasswordServices {
            verifier: Arc::new(super::super::LoginPasswordVerifier),
            hasher: Arc::new(super::super::RegistrationSecretHasher),
            mfa: Arc::new(crate::adapters::security::ServerMfaSecretHasher),
            dummy_hash: crate::adapters::security::dummy_password_hash()?,
        },
        documents: Arc::new(
            crate::adapters::remote_client_documents::RemoteClientDocumentResolver::new(
                &settings.modules.remote_client_document_private_origins,
            )
            .map_err(anyhow::Error::msg)?,
        ),
        email: Arc::new(
            crate::adapters::email::SmtpVerificationEmailDelivery::from_delivery(
                &settings.identity.email.delivery,
            )?,
        ),
        federation_http: Arc::new(crate::adapters::federation_http::FederationClient::new()?),
        module_lifecycle: Arc::new(nazo_runtime_tokio::StoredTransactionLifecycle::new(
            persistence.provider().runtime_modules(tenant.as_uuid()),
        )),
        scim_events: Arc::new(crate::adapters::scim_events::ScimEventLongPoll::new(
            nazo_scim_events::EventPublisher::new(
                persistence.provider().scim_event_store(),
                nazo_oauth_server::domain::scim::ServerScimEventSigner::new(keyset),
                settings.endpoint.issuer.clone(),
            ),
        )),
        certificate_verifier: None,
    })
}

pub(super) async fn build(
    startup: StartupConfiguration,
) -> anyhow::Result<Arc<nazoauth::NazoAuth>> {
    let mut capabilities = application_capabilities(
        &startup.settings,
        &startup.persistence,
        &startup.transient_state,
        startup.keyset.clone(),
    )?;
    capabilities.certificate_verifier = startup.certificate_verifier.clone();
    let mut builder = nazoauth::NazoAuthBuilder::new(
        startup.settings.application_configuration(),
        capabilities,
        startup.deployment.identity.runtime_instance_id(),
    )
    .with_deployment(startup.deployment.clone());
    if let Some(source) =
        crate::keyctl::MdocCrlSource::from_settings(&startup.settings, startup.keyset.clone())
    {
        builder = builder.with_mdoc_crls(Arc::new(source));
    }
    builder = match &startup.avatar_storage {
        super::super::ServerAvatarStorageCapability::Disabled => builder,
        super::super::ServerAvatarStorageCapability::Local { directory } => builder
            .with_avatar_storage(crate::adapters::avatar_files::LocalAvatarStorage::new(
                directory
                    .as_ref()
                    .unwrap_or(&startup.settings.storage.avatar_storage_dir)
                    .clone(),
            )),
        super::super::ServerAvatarStorageCapability::Direct(storage) => {
            builder.with_direct_avatar_storage(storage.clone())
        }
    };
    Ok(Arc::new(builder.build().await?))
}
