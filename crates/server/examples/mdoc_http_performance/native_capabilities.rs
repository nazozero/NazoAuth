// Benchmark-only native capability wiring, copied from bootstrap/startup/services.rs.
// main.rs checks this complete function against that authoritative production source
// before executing any request. No protocol or trust implementation is duplicated.
use crate::settings::Settings;
use std::sync::Arc;

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
        module_lifecycle: Arc::new(crate::runtime_modules::ServerModuleLifecycle::new(
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

