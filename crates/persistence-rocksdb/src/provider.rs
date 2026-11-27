//! Native durable capabilities; transient state remains bound to Valkey by the host.
use crate::RocksDb;
use std::sync::Arc;

impl nazo_oauth_server::ports::persistence::ServerPersistenceProvider for RocksDb {
    fn security_audit_ledger(&self) -> std::sync::Arc<dyn nazo_persistence::SecurityAuditLedger> {
        Arc::new(self.clone())
    }

    fn database_health(&self) -> std::sync::Arc<dyn nazo_persistence::DatabaseHealthPort> {
        Arc::new(self.clone())
    }

    fn security_state_maintenance(
        &self,
    ) -> std::sync::Arc<dyn nazo_persistence::SecurityStateMaintenancePort> {
        Arc::new(self.clone())
    }

    fn runtime_modules(
        &self,
        _tenant_id: uuid::Uuid,
    ) -> std::sync::Arc<dyn nazo_persistence::RuntimeModuleStore> {
        Arc::new(Self {
            tenant_id: _tenant_id,
            ..self.clone()
        })
    }

    fn signing_key_repository(
        &self,
        _tenant_id: uuid::Uuid,
    ) -> std::sync::Arc<dyn nazo_key_management::SigningKeyRepository> {
        Arc::new(Self {
            tenant_id: _tenant_id,
            ..self.clone()
        })
    }

    fn authorization_repository(
        &self,
        _tenant_id: uuid::Uuid,
    ) -> std::sync::Arc<dyn nazo_auth::AuthorizationRepositoryPort> {
        Arc::new(Self {
            tenant_id: _tenant_id,
            ..self.clone()
        })
    }

    fn device_grant_repository(
        &self,
        _tenant_id: uuid::Uuid,
    ) -> std::sync::Arc<dyn nazo_auth::DeviceGrantRepositoryPort> {
        Arc::new(Self {
            tenant_id: _tenant_id,
            ..self.clone()
        })
    }

    fn token_repository(&self) -> std::sync::Arc<dyn nazo_auth::TokenRepositoryPort> {
        Arc::new(self.clone())
    }

    fn access_token_revocations(
        &self,
    ) -> std::sync::Arc<dyn nazo_resource_server::AccessTokenRevocationLookup> {
        Arc::new(self.clone())
    }

    fn admin_clients(&self) -> std::sync::Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        Arc::new(self.clone())
    }

    fn dynamic_registration_clients(
        &self,
    ) -> std::sync::Arc<dyn nazo_auth::DynamicRegistrationClientStore> {
        Arc::new(self.clone())
    }

    fn logout_clients(&self) -> std::sync::Arc<dyn nazo_auth::LogoutClientRepositoryPort> {
        Arc::new(self.clone())
    }

    fn authorized_applications(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::AuthorizedApplicationRepositoryPort> {
        Arc::new(self.clone())
    }

    fn grant_summaries(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::GrantSummaryRepositoryPort> {
        Arc::new(self.clone())
    }

    fn admin_grants(&self) -> std::sync::Arc<dyn nazo_auth::AdminGrantRepositoryPort> {
        Arc::new(self.clone())
    }

    fn session_accounts(&self) -> std::sync::Arc<dyn nazo_identity::ports::SessionAccountPort> {
        Arc::new(self.clone())
    }

    fn login_accounts(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::LoginAccountRepositoryPort> {
        Arc::new(self.clone())
    }

    fn registration_accounts(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort> {
        Arc::new(self.clone())
    }

    fn admin_users(&self) -> std::sync::Arc<dyn nazo_identity::ports::AdminUserRepositoryPort> {
        Arc::new(self.clone())
    }

    fn profiles(&self) -> std::sync::Arc<dyn nazo_identity::ports::ProfileRepositoryPort> {
        Arc::new(self.clone())
    }

    fn avatars(&self) -> std::sync::Arc<dyn nazo_identity::ports::AvatarRepositoryPort> {
        Arc::new(self.clone())
    }

    fn passkey_accounts(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::PasskeyAccountRepositoryPort> {
        Arc::new(self.clone())
    }

    fn passkeys(&self) -> std::sync::Arc<dyn nazo_identity::ports::PasskeyRepositoryPort> {
        Arc::new(self.clone())
    }

    fn ciba_accounts(&self) -> std::sync::Arc<dyn nazo_persistence::CibaAccountStore> {
        Arc::new(self.clone())
    }

    fn openid4vc_subjects(&self) -> std::sync::Arc<dyn nazo_persistence::Openid4vcSubjectStore> {
        Arc::new(self.clone())
    }

    fn mfa_repository(&self) -> std::sync::Arc<dyn nazo_identity::ports::MfaRepositoryPort> {
        Arc::new(self.clone())
    }

    fn remembered_mfa_devices(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::RememberedMfaDevicePort> {
        Arc::new(self.clone())
    }

    fn federation_links(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::FederationLinkRepositoryPort> {
        Arc::new(self.clone())
    }

    fn federation_logins(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::FederationLoginRepositoryPort> {
        Arc::new(self.clone())
    }

    fn access_requests(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::AccessRequestRepositoryPort> {
        Arc::new(self.clone())
    }

    fn admin_access_requests(
        &self,
    ) -> std::sync::Arc<dyn nazo_persistence::AdminAccessRequestStore> {
        Arc::new(self.clone())
    }

    fn scim_repository(
        &self,
        event_retention_seconds: u64,
    ) -> std::sync::Arc<dyn nazo_identity::ports::ScimRepositoryPort> {
        Arc::new(crate::scim::ScimRepository {
            store: self.clone(),
            retention_seconds: event_retention_seconds,
        })
    }

    fn scim_credentials(&self) -> std::sync::Arc<dyn nazo_identity::ports::ScimCredentialPort> {
        Arc::new(self.clone())
    }

    fn scim_event_store(&self) -> std::sync::Arc<dyn nazo_scim_events::EventStorePort> {
        Arc::new(self.clone())
    }

    fn logout_outbox(&self) -> std::sync::Arc<dyn nazo_auth::BackchannelLogoutOutboxPort> {
        Arc::new(self.clone())
    }

    fn logout_delivery_store(
        &self,
    ) -> std::sync::Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore> {
        Arc::new(self.clone())
    }

    fn mtls_trust_anchors(&self) -> std::sync::Arc<dyn nazo_identity::ports::MtlsTrustAnchorStore> {
        Arc::new(self.clone())
    }

    fn openid4vc_trust_policies(
        &self,
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vcTrustPolicyStore> {
        Arc::new(self.clone())
    }

    fn openid4vci_store(
        &self,
        data_key: [u8; 32],
        secret_verifier: std::sync::Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vciStore> {
        Arc::new(crate::digital_credentials::issuance::IssuerStore::new(
            self.clone(),
            data_key,
            secret_verifier,
        ))
    }

    fn openid4vci_authorization_offers(
        &self,
        data_key: [u8; 32],
        secret_verifier: std::sync::Arc<dyn nazo_identity::ports::SecretVerifyPort>,
    ) -> std::sync::Arc<dyn nazo_openid4vci::AuthorizationOfferPort> {
        Arc::new(crate::digital_credentials::issuance::IssuerStore::new(
            self.clone(),
            data_key,
            secret_verifier,
        ))
    }

    fn openid4vci_datasets(
        &self,
        data_key: [u8; 32],
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vciDatasetStore> {
        Arc::new(crate::digital_credentials::datasets::DatasetStore::new(
            self.clone(),
            data_key,
        ))
    }

    fn openid4vp_store(
        &self,
        tenant_id: uuid::Uuid,
        data_key: [u8; 32],
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vpStore> {
        Arc::new(
            crate::digital_credentials::presentation::PresentationStore::new(
                Self {
                    tenant_id,
                    ..self.clone()
                },
                data_key,
            ),
        )
    }
}
