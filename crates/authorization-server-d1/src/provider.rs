//! Composition of supported D1 ports and explicitly unavailable optional capabilities.
use crate::{D1Provider, unavailable::Unavailable};
use std::sync::Arc;

impl nazo_oauth_server::ports::persistence::ServerPersistenceProvider for D1Provider {
    fn tenant_directory(&self) -> std::sync::Arc<dyn nazo_persistence::TenantDirectoryStore> {
        Arc::new(Unavailable)
    }

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
        Arc::new(crate::scim::ScimRepository::new(
            self.clone(),
            event_retention_seconds,
        ))
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

    fn controller_registry(&self) -> std::sync::Arc<dyn nazo_persistence::ControllerRegistryPort> {
        Arc::new(Unavailable)
    }

    fn recovery_root(&self) -> std::sync::Arc<dyn nazo_persistence::RecoveryRootPort> {
        Arc::new(Unavailable)
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
        Arc::new(crate::digital_credentials::IssuerStore::new(
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
        Arc::new(crate::digital_credentials::IssuerStore::new(
            self.clone(),
            data_key,
            secret_verifier,
        ))
    }

    fn openid4vci_datasets(
        &self,
        data_key: [u8; 32],
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vciDatasetStore> {
        Arc::new(crate::digital_credentials::DatasetStore::new(
            self.clone(),
            data_key,
        ))
    }

    fn openid4vp_store(
        &self,
        tenant_id: uuid::Uuid,
        data_key: [u8; 32],
    ) -> std::sync::Arc<dyn nazo_persistence::Openid4vpStore> {
        Arc::new(crate::digital_credentials::PresentationStore::new(
            Self {
                tenant_id,
                ..self.clone()
            },
            data_key,
        ))
    }
}

impl nazo_oauth_server::ports::transient_state::ServerTransientStateProvider for D1Provider {
    fn health(
        &self,
    ) -> std::sync::Arc<dyn nazo_oauth_server::ports::transient_state::TransientStateHealthPort>
    {
        Arc::new(self.clone())
    }

    fn authorization_state(&self) -> std::sync::Arc<dyn nazo_auth::AuthorizationStateStorePort> {
        Arc::new(self.clone())
    }

    fn token_state(&self) -> std::sync::Arc<dyn nazo_auth::TokenStateStorePort> {
        Arc::new(self.clone())
    }

    fn ciba_state(
        &self,
    ) -> std::sync::Arc<dyn nazo_auth::CibaStateStorePort<Version = nazo_auth::CibaStateVersion>>
    {
        Arc::new(self.clone())
    }

    fn ciba_ping_deliveries(
        &self,
    ) -> std::sync::Arc<dyn nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort> {
        Arc::new(self.clone())
    }

    fn device_state(
        &self,
    ) -> std::sync::Arc<dyn nazo_auth::DeviceStateStorePort<Version = nazo_auth::DeviceStateVersion>>
    {
        Arc::new(self.clone())
    }

    fn dpop_state(&self) -> std::sync::Arc<dyn nazo_auth::DpopStateStorePort> {
        Arc::new(self.clone())
    }

    fn protected_resource_dpop_state(
        &self,
    ) -> std::sync::Arc<dyn nazo_resource_server::ProtectedResourceDpopStateStore> {
        Arc::new(self.clone())
    }

    fn fapi_http_signature_replay(
        &self,
    ) -> std::sync::Arc<dyn nazo_oauth_server::ports::fapi_replay::FapiHttpSignatureReplayStore>
    {
        Arc::new(self.clone())
    }

    fn request_rate_limits(&self) -> std::sync::Arc<dyn nazo_auth::RequestRateLimitPort> {
        Arc::new(self.clone())
    }

    fn email_verification(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::EmailVerificationStorePort> {
        Arc::new(self.clone())
    }

    fn passkey_ceremonies(&self) -> std::sync::Arc<dyn nazo_identity::ports::PasskeyCeremonyPort> {
        Arc::new(self.clone())
    }

    fn federation_state(&self) -> std::sync::Arc<dyn nazo_identity::ports::FederationStatePort> {
        Arc::new(self.clone())
    }

    fn login_sessions(&self) -> std::sync::Arc<dyn nazo_identity::ports::LoginSessionPort> {
        Arc::new(self.clone())
    }

    fn sessions(&self) -> std::sync::Arc<dyn nazo_identity::ports::SessionStorePort> {
        Arc::new(self.clone())
    }

    fn login_throttle(&self) -> std::sync::Arc<dyn nazo_identity::ports::LoginThrottlePort> {
        Arc::new(self.clone())
    }

    fn mfa_attempt_throttle(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::MfaAttemptThrottlePort> {
        Arc::new(self.clone())
    }

    fn delivery(&self) -> std::sync::Arc<dyn nazo_identity::ports::DeliveryStorePort> {
        Arc::new(self.clone())
    }

    fn avatar_upload_state(
        &self,
    ) -> std::sync::Arc<dyn nazo_identity::ports::AvatarUploadStatePort> {
        Arc::new(Unavailable)
    }
}

impl nazo_oauth_server::ports::transient_state::TransientStateHealthPort for D1Provider {
    fn check(&self) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<'_, ()> {
        Box::pin(async move {
            nazo_persistence::DatabaseHealthPort::check(self)
                .await
                .map_err(|_| {
                    nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable
                })
        })
    }
}

impl nazo_oauth_server::ports::transient_state::TenantTransientStateFactory for D1Provider {
    fn for_tenant(
        &self,
        tenant_id: nazo_identity::TenantId,
    ) -> Result<
        nazo_oauth_server::ports::transient_state::ServerTransientStateBindings,
        nazo_oauth_server::ports::transient_state::TransientStateError,
    > {
        Ok(
            nazo_oauth_server::ports::transient_state::ServerTransientStateBindings::new(Arc::new(
                Self::new(self.database.clone(), tenant_id),
            )),
        )
    }
}
