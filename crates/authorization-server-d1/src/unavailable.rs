//! Explicit unavailable capabilities outside the initial Workers deployment profile.
//! No unsupported read is represented as an empty successful result.

pub(crate) struct Unavailable;

impl nazo_identity::ports::AdminUserRepositoryPort for Unavailable {
    fn page(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _limit: i64,
        _offset: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::UserPage> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn update_authorized_with_required_audit(
        &self,
        _tenant: nazo_identity::TenantContext,
        _actor_id: nazo_identity::UserId,
        _target_id: nazo_identity::UserId,
        _update: nazo_identity::ports::AdminUserUpdate,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AdminUserUpdateOutcome> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn set_tenant_admin_authorized(
        &self,
        _control_tenant_id: nazo_identity::TenantId,
        _actor_id: nazo_identity::UserId,
        _target_tenant_id: nazo_identity::TenantId,
        _target_id: nazo_identity::UserId,
        _admin_level: i32,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AdminUserUpdateOutcome> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::RegistrationAccountRepositoryPort for Unavailable {
    fn email_exists<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn create_user(
        &self,
        _user: nazo_identity::ports::NewUser,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn create_user_with_required_audit(
        &self,
        _user: nazo_identity::ports::NewUser,
        _actor_id: nazo_identity::UserId,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::EmailVerificationStorePort for Unavailable {
    fn reserve_peer_send<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _subject: &'a str,
        _owner: &'a str,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn reserve_email_send<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _owner: &'a str,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn store_code<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _owner: &'a str,
        _password_hash: nazo_identity::ports::PasswordHashInput,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn reserve_code_attempt<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _max_attempts: u64,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::ports::EmailVerificationRecord>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn consume_code<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _expected_version: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::EmailVerificationConsume>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn delete_code<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn release_email_send<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
        _owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn release_peer_send<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _subject: &'a str,
        _owner: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::RememberedMfaDevicePort for Unavailable {
    fn is_valid<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _token_hash: &'a str,
        _user_agent_hash: Option<&'a str>,
        _now: jiff::Timestamp,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::AuthorizedApplicationRepositoryPort for Unavailable {
    fn applications_for_user(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::ports::AuthorizedApplication>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::AccessRequestRepositoryPort for Unavailable {
    fn list_for_user(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::AccessRequest>> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn create(
        &self,
        _request: nazo_identity::NewAccessRequest,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AccessRequest> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _request_id: uuid::Uuid,
        _approved_client_id: uuid::Uuid,
        _client_id: &'a str,
        _secret_binding: Option<&'a str>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::DeliveryStorePort for Unavailable {
    fn stage<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _token: &'a str,
        _stage: nazo_identity::ports::DeliveryStage,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::DeliveryStageResult> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn publish<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _token: &'a str,
        _expected: &'a nazo_identity::ports::DeliveryRecord,
        _approved_client_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::DeliveryPublish> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn load<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _token: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::ports::DeliveryRecord>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn load_many<'a>(
        &'a self,
        _lookups: &'a [(nazo_identity::UserId, &'a str)],
    ) -> nazo_identity::ports::RepositoryFuture<'a, Vec<Option<nazo_identity::ports::DeliveryRecord>>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn retire<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _token: &'a str,
        _expected: &'a nazo_identity::ports::DeliveryRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn consume<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _token: &'a str,
        _expected: &'a nazo_identity::ports::DeliveryRecord,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::DeliveryConsume> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::AvatarRepositoryPort for Unavailable {
    fn compare_and_set_avatar<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _expected_avatar_url: Option<&'a str>,
        _expected_avatar_revision: i64,
        _avatar_url: Option<String>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::AvatarUploadStatePort for Unavailable {
    fn create<'a>(
        &'a self,
        _authorization: &'a nazo_identity::ports::AvatarUploadAuthorization,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn claim<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _lease_until: jiff::Timestamp,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::AvatarUploadClaim> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn record_candidate<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _staged_version: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn complete<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
        _final_object_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn release<'a>(
        &'a self,
        _user_id: nazo_identity::UserId,
        _upload_id: &'a str,
        _ownership_token: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::MfaRepositoryPort for Unavailable {
    fn check_totp_enrollment<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _code: &'a str,
        _timestamp: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::TotpEnrollmentCheck> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn begin_totp_enrollment<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _secret: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _code: &'a str,
        _timestamp: i64,
        _hashes: Vec<nazo_identity::ports::EncodedSecretHash>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::TotpVerificationOutcome>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn verify_and_confirm_totp_with_required_audit<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _code: &'a str,
        _timestamp: i64,
        _hashes: Vec<nazo_identity::ports::EncodedSecretHash>,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::TotpVerificationOutcome>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn record_invalid_totp_attempt(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _code: &'a str,
        _timestamp: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::TotpVerificationOutcome>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn backup_code_candidates(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::ports::BackupCodeCandidate>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn consume_backup_code_candidate(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _candidate_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<uuid::Uuid>> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn record_invalid_backup_code_attempt(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _credential_id: uuid::Uuid,
        _hashes: Vec<nazo_identity::ports::EncodedSecretHash>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn replace_backup_code_hashes_with_required_audit<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _credential_id: uuid::Uuid,
        _hashes: Vec<nazo_identity::ports::EncodedSecretHash>,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn clear_mfa_state_if_current<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _credential_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn clear_mfa_state_if_current_with_required_audit<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _credential_id: uuid::Uuid,
        _source_ip_hash: String,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn remember_device(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _credential_id: uuid::Uuid,
        _token_hash: String,
        _user_agent_hash: Option<String>,
        _expires_at: jiff::Timestamp,
    ) -> nazo_identity::ports::RepositoryFuture<'_, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::FederationLinkRepositoryPort for Unavailable {
    fn list_summaries(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::ports::FederationLinkSummary>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn delete(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _link_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<
        '_,
        Option<nazo_identity::ports::FederationLinkSummary>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::FederationLoginRepositoryPort for Unavailable {
    fn resolve_existing<'a>(
        &'a self,
        _login: &'a nazo_identity::ports::FederationLogin,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn email_exists<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn create_federated(
        &self,
        _identity: nazo_identity::ports::NewFederatedIdentity,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::FederationStatePort for Unavailable {
    fn store_oidc<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a nazo_identity::federation::OidcFederationState,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn take_oidc<'a>(
        &'a self,
        _state: &'a str,
        _expected_browser_binding_hash: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::federation::OidcFederationState>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn store_social<'a>(
        &'a self,
        _state: &'a str,
        _value: &'a nazo_identity::federation::SocialFederationState,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn take_social<'a>(
        &'a self,
        _state: &'a str,
        _expected_browser_binding_hash: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<
        'a,
        Option<nazo_identity::federation::SocialFederationState>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn reserve_saml_replay<'a>(
        &'a self,
        _assertion_signature: &'a str,
        _ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::ScimRepositoryPort for Unavailable {
    fn list<'a>(
        &'a self,
        _query: nazo_identity::ports::ScimListQuery,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::UserPage> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn get<'a>(
        &'a self,
        _tenant: nazo_identity::TenantContext,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn create<'a>(
        &'a self,
        _new_user: nazo_identity::ports::NewScimUser,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn replace<'a>(
        &'a self,
        _tenant: nazo_identity::TenantContext,
        _user_id: nazo_identity::UserId,
        _replacement: nazo_identity::scim::NormalizedScimUser,
        _mutation: nazo_scim_events::MutationContext,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn patch<'a>(
        &'a self,
        _tenant: nazo_identity::TenantContext,
        _user_id: nazo_identity::UserId,
        _patch: nazo_identity::scim::ScimPatch,
        _mutation: nazo_scim_events::MutationContext,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::PublicAccount> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn delete<'a>(
        &'a self,
        _tenant: nazo_identity::TenantContext,
        _user_id: nazo_identity::UserId,
        _mutation: nazo_scim_events::MutationContext,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::ScimCredentialPort for Unavailable {
    fn active_credential<'a>(
        &'a self,
        _token_hash: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::scim::ScimTokenCredential>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_identity::ports::MtlsTrustAnchorStore for Unavailable {
    fn create_for_owned_client(
        &self,
        _request: nazo_identity::NewMtlsTrustAnchorRequest,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::MtlsTrustAnchorRequest> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn list_for_user(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::MtlsTrustAnchorRequest>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn page(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _status: Option<nazo_identity::MtlsTrustAnchorStatus>,
        _limit: i64,
        _offset: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::MtlsTrustAnchorRequestPage> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn by_id(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::MtlsTrustAnchorRequest>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn approve(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _id: uuid::Uuid,
        _actor: nazo_identity::UserId,
        _note: Option<String>,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::MtlsTrustAnchorRequest> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn reject(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _id: uuid::Uuid,
        _actor: nazo_identity::UserId,
        _note: Option<String>,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::MtlsTrustAnchorRequest> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn revoke(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _id: uuid::Uuid,
        _actor: nazo_identity::UserId,
        _note: String,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::MtlsTrustAnchorRequest> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn active_bundle(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _client_id: Option<uuid::Uuid>,
    ) -> nazo_identity::ports::RepositoryFuture<'_, String> {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_auth::CibaStateStorePort for Unavailable {
    type Version = nazo_auth::CibaStateVersion;
    fn load<'a>(
        &'a self,
        _auth_req_id: &'a str,
    ) -> nazo_auth::CibaStateFuture<'a, Option<nazo_auth::CibaStoredRequest<Self::Version>>> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn create<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _state: &'a nazo_auth::CibaRequestState,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn create_with_authorization_deadline<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _state: &'a nazo_auth::CibaRequestState,
        _authorization_deadline: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn replace<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
        _state: &'a nazo_auth::CibaRequestState,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn replace_with_authorization_deadline<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
        _state: &'a nazo_auth::CibaRequestState,
        _authorization_deadline: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn delete<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }

    fn delete_with_authorization_deadline<'a>(
        &'a self,
        _auth_req_id: &'a str,
        _version: &'a Self::Version,
        _authorization_deadline: Option<i64>,
    ) -> nazo_auth::CibaStateFuture<'a, nazo_auth::CibaAtomicResult> {
        Box::pin(async { Err(nazo_auth::CibaStatePortError::Unavailable) })
    }
}

impl nazo_auth::AdminGrantRepositoryPort for Unavailable {
    fn page(
        &self,
        _tenant_id: uuid::Uuid,
        _limit: i64,
        _offset: i64,
    ) -> nazo_auth::AdminGrantFuture<'_, nazo_auth::AdminGrantPage> {
        Box::pin(async { Err(nazo_auth::AuthorizationPortError::Unavailable) })
    }

    fn revoke_by_client_id<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _user_id: uuid::Uuid,
        _client_id: &'a str,
        _admin_user_id: uuid::Uuid,
    ) -> nazo_auth::AdminGrantRevokeFuture<'a> {
        Box::pin(async {
            Err(nazo_auth::AdminGrantRevokeError::Revoke(
                nazo_auth::AuthorizationPortError::Unavailable,
            ))
        })
    }
}

impl nazo_auth::BackchannelLogoutOutboxPort for Unavailable {
    fn enqueue_idempotent_batch<'a>(
        &'a self,
        _deliveries: &'a [nazo_auth::IdempotentBackchannelLogoutDelivery],
    ) -> nazo_auth::LogoutFuture<'a, ()> {
        Box::pin(async { Err(nazo_auth::LogoutDependencyError::Unavailable) })
    }
}

impl nazo_persistence::TenantDirectoryStore for Unavailable {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_identity::TenantDirectorySnapshot, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn find_active_binding(
        &self,
        _tenant_id: nazo_identity::TenantId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Option<nazo_identity::TenantDirectoryBinding>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::Openid4vcTrustPolicyStore for Unavailable {
    fn for_client<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _public_client_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<nazo_persistence::ClientTrustPolicy, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn active_for_origin<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _resource_id: &'a str,
        _wallet_origin: &'a str,
        _expected_digest: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_persistence::Openid4vcTrustPolicyRecord>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::CibaAccountStore for Unavailable {
    fn by_email<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _email: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<nazo_identity::PublicAccount>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn by_id(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<nazo_identity::PublicAccount>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::AdminAccessRequestStore for Unavailable {
    fn approved_delivery_with_required_audit_matches<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _user_id: nazo_identity::UserId,
        _request_id: uuid::Uuid,
        _approved_client_id: uuid::Uuid,
        _client_id: &'a str,
        _secret_binding: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<bool, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn approve_with_required_audit<'a>(
        &'a self,
        _tenant: nazo_identity::TenantContext,
        _request_id: uuid::Uuid,
        _actor_user_id: nazo_identity::UserId,
        _client: &'a nazo_auth::PreparedClientRegistration,
        _source_ip_hash: String,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<nazo_persistence::AdminAccessRequestApproval, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn reject_with_required_audit(
        &self,
        _tenant: nazo_identity::TenantContext,
        _request_id: uuid::Uuid,
        _actor_user_id: nazo_identity::UserId,
        _admin_note: String,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_identity::AccessRequest, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn page<'a>(
        &'a self,
        _tenant_id: nazo_identity::TenantId,
        _limit: i64,
        _offset: i64,
        _search: Option<&'a str>,
        _status: Option<nazo_identity::AccessRequestStatus>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<nazo_identity::AccessRequestPage, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn by_id(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _id: uuid::Uuid,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<nazo_identity::AccessRequest>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::BackchannelLogoutDeliveryStore for Unavailable {
    fn claim_due(
        &self,
        _limit: i64,
        _lock_timeout_seconds: i32,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Vec<nazo_auth::BackchannelLogoutDelivery>, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn complete(
        &self,
        _delivery_id: uuid::Uuid,
        _expected_attempts: i32,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }

    fn fail<'a>(
        &'a self,
        _delivery_id: uuid::Uuid,
        _expected_attempts: i32,
        _next_attempt_at: Option<jiff::Timestamp>,
        _last_error: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_persistence::ControllerRegistryPort for Unavailable {
    fn renew_controller_key(
        &self,
        _deployment_id: String,
        _controller_id: String,
        _previous_kid: String,
        _public_key: [u8; 32],
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<Option<String>, nazo_persistence::ControllerRegistryError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn issue_identity_approval_with_required_audit(
        &self,
        _command: nazo_persistence::IdentityApprovalCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedIdentityApproval, nazo_persistence::IdentityApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::IdentityApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_creation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotCreationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_rotation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotRotationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_slot_revocation_with_required_audit(
        &self,
        _command: nazo_persistence::SlotRevocationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredControllerSlot, nazo_persistence::CommitWithApprovalError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::CommitWithApprovalError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn list_slots<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_persistence::StoredControllerSlot>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn admitted_controllers<'a>(
        &'a self,
        _deployment_id: &'a str,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Vec<nazo_persistence::AdmittedController>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn admitted_controller_by_kid<'a>(
        &'a self,
        _deployment_id: &'a str,
        _kid: &'a str,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_persistence::AdmittedController>,
            nazo_persistence::ControllerRegistryError,
        >,
    > {
        Box::pin(async {
            Err(nazo_persistence::ControllerRegistryError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }
}

impl nazo_persistence::RecoveryRootPort for Unavailable {
    fn issue_rotation_approval_with_required_audit(
        &self,
        _command: nazo_persistence::RecoveryApprovalCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedIdentityApproval, nazo_persistence::RecoveryRotationError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRotationError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn commit_rotation_with_required_audit(
        &self,
        _command: nazo_persistence::RecoveryRotationCommand,
        _audit: nazo_persistence::AdminIdentityAudit,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::StoredRecoveryRoot, nazo_persistence::RecoveryRotationError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRotationError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn current_root<'a>(
        &'a self,
        _deployment_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<nazo_persistence::StoredRecoveryRoot>, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn issue_recovery_challenge(
        &self,
        _challenge: nazo_persistence::NewRecoveryChallenge,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::IssuedRecoveryChallenge, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }

    fn submit_recovery_challenge(
        &self,
        _submission: nazo_persistence::RecoverySubmission,
        _now: jiff::Timestamp,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::RecoveredSlotCommit, nazo_persistence::RecoveryRootError>,
    > {
        Box::pin(async {
            Err(nazo_persistence::RecoveryRootError::Transport(
                anyhow::anyhow!("capability is unavailable in the Workers profile"),
            ))
        })
    }
}

impl nazo_persistence::Openid4vciStore for Unavailable {
    fn insert_offer<'a>(
        &'a self,
        _offer: &'a nazo_openid4vci::StoredCredentialOffer,
        _issuer_state_hash: Option<&'a str>,
        _pre_authorized_code_hash: Option<&'a str>,
        _tx_code_hash: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }
}

impl nazo_persistence::Openid4vciDatasetStore for Unavailable {
    fn datasets_available<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _subject_id: uuid::Uuid,
        _credential_configuration_ids: &'a [String],
    ) -> futures_util::future::BoxFuture<'a, Result<bool, nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn dataset<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _subject_id: uuid::Uuid,
        _credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<serde_json::Value>, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn managed_dataset<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _subject_id: uuid::Uuid,
        _credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<
            Option<nazo_persistence::ManagedCredentialDataset>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn upsert_managed_dataset(
        &self,
        _write: nazo_persistence::ManagedCredentialDatasetWrite,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Option<nazo_persistence::ManagedCredentialDataset>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn delete_managed_dataset<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _actor_user_id: uuid::Uuid,
        _subject_id: uuid::Uuid,
        _credential_configuration_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<bool, nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }
}

impl nazo_persistence::Openid4vcSubjectStore for Unavailable {
    fn is_active(
        &self,
        _tenant_id: nazo_identity::TenantId,
        _subject_id: nazo_identity::UserId,
    ) -> futures_util::future::BoxFuture<'_, Result<bool, nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async { Err(nazo_identity::ports::RepositoryError::Unavailable) })
    }
}

impl nazo_openid4vci::AuthorizationOfferPort for Unavailable {
    fn resolve_authorization_offer<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _issuer_state_hash: &'a str,
        _subject_id: uuid::Uuid,
        _client_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vci::CredentialAuthorization>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }
}

impl nazo_openid4vci::CredentialStorePort for Unavailable {
    fn upsert_access<'a>(
        &'a self,
        _token_hash: &'a str,
        _access: &'a nazo_openid4vci::CredentialAccess,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn persist_pre_authorized_access<'a>(
        &'a self,
        _offer: &'a [u8],
        _token_hash: &'a str,
        _access: &'a nazo_openid4vci::CredentialAccess,
        _registered_client_id: Option<&'a str>,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn offer<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _id: uuid::Uuid,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vci::StoredCredentialOffer>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn prepare_pre_authorized_offer<'a>(
        &'a self,
        _tenant_id: uuid::Uuid,
        _code_hash: &'a str,
        _tx_code: Option<&'a str>,
        _client_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vci::PreparedPreAuthorizedOffer>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn issue_nonce<'a>(
        &'a self,
        _nonce: &'a nazo_openid4vci::NonceRecord,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn claim_nonce<'a>(
        &'a self,
        _nonce_hash: &'a str,
        _claim_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn release_nonce<'a>(
        &'a self,
        _nonce_hash: &'a str,
        _claim_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn find_response<'a>(
        &'a self,
        _issuance_id: uuid::Uuid,
        _token_id: uuid::Uuid,
        _request_digest: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vci::StoredCredentialResponse>,
            nazo_openid4vci::CredentialStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        _nonce_hash: &'a str,
        _claim_id: &'a str,
        _handle: &'a nazo_openid4vci::NotificationHandle,
        _response: &'a nazo_openid4vci::StoredCredentialResponse,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn store_response_with_notification<'a>(
        &'a self,
        _handle: &'a nazo_openid4vci::NotificationHandle,
        _response: &'a nazo_openid4vci::StoredCredentialResponse,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn resolve_access<'a>(
        &'a self,
        _token_hash: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<Option<nazo_openid4vci::CredentialAccess>, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        _credential: &'a nazo_openid4vci::DeferredCredential,
        _nonce_hash: &'a str,
        _claim_id: &'a str,
        _response: &'a nazo_openid4vci::StoredCredentialResponse,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        _credential: &'a nazo_openid4vci::DeferredCredential,
        _response: &'a nazo_openid4vci::StoredCredentialResponse,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<'a, Result<(), nazo_openid4vci::CredentialStoreError>>
    {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        _transaction_hash: &'a str,
        _token_id: uuid::Uuid,
        _claim_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<nazo_openid4vci::DeferredClaimOutcome, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn release_deferred<'a>(
        &'a self,
        _transaction_hash: &'a str,
        _token_id: uuid::Uuid,
        _claim_id: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        _transaction_hash: &'a str,
        _token_id: uuid::Uuid,
        _claim_id: &'a str,
        _handle: &'a nazo_openid4vci::NotificationHandle,
        _response: &'a nazo_openid4vci::StoredCredentialResponse,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }

    fn record_notification<'a>(
        &'a self,
        _notification: &'a nazo_openid4vci::IssuanceNotification,
    ) -> nazo_openid4vci::CredentialStoreFuture<
        'a,
        Result<bool, nazo_openid4vci::CredentialStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vci::CredentialStoreError::Unavailable) })
    }
}

impl nazo_openid4vp::PresentationStorePort for Unavailable {
    fn create<'a>(
        &'a self,
        _transaction: &'a nazo_openid4vp::PresentationTransaction,
        _idempotency: nazo_openid4vp::PresentationCreateIdempotency<'a>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<nazo_openid4vp::PresentationCreateOutcome, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }

    fn find_by_create_request<'a>(
        &'a self,
        _idempotency: nazo_openid4vp::PresentationCreateIdempotency<'a>,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vp::PresentationTransaction>,
            nazo_openid4vp::PresentationStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }

    fn request<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<
            Option<nazo_openid4vp::PresentationTransaction>,
            nazo_openid4vp::PresentationStoreError,
        >,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _wallet_nonce: &'a str,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<bool, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }

    fn complete<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _state_hash: &'a str,
        _result: &'a nazo_openid4vp::PresentationResult,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<bool, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }

    fn result<'a>(
        &'a self,
        _transaction_id: uuid::Uuid,
        _now: jiff::Timestamp,
    ) -> nazo_openid4vp::PresentationStoreFuture<
        'a,
        Result<Option<nazo_openid4vp::PresentationResult>, nazo_openid4vp::PresentationStoreError>,
    > {
        Box::pin(async { Err(nazo_openid4vp::PresentationStoreError::Unavailable) })
    }
}

impl nazo_scim_events::EventStorePort for Unavailable {
    fn apply_dispositions_and_poll<'a>(
        &'a self,
        _receiver: &'a nazo_scim_events::EventReceiver,
        _request: &'a nazo_scim_events::ValidatedPollRequest,
    ) -> nazo_scim_events::EventFuture<
        'a,
        Result<nazo_scim_events::EventPage, nazo_scim_events::EventStoreError>,
    > {
        Box::pin(async { Err(nazo_scim_events::EventStoreError::Unavailable) })
    }
}

impl nazo_oauth_server::ports::transient_state::CibaPingDeliveryPort for Unavailable {
    fn claim_due<'a>(
        &'a self,
        _now: i64,
        _lock_until: i64,
        _limit: usize,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<
        'a,
        nazo_auth::CibaPingClaimBatch,
    > {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }

    fn finish<'a>(
        &'a self,
        _delivery: &'a nazo_auth::CibaPingDelivery,
        _outcome: nazo_auth::CibaPingFinishOutcome,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<
        'a,
        nazo_auth::CibaPingFinishResult,
    > {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }
}

impl nazo_oauth_server::ports::transient_state::TenantDirectoryCachePort for Unavailable {
    fn load(
        &self,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<
        '_,
        Option<std::sync::Arc<nazo_identity::TenantDirectorySnapshot>>,
    > {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }

    fn publish_authoritative<'a>(
        &'a self,
        _snapshot: &'a nazo_identity::TenantDirectorySnapshot,
    ) -> nazo_oauth_server::ports::transient_state::TransientStateFuture<'a, bool> {
        Box::pin(async {
            Err(nazo_oauth_server::ports::transient_state::TransientStateError::Unavailable)
        })
    }
}
