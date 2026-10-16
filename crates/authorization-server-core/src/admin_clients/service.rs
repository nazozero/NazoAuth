use base64::Engine as _;
use uuid::Uuid;

use super::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, AdminClientRepositoryPort,
    CreateClientRequest, CreatedClient, PatchClientRequest, PreparedClientRegistration,
    SectorIdentifierResolverPort, SuppliedClientSecret,
};
use crate::ClientSecretDigesterPort;
use crate::OAuthClient;

/// Concrete service shape is cheap to clone (repository and crypto handles are
/// internally shared), so long-lived callers such as the one-shot tenant-resource
/// operator path can hold it by value next to the HTTP composition.
#[derive(Clone)]
pub struct AdminClientService<R, S, C> {
    pub(super) repository: R,
    pub(super) sector_identifiers: S,
    pub(super) crypto: C,
    pub(super) policy: AdminClientPolicy,
}

impl<R, S, C> AdminClientService<R, S, C>
where
    R: AdminClientRepositoryPort,
    S: SectorIdentifierResolverPort,
    C: AdminClientCryptoPort,
{
    pub const fn new(
        repository: R,
        sector_identifiers: S,
        crypto: C,
        policy: AdminClientPolicy,
    ) -> Self {
        Self {
            repository,
            sector_identifiers,
            crypto,
            policy,
        }
    }

    pub async fn page(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<OAuthClient>, i64), AdminClientError> {
        self.repository
            .page(self.policy.tenant.tenant_id.as_uuid(), offset, limit)
            .await
            .map_err(AdminClientError::Repository)
    }

    pub async fn detail(&self, client_id: &str) -> Result<OAuthClient, AdminClientError> {
        self.repository
            .by_client_id(self.policy.tenant.tenant_id.as_uuid(), client_id)
            .await
            .map_err(AdminClientError::Lookup)?
            .ok_or(AdminClientError::NotFound)
    }

    /// Administrative HTTP creation uses the accepting owner that binds current
    /// actor authority and canonical Required outcome before exposing the secret.
    pub async fn create_with_required_audit(
        &self,
        request: CreateClientRequest,
        actor_id: Uuid,
        source_ip_hash: &str,
    ) -> Result<CreatedClient, AdminClientError> {
        let mut prepared = self.prepare_registration(request).await?.into_write();
        let client = &prepared.client;
        let inserted = self
            .repository
            .insert_with_required_audit(
                client,
                prepared.client_secret_hash.as_deref(),
                prepared.registration_access_token_blake3.as_deref(),
                actor_id,
                source_ip_hash,
            )
            .await
            .map_err(AdminClientError::Write)?;
        Ok(CreatedClient {
            client: inserted,
            issued_secret: prepared.issued_secret.take_after_commit(),
        })
    }

    /// Validate and prepare a registration for a caller that owns a wider transaction boundary.
    ///
    /// Access-request approval uses this path so the client row and approval state can still be
    /// committed by the persistence adapter in one transaction.
    pub async fn prepare_registration(
        &self,
        request: CreateClientRequest,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        super::registration::prepare_client_registration(
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await
    }

    pub async fn update_with_required_audit(
        &self,
        client_id: &str,
        request: PatchClientRequest,
        actor_id: Uuid,
        source_ip_hash: &str,
    ) -> Result<OAuthClient, AdminClientError> {
        let (expected, updated) = self.prepare_update(client_id, request).await?;
        self.repository
            .update_with_required_audit(&expected, &updated, actor_id, source_ip_hash)
            .await
            .map_err(AdminClientError::Write)
    }

    async fn prepare_update(
        &self,
        client_id: &str,
        request: PatchClientRequest,
    ) -> Result<(OAuthClient, OAuthClient), AdminClientError> {
        let expected = self.detail(client_id).await?;
        let updated = super::patch::prepare_client_patch(
            expected.clone(),
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await?;
        Ok((expected, updated))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/admin_clients/service.rs"]
mod tests;

impl<R, S, C> AdminClientService<R, S, C>
where
    R: AdminClientRepositoryPort,
    S: SectorIdentifierResolverPort,
    C: AdminClientCryptoPort + ClientSecretDigesterPort,
{
    /// Prepare a registration while binding a caller-supplied secret. The
    /// authenticated operator-management path uses this only when it can
    /// deliver that secret to the client out of band; ordinary administrative
    /// registration continues to generate a fresh secret.
    pub async fn prepare_registration_with_secret(
        &self,
        request: CreateClientRequest,
        secret: SuppliedClientSecret,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        if !request.requires_client_secret() {
            return Err(AdminClientError::InvalidRequest(
                "supplied client secret is only valid for confidential client_secret auth"
                    .to_owned(),
            ));
        }
        let mut prepared = super::registration::prepare_client_registration_metadata(
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await?;
        let secret = secret.as_str().map_err(|_| {
            AdminClientError::InvalidRequest("supplied client secret is not UTF-8".to_owned())
        })?;
        let salt =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        prepared.client_secret_hash = Some(self.crypto.client_secret_digest(
            secret,
            &self.policy.client_secret_pepper,
            &salt,
        ));
        Ok(prepared)
    }
}
