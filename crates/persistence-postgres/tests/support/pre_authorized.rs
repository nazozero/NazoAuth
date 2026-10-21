//! Real-adapter fixtures: preparation and commit both use the production port.
use chrono::{DateTime, Duration, Utc};
use nazo_openid4vci::{
    CredentialAccess, CredentialAuthorization, CredentialOfferGrants, CredentialStoreError,
    CredentialStorePort, PreAuthorizedCodeGrant, StoredCredentialOffer,
};
use nazo_postgres::Openid4vciRepository;
use uuid::Uuid;

pub async fn prepared_offer(
    repository: &Openid4vciRepository,
    access: &CredentialAccess,
) -> Vec<u8> {
    let code = Uuid::now_v7().to_string();
    let hash = blake3::hash(code.as_bytes()).to_hex().to_string();
    let offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id: access.tenant_id,
        subject_id: Some(access.subject_id),
        credential_configuration_ids: access.configuration_ids.clone(),
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code: code,
                tx_code: None,
                authorization_server: None,
            }),
        ),
        expires_at: access.expires_at + Duration::seconds(1),
    };
    repository
        .insert_offer(&offer, None, Some(&hash), None)
        .await
        .unwrap();
    repository
        .prepare_pre_authorized_offer(access.tenant_id, &hash, None, &access.client_id, Utc::now())
        .await
        .unwrap()
        .unwrap()
        .commit_token
}

pub trait PreAuthorizedFixture {
    async fn persist_new_offer_access(
        &self,
        hash: &str,
        access: &CredentialAccess,
        client: Option<&str>,
    ) -> Result<(), CredentialStoreError>;
    async fn consume_offer_with_access(
        &self,
        tenant: Uuid,
        hash: &str,
        tx: Option<&str>,
        client: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CredentialAuthorization>, CredentialStoreError>;
}

impl PreAuthorizedFixture for Openid4vciRepository {
    async fn persist_new_offer_access(
        &self,
        hash: &str,
        access: &CredentialAccess,
        client: Option<&str>,
    ) -> Result<(), CredentialStoreError> {
        let offer = prepared_offer(self, access).await;
        self.persist_pre_authorized_access(&offer, hash, access, client)
            .await
    }

    async fn consume_offer_with_access(
        &self,
        tenant: Uuid,
        hash: &str,
        tx: Option<&str>,
        client: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CredentialAuthorization>, CredentialStoreError> {
        let Some(prepared) = self
            .prepare_pre_authorized_offer(tenant, hash, tx, client, now)
            .await?
        else {
            return Ok(None);
        };
        let auth = &prepared.authorization;
        let access = CredentialAccess {
            authorization_id: Some(Uuid::now_v7()),
            mtls_x5t_s256: None,
            proof_origin: nazo_openid4vci::CredentialProofOrigin::AnonymousPreAuthorized,
            token_id: Uuid::now_v7(),
            tenant_id: auth.tenant_id,
            subject_id: auth.subject_id,
            client_id: auth.client_id.clone(),
            configuration_ids: auth.configuration_ids.clone(),
            credential_identifiers: auth.credential_identifiers.clone(),
            dpop_jkt: None,
            expires_at: auth.expires_at,
        };
        let hash = blake3::hash(access.token_id.as_bytes())
            .to_hex()
            .to_string();
        match self
            .persist_pre_authorized_access(&prepared.commit_token, &hash, &access, None)
            .await
        {
            Ok(()) => Ok(Some(prepared.authorization)),
            Err(CredentialStoreError::InvalidTransition) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
