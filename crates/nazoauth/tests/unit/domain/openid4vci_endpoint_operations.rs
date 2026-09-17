use nazo_digital_credentials::EphemeralEncryptionKey;
use nazo_oauth_server::domain::openid4vc::{Openid4vcCredentialCrypto, Openid4vcProofValidator};
use nazo_oauth_server::domain::openid4vc_endpoints::{
    ServerCredentialIssuerOperations, openid4vci_authorization_detail,
};
use nazo_openid4vci::application::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CredentialHttpError, CredentialIssuerOperations, CredentialRequestBody,
    CredentialRequestContext, CredentialResponseBody, PreAuthorizedTokenRequest,
};
use nazo_openid4vci::{
    CredentialAccess, CredentialAuthorization, CredentialConfiguration, CredentialRequest,
    CredentialStoreError, CredentialStoreFuture, CredentialStorePort, DeferredCredential,
    DeferredCredentialClaim, DeferredCredentialRequest, IssuanceNotification, NonceRecord,
    NotificationHandle, NotificationRequest, StoredCredentialOffer, StoredCredentialResponse,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use diesel::sql_query;
use diesel::sql_types::{Integer, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use nazo_auth::SigningPurpose;
use nazo_auth::{
    CommitTokenIssuance, CommitTokenIssuanceResult, RefreshToken, TokenPortError,
    TokenRepositoryPort, TokenRevocation,
};
use nazo_digital_credentials::{VcIssuerTrustPolicy, encrypt_ecdh_es};
use nazo_key_management::{
    KeyManager, KeySettings, LocalKeyRegistration, Openid4vcMaterial, Openid4vcPublicMaterial,
};
use nazo_openid4vci::{CredentialResponse, ProofTypeMetadata};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::config::ConfigSource;
use crate::runtime_modules::test_support::runtime_module_registry_with_modules_for_test;
use crate::settings::Settings;
use nazo_identity::DEFAULT_ORGANIZATION_ID;
use nazo_identity::DEFAULT_REALM_ID;
use nazo_identity::DEFAULT_TENANT_ID;
use nazo_oauth_server::services::ServerAuthorizationService;
use nazo_oauth_server::services::ServerTokenService;

struct IssuerFixture {
    operations: ServerCredentialIssuerOperations,
    issuer: String,
    tenant_id: Uuid,
    token_service: Arc<ServerTokenService>,
    request_encryption: EphemeralEncryptionKey,
    datasets: Arc<dyn nazo_persistence::Openid4vciDatasetStore>,
}

impl std::ops::Deref for IssuerFixture {
    type Target = ServerCredentialIssuerOperations;

    fn deref(&self) -> &Self::Target {
        &self.operations
    }
}

impl IssuerFixture {
    async fn access(&self, context: &CredentialRequestContext) -> Result<(), CredentialHttpError> {
        match self
            .operations
            .credential(
                context.clone(),
                CredentialRequestBody::Json(credential_request()),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.status == 400 => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn invalid_pool() -> nazo_postgres::DbPool {
    nazo_postgres::create_pool(
        "postgres://nazo_openid4vci_unit:nazo_openid4vci_unit@127.0.0.1:1/nazo".to_owned(),
        1,
    )
    .expect("pool construction must not connect")
}

async fn fixture_crypto() -> Openid4vcCredentialCrypto {
    let settings = KeySettings {
        rotation_interval: chrono::Duration::days(30),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::hours(1),
    };
    let keyset = nazo_key_management::test_support::key_manager(settings)
        .await
        .expect("database-backed endpoint keyset should initialize");
    let signing_kid = keyset
        .database_register_local(LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [
                SigningPurpose::Credential,
                SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect(),
        })
        .await
        .expect("database endpoint signing key registration");
    let signing_key = KeyPair::from_pem(
        &keyset
            .database_local_private_key_pem(&signing_kid)
            .expect("database endpoint signing key PEM"),
    )
    .expect("database endpoint P-256 signing key");
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("endpoint CA key");
    let now = time::OffsetDateTime::now_utc();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("endpoint CA certificate");

    let mut leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("endpoint leaf SAN");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::hours(1);
    let leaf = leaf_params
        .signed_by(&signing_key, &ca)
        .expect("endpoint leaf certificate");

    keyset.set_openid4vc_material_for_test(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid,
            certificate_chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
            trust_anchors_pem: ca.pem(),
            revocation_snapshot: None,
        },
        iaca_private_materials: Default::default(),
    });
    Openid4vcCredentialCrypto::new_with_policies(
        keyset,
        VcIssuerTrustPolicy::san_bound(),
        nazo_oauth_server::policy::Openid4vcRevocationPolicy::Disabled,
        Arc::new(crate::adapters::mdoc_signer::TokioMdocDocumentSigner),
    )
    .expect("endpoint credential crypto")
}

async fn operations(enabled: bool) -> IssuerFixture {
    let pool = invalid_pool();
    let mut valkey_builder = fred::prelude::Builder::default_centralized();
    valkey_builder.with_performance_config(|performance: &mut fred::prelude::PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(100);
    });
    valkey_builder.with_connection_config(|connection: &mut fred::prelude::ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(100);
        connection.internal_command_timeout = std::time::Duration::from_millis(100);
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder
        .build()
        .expect("valkey fixture should build without connecting");
    let valkey_connection = nazo_valkey::test_support::scoped_connection(valkey);
    operations_with_inputs(
        pool,
        valkey_connection,
        enabled,
        BTreeMap::from([("unit-config".to_owned(), unit_configuration())]),
        BTreeSet::new(),
    )
    .await
}

fn unit_configuration() -> CredentialConfiguration {
    CredentialConfiguration {
        format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
        scope: Some("unit-credential".to_owned()),
        cryptographic_binding_methods_supported: Vec::new(),
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: Default::default(),
        vct: Some("https://issuer.example/unit".to_owned()),
        doctype: None,
        credential_metadata: None,
    }
}

async fn operations_with_inputs(
    pool: nazo_postgres::DbPool,
    valkey_connection: nazo_valkey::ValkeyConnection,
    enabled: bool,
    configurations: BTreeMap<String, CredentialConfiguration>,
    deferred_configurations: BTreeSet<String>,
) -> IssuerFixture {
    operations_with_overrides(
        pool,
        valkey_connection,
        enabled,
        configurations,
        deferred_configurations,
        None,
        None,
    )
    .await
}

async fn operations_with_overrides(
    pool: nazo_postgres::DbPool,
    valkey_connection: nazo_valkey::ValkeyConnection,
    enabled: bool,
    configurations: BTreeMap<String, CredentialConfiguration>,
    deferred_configurations: BTreeSet<String>,
    store_override: Option<Arc<dyn nazo_persistence::Openid4vciStore>>,
    token_repository: Option<Arc<dyn nazo_auth::TokenRepositoryPort>>,
) -> IssuerFixture {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("unit settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.modules.enable_openid4vci_issuer = enabled;
    let keyset = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let token_service = Arc::new(ServerTokenService::from_port(
        token_repository
            .unwrap_or_else(|| Arc::new(nazo_postgres::TokenIssuanceRepository::new(pool.clone()))),
        Arc::new(nazo_valkey::TokenIssuanceStateAdapter::new(
            &valkey_connection,
        )),
        keyset.clone(),
    ));
    let authorization = Arc::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(pool.clone(), DEFAULT_TENANT_ID),
        Arc::new(nazo_valkey::AuthorizationStateAdapter::new(
            &valkey_connection,
        )),
        keyset.clone(),
    ));
    let mut active_modules = crate::test_support::persisted_runtime_modules_fixture();
    if enabled {
        active_modules.extend([
            nazo_runtime_modules::ModuleId::Openid4vciIssuer,
            nazo_runtime_modules::ModuleId::AuthorizationDetails,
        ]);
    }
    let runtime =
        runtime_module_registry_with_modules_for_test(pool.clone(), &settings, active_modules)
            .expect("runtime module fixture should build");
    let proof_validator = Openid4vcProofValidator::new(json!({ "keys": [] }))
        .expect("proof validator fixture should build");
    let crypto = fixture_crypto().await;
    let store: Arc<dyn nazo_persistence::Openid4vciStore> = store_override.unwrap_or_else(|| {
        Arc::new(nazo_postgres::Openid4vciRepository::new(
            pool.clone(),
            [0x51; 32],
        ))
    });
    let users: Arc<dyn nazo_persistence::Openid4vcSubjectStore> =
        Arc::new(nazo_postgres::UserRepository::new(pool.clone()));
    let datasets: Arc<dyn nazo_persistence::Openid4vciDatasetStore> = Arc::new(
        nazo_postgres::Openid4vciDatasetRepository::new(pool, [0x51; 32]),
    );
    let issuer = settings.endpoint.issuer;
    let request_encryption =
        EphemeralEncryptionKey::derive(&[0x51; 32], b"credential-request-encryption")
            .expect("fixture encryption key should derive");
    let operations = ServerCredentialIssuerOperations::new(
        store,
        users,
        datasets.clone(),
        DEFAULT_TENANT_ID,
        [0x51; 32],
        token_service.clone(),
        authorization,
        runtime.snapshot_store(),
        Arc::new(crate::bootstrap::RegistrationSecretHasher),
        crypto,
        proof_validator,
        issuer.clone(),
        configurations,
        deferred_configurations,
        nazo_auth::DpopNoncePolicy::Optional,
    )
    .expect("credential issuer fixture should build");
    IssuerFixture {
        operations,
        issuer,
        tenant_id: DEFAULT_TENANT_ID,
        token_service,
        request_encryption,
        datasets,
    }
}

/// Token repository test double that keeps every read real except the two
/// active-subject projections, which report a backend outage. Used to prove
/// the credential access path fails closed with a 503 when subject state
/// cannot be read, while token decode and revocation checks still succeed.
struct SubjectStateOutage {
    inner: Arc<dyn TokenRepositoryPort>,
}

impl TokenRepositoryPort for SubjectStateOutage {
    fn commit_token_issuance<'a>(
        &'a self,
        input: CommitTokenIssuance,
    ) -> nazo_auth::TokenFuture<'a, CommitTokenIssuanceResult> {
        self.inner.commit_token_issuance(input)
    }

    fn userinfo_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        subject: nazo_auth::UserinfoSubjectRef<'a>,
        client_id: &'a str,
    ) -> nazo_auth::TokenFuture<'a, Option<nazo_auth::UserinfoSnapshot>> {
        self.inner.userinfo_snapshot(tenant_id, subject, client_id)
    }

    fn refresh_token<'a>(
        &'a self,
        tenant_id: Uuid,
        raw_token: &'a str,
    ) -> nazo_auth::TokenFuture<'a, Option<RefreshToken>> {
        self.inner.refresh_token(tenant_id, raw_token)
    }

    fn inspect_lost_response_successor<'a>(
        &'a self,
        token: &'a RefreshToken,
        client_id: Uuid,
        retry_started_at: chrono::DateTime<chrono::Utc>,
    ) -> nazo_auth::TokenFuture<'a, Option<RefreshToken>> {
        self.inner
            .inspect_lost_response_successor(token, client_id, retry_started_at)
    }

    fn active_subject_claims<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> nazo_auth::TokenFuture<'a, Option<nazo_identity::SubjectClaims>> {
        self.inner.active_subject_claims(tenant_id, user_id)
    }

    fn active_subject_id<'a>(
        &'a self,
        _tenant_id: Uuid,
        _user_id: Uuid,
    ) -> nazo_auth::TokenFuture<'a, Option<Uuid>> {
        Box::pin(async { Err(TokenPortError::Unavailable) })
    }

    fn active_subject_id_by_access_token<'a>(
        &'a self,
        _tenant_id: Uuid,
        _jti: &'a str,
    ) -> nazo_auth::TokenFuture<'a, Option<Uuid>> {
        Box::pin(async { Err(TokenPortError::Unavailable) })
    }

    fn revoke_issued_tokens<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &'a str,
        access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> nazo_auth::TokenFuture<'a, ()> {
        self.inner.revoke_issued_tokens(
            tenant_id,
            client_id,
            access_token_jti,
            access_token_expires_at,
            refresh_token_family_id,
        )
    }

    fn access_token_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        jti: &'a str,
    ) -> nazo_auth::TokenFuture<'a, bool> {
        self.inner.access_token_revoked(tenant_id, jti)
    }

    fn refresh_family_active<'a>(
        &'a self,
        tenant_id: Uuid,
        family_id: Uuid,
        user_id: Uuid,
    ) -> nazo_auth::TokenFuture<'a, bool> {
        self.inner
            .refresh_family_active(tenant_id, family_id, user_id)
    }

    fn revoke_token<'a>(&'a self, input: TokenRevocation<'a>) -> nazo_auth::TokenFuture<'a, usize> {
        self.inner.revoke_token(input)
    }
}

/// Credential store test double that deactivates the authenticated
/// `oauth_clients` row inside `persist_pre_authorized_access`, reproducing the
/// window between pre-authorized offer consumption and final grant
/// persistence where a registered client can be deactivated. Every other
/// transition delegates to the real PostgreSQL store unchanged.
struct ClientDeactivatingStore {
    inner: Arc<dyn nazo_persistence::Openid4vciStore>,
    pool: nazo_postgres::DbPool,
}

impl ClientDeactivatingStore {
    async fn deactivate(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<(), CredentialStoreError> {
        let mut connection = nazo_postgres::get_conn(&self.pool)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
        sql_query(
            "UPDATE oauth_clients SET is_active = FALSE WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<Text, _>(client_id)
        .execute(&mut connection)
        .await
        .map_err(|_| CredentialStoreError::Unavailable)?;
        Ok(())
    }
}

impl CredentialStorePort for ClientDeactivatingStore {
    fn upsert_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.upsert_access(token_hash, access)
    }

    fn persist_pre_authorized_access<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
        registered_client_id: Option<&'a str>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if let Some(client_id) = registered_client_id {
                self.deactivate(access.tenant_id, client_id).await?;
            }
            self.inner
                .persist_pre_authorized_access(token_hash, access, registered_client_id)
                .await
        })
    }

    fn offer<'a>(
        &'a self,
        tenant_id: Uuid,
        id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        self.inner.offer(tenant_id, id, now)
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        tenant_id: Uuid,
        code_hash: &'a str,
        tx_code: Option<&'a str>,
        client_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAuthorization>, CredentialStoreError>>
    {
        self.inner
            .consume_pre_authorized_offer(tenant_id, code_hash, tx_code, client_id, now)
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.issue_nonce(nonce)
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.claim_nonce(nonce_hash, claim_id, now)
    }

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_nonce(nonce_hash, claim_id, now)
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.release_nonce(nonce_hash, claim_id, now)
    }

    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .finalize_nonce_with_notification(nonce_hash, claim_id, handle, now)
    }

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        self.inner
            .find_response(issuance_id, token_id, request_digest, now)
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_nonce_with_notification_and_response(
            nonce_hash, claim_id, handle, response, now,
        )
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_response_with_notification(handle, response, now)
    }

    fn resolve_access<'a>(
        &'a self,
        token_hash: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        self.inner.resolve_access(token_hash, now)
    }

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.store_deferred(credential)
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_deferred_and_finalize_nonce(credential, nonce_hash, claim_id, now)
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.store_deferred_and_finalize_nonce_with_response(
            credential, nonce_hash, claim_id, response, now,
        )
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner
            .store_deferred_with_response(credential, response, now)
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        self.inner
            .claim_ready_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .finalize_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner
            .release_deferred(transaction_hash, token_id, claim_id, now)
    }

    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_deferred_with_notification(
            transaction_hash,
            token_id,
            claim_id,
            handle,
            now,
        )
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: chrono::DateTime<chrono::Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.finalize_deferred_with_notification_and_response(
            transaction_hash,
            token_id,
            claim_id,
            handle,
            response,
            now,
        )
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.inner.record_notification(notification)
    }

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.issue_notification_handle(handle)
    }
}

impl nazo_persistence::Openid4vciStore for ClientDeactivatingStore {
    fn insert_offer<'a>(
        &'a self,
        offer: &'a StoredCredentialOffer,
        issuer_state_hash: Option<&'a str>,
        pre_authorized_code_hash: Option<&'a str>,
        tx_code_hash: Option<&'a str>,
    ) -> futures_util::future::BoxFuture<'a, Result<(), CredentialStoreError>> {
        self.inner.insert_offer(
            offer,
            issuer_state_hash,
            pre_authorized_code_hash,
            tx_code_hash,
        )
    }
}

fn live_configuration(configuration_id: &str) -> (String, CredentialConfiguration) {
    (
        configuration_id.to_owned(),
        CredentialConfiguration {
            format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
            scope: Some(format!("{configuration_id}-scope")),
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            proof_types_supported: BTreeMap::from([(
                "jwt".to_owned(),
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: vec!["ES256".to_owned()],
                    key_attestations_required: None,
                },
            )]),
            vct: Some(format!("https://issuer.example/{configuration_id}")),
            doctype: None,
            credential_metadata: None,
        },
    )
}

struct LiveEndpointFixture {
    issuer: IssuerFixture,
    pool: nazo_postgres::DbPool,
    admin_id: Uuid,
    subject_id: Uuid,
    wallet_client_id: String,
}

impl LiveEndpointFixture {
    async fn new(configuration_id: &str, deferred: bool) -> Option<Self> {
        Self::new_with_overrides(configuration_id, deferred, None, None).await
    }

    async fn new_with_overrides(
        configuration_id: &str,
        deferred: bool,
        store_override: Option<Arc<dyn nazo_persistence::Openid4vciStore>>,
        token_repository: Option<Arc<dyn TokenRepositoryPort>>,
    ) -> Option<Self> {
        let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        nazo_postgres::run_pending_migrations(&database_url)
            .await
            .expect("OpenID4VC endpoint fixture migrations should succeed");
        let pool = nazo_postgres::create_pool(database_url, 4)
            .expect("OpenID4VC endpoint fixture pool should build");
        let mut valkey_builder = fred::prelude::Builder::from_config(
            fred::prelude::Config::from_url(&valkey_url)
                .expect("OpenID4VC endpoint fixture VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(
            |performance: &mut fred::prelude::PerformanceConfig| {
                performance.default_command_timeout = std::time::Duration::from_secs(2);
            },
        );
        valkey_builder.with_connection_config(
            |connection: &mut fred::prelude::ConnectionConfig| {
                connection.connection_timeout = std::time::Duration::from_secs(2);
                connection.internal_command_timeout = std::time::Duration::from_secs(2);
                connection.max_command_attempts = 1;
            },
        );
        let valkey = valkey_builder
            .build()
            .expect("OpenID4VC endpoint fixture Valkey client should build");
        valkey
            .init()
            .await
            .expect("OpenID4VC endpoint fixture Valkey should connect");
        let valkey_connection = nazo_valkey::test_support::scoped_connection(valkey);
        let (configuration_key, configuration) = live_configuration(configuration_id);
        let issuer = operations_with_overrides(
            pool.clone(),
            valkey_connection,
            true,
            BTreeMap::from([(configuration_key, configuration)]),
            if deferred {
                BTreeSet::from([configuration_id.to_owned()])
            } else {
                BTreeSet::new()
            },
            store_override,
            token_repository,
        )
        .await;

        let admin_id = Uuid::now_v7();
        let subject_id = Uuid::now_v7();
        let wallet_client_id = format!("live-wallet-{}", subject_id.simple());
        let mut connection = nazo_postgres::get_conn(&pool)
            .await
            .expect("OpenID4VC endpoint fixture database connection");
        for (id, role, admin_level) in [(admin_id, "admin", 1_i32), (subject_id, "user", 0_i32)] {
            sql_query(
                "INSERT INTO users
                    (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level)
                 VALUES ($1,$2,$3,$4,$5,$6,'openid4vci-live-fixture',$7,$8)",
            )
            .bind::<SqlUuid, _>(id)
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
            .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
            .bind::<Text, _>(format!("openid4vci-live-{id}"))
            .bind::<Text, _>(format!("openid4vci-live-{id}@example.test"))
            .bind::<Text, _>(role)
            .bind::<Integer, _>(admin_level)
            .execute(&mut connection)
            .await
            .expect("OpenID4VC endpoint fixture user insert");
        }
        // A registered, active client row is required by
        // `persist_pre_authorized_access` whenever the token request carried an
        // authenticated client identity; without it the FOR SHARE re-check
        // fails closed and no access grant is persisted.
        sql_query(
            "INSERT INTO oauth_clients (\
                id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
                redirect_uris, scopes, grant_types, token_endpoint_auth_method, is_active, security_policy\
            ) VALUES ($1, $2, $3, $4, $5, 'openid4vci-live-wallet', 'public', '[]'::jsonb, '[]'::jsonb,\
                '[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"]'::jsonb, 'none', TRUE,\
                jsonb_build_object(\
                    'version', 1, 'assurance', 'baseline',\
                    'require_signed_authorization_request', false,\
                    'require_signed_authorization_response', false,\
                    'require_signed_introspection_response', false,\
                    'session_management', false, 'allow_cross_device_flows', false,\
                    'allow_confidential_oidc_without_pkce', false))",
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(wallet_client_id.clone())
        .execute(&mut connection)
        .await
        .expect("OpenID4VC endpoint fixture wallet client insert");
        drop(connection);
        let claims = json!({"given_name":"OpenID4VC Live Fixture", "sub": subject_id});
        let inserted = issuer
            .datasets
            .upsert_managed_dataset(nazo_persistence::ManagedCredentialDatasetWrite {
                tenant_id: DEFAULT_TENANT_ID,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: configuration_id.to_owned(),
                claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .expect("OpenID4VC endpoint fixture dataset upsert");
        assert!(
            inserted,
            "OpenID4VC endpoint fixture dataset must be inserted"
        );
        Some(Self {
            issuer,
            pool,
            admin_id,
            subject_id,
            wallet_client_id,
        })
    }

    async fn cleanup(self) {
        let mut connection = nazo_postgres::get_conn(&self.pool)
            .await
            .expect("OpenID4VC endpoint fixture cleanup connection");
        for query in [
            "DELETE FROM openid4vci_notifications WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_issuance_responses WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_deferred_transactions WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_access_grants WHERE subject_id = $1",
            "DELETE FROM openid4vci_offers WHERE subject_id = $1",
            "DELETE FROM openid4vci_credential_dataset_events WHERE subject_id = $1",
            "DELETE FROM openid4vci_credential_datasets WHERE subject_id = $1",
            "DELETE FROM users WHERE id IN ($1,$2)",
        ] {
            if query.contains("users WHERE") {
                sql_query(query)
                    .bind::<SqlUuid, _>(self.subject_id)
                    .bind::<SqlUuid, _>(self.admin_id)
                    .execute(&mut connection)
                    .await
                    .expect("OpenID4VC endpoint fixture cleanup query");
            } else {
                sql_query(query)
                    .bind::<SqlUuid, _>(self.subject_id)
                    .execute(&mut connection)
                    .await
                    .expect("OpenID4VC endpoint fixture cleanup query");
            }
        }
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(self.wallet_client_id)
            .execute(&mut connection)
            .await
            .expect("OpenID4VC endpoint fixture wallet client cleanup");
    }
}

fn pre_authorized_code(offer: &CreateCredentialOfferResponse) -> String {
    let grants = offer
        .credential_offer
        .grants
        .as_ref()
        .expect("pre-authorized offer grants");
    let value = grants
        .0
        .get(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
        .expect("pre-authorized grant");
    serde_json::from_value::<nazo_openid4vci::PreAuthorizedCodeGrant>(value.clone())
        .expect("pre-authorized grant JSON")
        .pre_authorized_code
}

fn jwt_credential_request(configuration_id: &str, issuer: &str, nonce: &str) -> CredentialRequest {
    let fixture = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let jwk = serde_json::from_value(fixture.public_jwk("openid4vci-proof"))
        .expect("credential proof JWK");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("openid4vci-proof+jwt".to_owned());
    header.jwk = Some(jwk);
    let jwt = fixture.encode_jwt(
        &header,
        &json!({
            "aud": issuer,
            "nonce": nonce,
            "iat": chrono::Utc::now().timestamp(),
        }),
    );
    CredentialRequest {
        credential_identifier: Some(nazo_openid4vci::CredentialIdentifier(
            openid4vci_authorization_detail("https://issuer.example", configuration_id)
                ["credential_identifiers"][0]
                .as_str()
                .expect("fixture identifier")
                .to_owned(),
        )),
        credential_configuration_id: None,
        proofs: Some(nazo_openid4vci::Proofs(BTreeMap::from([(
            "jwt".to_owned(),
            vec![json!(jwt)],
        )]))),
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
}

fn credential_request() -> CredentialRequest {
    CredentialRequest {
        credential_identifier: None,
        credential_configuration_id: Some("unit-config".to_owned()),
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
}

fn request_context() -> CredentialRequestContext {
    CredentialRequestContext {
        bearer_token: "not-a-token".to_owned(),
        access_token_scheme: AccessTokenScheme::Bearer,
        dpop_proof: None,
        mtls_x5t_s256: None,
        request_url: "/openid4vci/credential".to_owned(),
        method: "POST",
    }
}

fn assert_error(
    error: CredentialHttpError,
    status: u16,
    code: &'static str,
    description: &'static str,
) {
    assert_eq!(error.status, status);
    assert_eq!(error.error, code);
    assert_eq!(error.description, description);
    assert!(error.dpop_nonce.is_none());
}

#[tokio::test]
async fn credential_decrypts_a_valid_encrypted_request_before_access_validation() {
    let issuer = operations(true).await;
    let request = credential_request();
    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let encrypted = encrypt_ecdh_es(
        &serde_json::to_vec(&request).expect("credential request should serialize"),
        &jwk,
        Some("application/json"),
    )
    .expect("credential request should encrypt");
    let error = issuer
        .credential(request_context(), CredentialRequestBody::Jwt(encrypted))
        .await
        .expect_err("valid encrypted request should then reach access validation");
    assert_error(error, 401, "invalid_token", "Access token is invalid.");
}

#[tokio::test]
async fn deferred_decrypts_a_valid_encrypted_request_before_access_validation() {
    let issuer = operations(true).await;
    let request = DeferredCredentialRequest {
        transaction_id: "unit-transaction".to_owned(),
        credential_response_encryption: None,
    };
    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let encrypted = encrypt_ecdh_es(
        &serde_json::to_vec(&request).expect("deferred request should serialize"),
        &jwk,
        Some("application/json"),
    )
    .expect("deferred request should encrypt");
    let error = issuer
        .deferred(request_context(), CredentialRequestBody::Jwt(encrypted))
        .await
        .expect_err("valid encrypted request should then reach access validation");
    assert_error(error, 401, "invalid_token", "Access token is invalid.");
}

#[tokio::test]
async fn enabled_metadata_is_signed_and_advertises_request_and_response_encryption() {
    let issuer = operations(true).await;
    let metadata = issuer
        .metadata()
        .await
        .expect("enabled issuer metadata should be available");
    assert_eq!(metadata.credential_issuer, issuer.issuer);
    assert_eq!(metadata.authorization_servers, vec![issuer.issuer.clone()]);
    assert_eq!(
        metadata.credential_endpoint,
        "https://issuer.example/openid4vci/credential"
    );
    assert_eq!(
        metadata.deferred_credential_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/deferred_credential")
    );
    assert_eq!(
        metadata.notification_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/notification")
    );
    assert!(
        !metadata
            .credential_request_encryption
            .as_ref()
            .expect("request encryption metadata")
            .encryption_required
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .alg_values_supported,
        vec!["ECDH-ES".to_owned()]
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .zip_values_supported,
        vec!["DEF".to_owned()]
    );
    assert_eq!(
        metadata
            .batch_credential_issuance
            .as_ref()
            .expect("batch metadata")
            .batch_size,
        10
    );
    assert!(metadata.signed_metadata.is_some());
}

#[tokio::test]
async fn disabled_issuer_rejects_every_mutating_endpoint_before_state_access() {
    let issuer = operations(false).await;
    assert_error(
        issuer.metadata().await.expect_err("metadata disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("offer disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer.nonce(None).await.expect_err("nonce disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Json(credential_request()),
            )
            .await
            .expect_err("credential disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is not accepting new requests.",
    );
    assert_error(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Json(DeferredCredentialRequest {
                    transaction_id: "unit-transaction".to_owned(),
                    credential_response_encryption: None,
                }),
            )
            .await
            .expect_err("deferred disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .notify(
                request_context(),
                NotificationRequest {
                    notification_id: "unit-notification".to_owned(),
                    event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                    event_description: None,
                },
            )
            .await
            .expect_err("notification disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .pre_authorized_token(PreAuthorizedTokenRequest {
                pre_authorized_code: "unit-code".to_owned(),
                tx_code: None,
                client_id: None,
                dpop_jkt: None,
                mtls_x5t_s256: None,
            })
            .await
            .expect_err("pre-authorized token disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unit-config".to_owned()],
                grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("offer creation disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
}

#[tokio::test]
async fn enabled_issuer_validates_request_shape_before_database_state() {
    let issuer = operations(true).await;
    assert_eq!(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("malformed offer identifier")
            .status,
        404
    );
    assert_eq!(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed credential JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed deferred JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unknown".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("unknown configuration")
            .status,
        400
    );

    let error = issuer
        .offer(&Uuid::now_v7().to_string())
        .await
        .expect_err("valid offer identifier should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );

    let error = issuer
        .nonce(None)
        .await
        .expect_err("nonce issuance should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential nonce state is unavailable.",
    );
}

#[tokio::test]
async fn access_and_notification_fail_closed_for_invalid_bearer() {
    let issuer = operations(true).await;
    let context = request_context();
    let access_error = issuer
        .access(&context)
        .await
        .expect_err("invalid bearer must not reach credential state");
    assert_error(
        access_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );

    let notify_error = issuer
        .notify(
            context,
            NotificationRequest {
                notification_id: "unit-notification".to_owned(),
                event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                event_description: Some("unit".to_owned()),
            },
        )
        .await
        .expect_err("notification requires a valid access token");
    assert_error(
        notify_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );
}

#[tokio::test]
async fn access_rejects_signed_token_for_different_tenant_before_revocation_lookup() {
    let issuer = operations(true).await;
    let other_tenant = Uuid::from_u128(0x2222);
    assert_ne!(other_tenant, issuer.tenant_id);
    let subject = Uuid::from_u128(0x3333);
    let subject_string = subject.to_string();
    let audiences = [issuer.issuer.clone()];
    let authorization_details = Value::Array(Vec::new());
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: other_tenant,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &audiences,
            scopes: &[],
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("a token from another tenant must be rejected before state access");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token tenant does not match this credential issuer.",
    );
}

#[tokio::test]
async fn access_rejects_signed_token_with_another_audience_before_state_access() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x4444);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &["https://another.example".to_owned()],
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("token for another audience must be rejected");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token is not intended for this credential issuer.",
    );
}

#[tokio::test]
async fn access_fails_closed_when_revocation_state_is_unavailable() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x5555);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: std::slice::from_ref(&issuer.issuer),
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("unavailable revocation state must fail closed");
    assert_error(error, 401, "invalid_token", "Access token is revoked.");
}

#[tokio::test]
async fn pre_authorized_token_reaches_offer_state() {
    let issuer = operations(true).await;
    let error = issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: "unit-code".to_owned(),
            tx_code: None,
            client_id: None,
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("missing offer state should fail at the persistence boundary");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );
}

#[tokio::test]
async fn create_offer_rejects_invalid_grant_shapes_and_subject_before_database_state() {
    let issuer = operations(true).await;
    let base = |grant_types: Vec<String>, tx_code: Option<&str>, subject_id| {
        CreateCredentialOfferRequest {
            subject_id,
            credential_configuration_ids: vec!["unit-config".to_owned()],
            grant_types,
            tx_code: tx_code.map(str::to_owned),
            expires_in: 300,
        }
    };

    for request in [
        base(Vec::new(), None, Uuid::nil()),
        base(vec!["unsupported".to_owned()], None, Uuid::nil()),
        base(
            vec![
                "authorization_code".to_owned(),
                "authorization_code".to_owned(),
            ],
            None,
            Uuid::nil(),
        ),
        base(
            vec!["authorization_code".to_owned()],
            Some("1234"),
            Uuid::nil(),
        ),
    ] {
        let error = issuer
            .create_offer(request)
            .await
            .expect_err("invalid grant shape must be rejected");
        assert_error(
            error,
            400,
            "invalid_request",
            "Credential offer grant types are invalid.",
        );
    }

    let error = issuer
        .create_offer(base(
            vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            None,
            Uuid::nil(),
        ))
        .await
        .expect_err("nil subject must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Credential subject is invalid.",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_immediate_offer_pre_authorized_credential_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-immediate", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-immediate".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live immediate offer should persist");
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect("live pre-authorized token should be issued");
    assert_eq!(access.token_type, "Bearer");
    assert_eq!(access.authorization_details.len(), 1);

    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live credential nonce should be issued");
    let request = jwt_credential_request("unit-live-immediate", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let response = fixture
        .issuer
        .credential(
            context.clone(),
            CredentialRequestBody::Json(request.clone()),
        )
        .await
        .expect("live immediate credential should be issued");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("immediate response notification id"),
        CredentialResponseBody::Jwt(_) => panic!("live fixture requests JSON response"),
    };
    assert!(matches!(
        &response.body,
        CredentialResponseBody::Json(CredentialResponse {
            credentials: Some(_),
            transaction_id: None,
            ..
        })
    ));

    let replay = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("identical immediate credential request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context.clone()
            },
            NotificationRequest {
                notification_id: notification_id.clone(),
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate completed".to_owned()),
            },
        )
        .await
        .expect("live immediate notification should be recorded");

    let error = fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate replay".to_owned()),
            },
        )
        .await
        .expect_err("terminal notification must not be replayed");
    assert_error(
        error,
        400,
        "invalid_notification_id",
        "Notification identifier is invalid or already terminal.",
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_deferred_credential_claim_response_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-deferred", true).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-deferred".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live deferred offer should persist");
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect("live deferred pre-authorized token should be issued");
    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live deferred credential nonce should be issued");
    let request = jwt_credential_request("unit-live-deferred", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let pending = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("live deferred credential should return a transaction");
    let transaction_id = match pending.body {
        CredentialResponseBody::Json(CredentialResponse {
            transaction_id: Some(transaction_id),
            credentials: None,
            ..
        }) => transaction_id,
        _ => panic!("live deferred response should contain a transaction id"),
    };

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let deferred_request = DeferredCredentialRequest {
        transaction_id,
        credential_response_encryption: None,
    };
    let deferred_context = CredentialRequestContext {
        request_url: "/openid4vci/deferred_credential".to_owned(),
        ..context
    };
    let response = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request.clone()),
        )
        .await
        .expect("live deferred credential should be released");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("deferred response notification id"),
        CredentialResponseBody::Jwt(_) => panic!("live fixture requests JSON response"),
    };
    assert!(matches!(
        &response.body,
        CredentialResponseBody::Json(CredentialResponse {
            credentials: Some(_),
            transaction_id: None,
            ..
        })
    ));

    let replay = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request),
        )
        .await
        .expect("identical deferred request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..deferred_context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live deferred completed".to_owned()),
            },
        )
        .await
        .expect("live deferred notification should be recorded");
    fixture.cleanup().await;
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    total: i64,
}

#[derive(diesel::QueryableByName)]
struct ActiveFlagRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_active: bool,
}

#[derive(diesel::QueryableByName)]
struct TokenIdRow {
    #[diesel(sql_type = SqlUuid)]
    token_id: Uuid,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_pre_authorized_uuid_access_resolves_without_generic_issuance_row() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-standalone-access", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-standalone-access".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("standalone offer should persist");
    // Anonymous wallet entry: no registered client identity, so persistence
    // skips the client lock entirely and issues a UUID-subject access token.
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: None,
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect("standalone pre-authorized token should be issued");

    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("standalone access fixture database connection");
    let grants = sql_query("SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1")
        .bind::<SqlUuid, _>(fixture.subject_id)
        .load::<TokenIdRow>(&mut connection)
        .await
        .expect("standalone access grant lookup");
    assert_eq!(grants.len(), 1, "exactly one access grant should persist");
    let issuances = sql_query(
        "SELECT count(*) AS total FROM oauth_token_issuances WHERE access_token_jti = $1",
    )
    .bind::<Text, _>(grants[0].token_id.to_string())
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("generic issuance lookup should succeed");
    assert_eq!(
        issuances.total, 0,
        "standalone pre-authorized access must not create a generic issuance row"
    );
    drop(connection);

    fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: access.access_token,
            ..request_context()
        })
        .await
        .expect("UUID subject must resolve without a generic issuance row");
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_pre_authorized_rejects_inactive_subject_after_offer_consumption() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-inactive-subject", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-inactive-subject".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("inactive-subject offer should persist");
    let code = pre_authorized_code(&offer);
    // Deactivate the subject directly so the still-unconsumed offer reaches the
    // subject-activity check inside the token operation.
    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("inactive-subject fixture database connection");
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(fixture.subject_id)
        .execute(&mut connection)
        .await
        .expect("inactive-subject fixture user update");
    drop(connection);

    let request = |code: &str| PreAuthorizedTokenRequest {
        pre_authorized_code: code.to_owned(),
        tx_code: None,
        client_id: Some(fixture.wallet_client_id.clone()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };
    let error = fixture
        .issuer
        .pre_authorized_token(request(&code))
        .await
        .expect_err("an inactive subject must reject the pre-authorized grant");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Credential subject is inactive.",
    );

    let error = fixture
        .issuer
        .pre_authorized_token(request(&code))
        .await
        .expect_err("the consumed offer must not be replayable");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Pre-authorized code or transaction code is invalid.",
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_pre_authorized_rejects_client_deactivated_before_persistence() {
    let Some(database_url) = std::env::var("NAZO_TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
    else {
        return;
    };
    let wrapper_pool =
        nazo_postgres::create_pool(database_url, 2).expect("deactivating store pool should build");
    let store: Arc<dyn nazo_persistence::Openid4vciStore> = Arc::new(ClientDeactivatingStore {
        inner: Arc::new(nazo_postgres::Openid4vciRepository::new(
            wrapper_pool.clone(),
            [0x51; 32],
        )),
        pool: wrapper_pool,
    });
    let Some(fixture) = LiveEndpointFixture::new_with_overrides(
        "unit-live-client-deactivation",
        false,
        Some(store),
        None,
    )
    .await
    else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-client-deactivation".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("client-deactivation offer should persist");
    let code = pre_authorized_code(&offer);

    // The deactivating store flips the registered client to inactive inside the
    // persistence call, reproducing the window after offer consumption where
    // the earlier authentication check can no longer see the client state.
    let error = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: code.clone(),
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("a client deactivated before persistence must not be issued a token");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "unauthorized_client");
    assert_eq!(error.description, "Credential client is inactive.");

    // The token endpoint presents this failure as an HTTP 400
    // unauthorized_client body carrying no token material and no challenge.
    let response = nazo_http_actix::pre_authorized_token_error_response(error);
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .is_none(),
        "unauthorized_client carries no WWW-Authenticate challenge"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("pre-authorized error body should collect");
    let body: Value = serde_json::from_slice(&body).expect("pre-authorized error body is JSON");
    assert_eq!(body["error"], "unauthorized_client");
    assert_eq!(body["error_description"], "Credential client is inactive.");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());

    let mut connection = nazo_postgres::get_conn(&fixture.pool)
        .await
        .expect("client-deactivation fixture database connection");
    let grants =
        sql_query("SELECT count(*) AS total FROM openid4vci_access_grants WHERE subject_id = $1")
            .bind::<SqlUuid, _>(fixture.subject_id)
            .get_result::<CountRow>(&mut connection)
            .await
            .expect("access grant count should query");
    assert_eq!(
        grants.total, 0,
        "no access grant may be persisted for a deactivated client"
    );
    let client =
        sql_query("SELECT is_active FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(fixture.wallet_client_id.clone())
            .get_result::<ActiveFlagRow>(&mut connection)
            .await
            .expect("wallet client row should exist");
    assert!(
        !client.is_active,
        "the fixture deactivation must be visible"
    );
    drop(connection);

    let error = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: code,
            tx_code: None,
            client_id: Some(fixture.wallet_client_id.clone()),
            dpop_jkt: None,
            mtls_x5t_s256: None,
        })
        .await
        .expect_err("the consumed offer must not be replayable");
    assert_error(
        error,
        400,
        "invalid_grant",
        "Pre-authorized code or transaction code is invalid.",
    );
    fixture.cleanup().await;
}

#[path = "openid4vci_endpoint_operations_policy.rs"]
mod policy;
