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

#[path = "openid4vci_endpoint_operations/access.rs"]
mod access;
#[path = "openid4vci_endpoint_operations/credential.rs"]
mod credential;
#[path = "openid4vci_endpoint_operations/deferred.rs"]
mod deferred;
#[path = "openid4vci_endpoint_operations/notification.rs"]
mod notification;
#[path = "openid4vci_endpoint_operations/offer.rs"]
mod offer;
#[path = "openid4vci_endpoint_operations/pre_authorized.rs"]
mod pre_authorized;

#[path = "openid4vci_endpoint_operations_policy.rs"]
mod policy;

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
            .ok();
        let valkey_url = std::env::var("VALKEY_URL").ok();
        if database_url.is_none() || valkey_url.is_none() {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL"
            );
            return None;
        }
        let (database_url, valkey_url) = (database_url?, valkey_url?);
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
