#[cfg(not(test))]
use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(not(test))]
use actix_web::HttpRequest;
#[cfg(not(test))]
use nazo_auth::{
    AdminClientCryptoPort, AdminClientPolicy, CreateClientRequest, PreparedClientRegistration,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};
#[cfg(not(test))]
use nazo_http_actix::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError,
    DynamicRegistrationEndpoint, DynamicRegistrationEndpointConfig, DynamicRegistrationFuture,
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
    DynamicRegistrationSecurity,
};
#[cfg(not(test))]
use serde_json::{Value, json};
#[cfg(not(test))]
use uuid::Uuid;

#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;
#[cfg(not(test))]
use crate::support::{
    audit::{audit_event, audit_fields},
    client_ip::{ClientIpConfig, client_ip_with_config},
    oauth::{
        client_jwks_contains_signing_key, client_jwks_matching_encryption_key_count,
        validate_client_jwks_with_missing_kid_policy, validate_self_signed_mtls_jwks,
    },
    sector_identifier::fetch_sector_identifier_uris,
    security::{
        blake3_hex, client_secret_digest, constant_time_eq, hash_client_secret,
        random_urlsafe_token,
    },
};
use crate::support::{client_ip::ClientIpHeaderMode, client_ip::IpCidr};

#[derive(Clone)]
pub(crate) struct DynamicRegistrationConfig {
    pub(crate) issuer: String,
    pub(crate) default_audience: String,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) client_secret_pepper: String,
    pub(crate) initial_access_token: Option<String>,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) rate_limit_max_requests: u64,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for DynamicRegistrationConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let identity = &settings.identity;
        let modules = &settings.modules;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            default_audience: protocol.default_audience.to_owned(),
            pairwise_subject_secret: protocol
                .pairwise_subject_secret
                .as_deref()
                .map(ToOwned::to_owned),
            client_secret_pepper: protocol.client_secret_pepper.to_owned(),
            initial_access_token: modules
                .dynamic_client_registration_initial_access_token
                .as_deref()
                .map(ToOwned::to_owned),
            rate_limit_window_seconds: identity.rate_limit.window_seconds,
            rate_limit_max_requests: identity.rate_limit.token_management_max_requests,
            client_ip_header_mode: endpoint.client_ip_header_mode,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct DynamicRegistrationHandles {
    pub(crate) config: DynamicRegistrationConfig,
    pub(crate) clients: nazo_postgres::OAuthClientRepository,
    pub(crate) rate_limits: nazo_valkey::RateLimitStore,
    pub(crate) keyset: nazo_key_management::KeyManager,
    pub(crate) enabled: bool,
}

#[cfg(test)]
impl DynamicRegistrationHandles {
    pub(crate) fn accepts_new_requests(&self) -> bool {
        self.enabled
    }

    pub(crate) fn from_app_state(state: &super::AppState) -> Self {
        Self {
            config: DynamicRegistrationConfig::from(state.settings.as_ref()),
            clients: nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            rate_limits: nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            keyset: state.keyset.clone(),
            enabled: state.settings.modules.enable_dynamic_client_registration,
        }
    }
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct ServerDynamicRegistrationClientStore {
    repository: nazo_postgres::OAuthClientRepository,
}

#[cfg(not(test))]
impl ServerDynamicRegistrationClientStore {
    pub(crate) fn new(repository: nazo_postgres::OAuthClientRepository) -> Self {
        Self { repository }
    }
}

#[cfg(not(test))]
impl DynamicRegistrationClientStore for ServerDynamicRegistrationClientStore {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        Box::pin(async move {
            nazo_auth::insert_prepared_client(&self.repository, prepared)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to insert dynamically registered client");
                    DynamicRegistrationDependencyError::Unavailable
                })
        })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<nazo_auth::OAuthClient>> {
        Box::pin(async move {
            self.repository
                .by_registration_access_token(tenant_id, client_id, token_hash)
                .await
                .map_err(|error| dependency_error("query registration access token", error))
        })
    }

    fn has_client_secret(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            self.repository
                .has_client_secret(client_id)
                .await
                .map_err(|error| dependency_error("inspect client secret", error))
        })
    }

    fn client_secret_salt(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async move {
            self.repository
                .client_secret_salt(client_id)
                .await
                .map_err(|error| dependency_error("load client secret salt", error))
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            self.repository
                .client_secret_digest_matches(client_id, candidate_digest)
                .await
                .map_err(|error| dependency_error("verify client secret", error))
        })
    }

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        Box::pin(async move {
            self.repository
                .rotate_credentials(
                    tenant_id,
                    client_id,
                    client_secret_hash,
                    registration_access_token_hash,
                )
                .await
                .map_err(|error| dependency_error("rotate client credentials", error))
        })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a nazo_auth::OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, nazo_auth::OAuthClient> {
        Box::pin(async move {
            self.repository
                .replace_registration(client, client_secret_hash, registration_access_token_hash)
                .await
                .map_err(|error| dependency_error("replace client registration", error))
        })
    }

    fn deactivate(&self, tenant_id: Uuid, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            self.repository
                .deactivate(tenant_id, client_id)
                .await
                .map_err(|error| dependency_error("deactivate client", error))
        })
    }
}

#[cfg(not(test))]
fn dependency_error(
    operation: &'static str,
    error: nazo_identity::ports::RepositoryError,
) -> DynamicRegistrationDependencyError {
    tracing::warn!(%error, operation, "dynamic registration repository operation failed");
    DynamicRegistrationDependencyError::Unavailable
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct ServerDynamicRegistrationSecurity {
    keyset: nazo_key_management::KeyManager,
}

#[cfg(not(test))]
impl ServerDynamicRegistrationSecurity {
    pub(crate) fn new(keyset: nazo_key_management::KeyManager) -> Self {
        Self { keyset }
    }
}

#[cfg(not(test))]
impl SectorIdentifierResolverPort for ServerDynamicRegistrationSecurity {
    fn resolve<'a>(&'a self, uri: &'a str) -> SectorIdentifierFuture<'a> {
        Box::pin(async move {
            fetch_sector_identifier_uris(uri)
                .await
                .map_err(|error| format!("{error:?}"))
        })
    }
}

#[cfg(not(test))]
impl AdminClientCryptoPort for ServerDynamicRegistrationSecurity {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.keyset
            .snapshot()
            .response_signing_alg_values_supported()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String> {
        validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
            .map_err(|error| error.to_string())
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        client_jwks_contains_signing_key(jwks)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        validate_self_signed_mtls_jwks(jwks)
    }
}

#[cfg(not(test))]
impl DynamicRegistrationSecurity for ServerDynamicRegistrationSecurity {
    fn prepare_registration<'a>(
        &'a self,
        request: CreateClientRequest,
        policy: AdminClientPolicy,
        registration_access_token: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<PreparedClientRegistration, nazo_auth::AdminClientError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut prepared =
                nazo_auth::prepare_client_registration(request, &policy, self, self).await?;
            prepared.registration_access_token_blake3 = Some(blake3_hex(registration_access_token));
            Ok(prepared)
        })
    }

    fn random_token(&self) -> String {
        random_urlsafe_token()
    }

    fn token_hash(&self, token: &str) -> String {
        blake3_hex(token)
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        <Self as AdminClientCryptoPort>::issue_client_secret(self, pepper)
    }

    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
        client_secret_digest(secret, pepper, salt)
    }

    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        constant_time_eq(left, right)
    }
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct ServerDynamicRegistrationRequestGuard {
    rate_limits: nazo_valkey::RateLimitStore,
    window_seconds: u64,
    max_requests: u64,
    client_ip: ClientIpConfig,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}

#[cfg(not(test))]
impl ServerDynamicRegistrationRequestGuard {
    pub(crate) fn new(
        rate_limits: nazo_valkey::RateLimitStore,
        config: &DynamicRegistrationConfig,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            rate_limits,
            window_seconds: config.rate_limit_window_seconds,
            max_requests: config.rate_limit_max_requests,
            client_ip: ClientIpConfig::new(
                &config.trusted_proxy_cidrs,
                config.client_ip_header_mode,
            ),
            runtime_modules,
        }
    }
}

#[cfg(not(test))]
impl DynamicRegistrationRequestGuard for ServerDynamicRegistrationRequestGuard {
    fn accepts_new_requests(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::DynamicClientRegistration,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    fn enforce_rate_limit<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        let subject = client_ip_with_config(request, &self.client_ip);
        Box::pin(async move {
            let count = self
                .rate_limits
                .increment(
                    nazo_valkey::RateDimension::TokenManagement,
                    &subject,
                    self.window_seconds,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "dynamic registration rate-limit increment failed");
                    DynamicRegistrationRateLimitError::Unavailable
                })?;
            if count > self.max_requests {
                return Err(DynamicRegistrationRateLimitError::Limited {
                    retry_after_seconds: self.window_seconds,
                });
            }
            Ok(())
        })
    }

    fn audit(&self, event: &'static str, client: &nazo_auth::OAuthClient, request: &HttpRequest) {
        audit_event(
            event,
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("client_type", json!(client.client_type)),
                ("grant_types", json!(client.grant_types)),
                (
                    "token_endpoint_auth_method",
                    json!(client.token_endpoint_auth_method),
                ),
                (
                    "source_ip_hash",
                    json!(blake3_hex(&client_ip_with_config(request, &self.client_ip))),
                ),
            ]),
        );
    }
}

#[cfg(not(test))]
pub(crate) fn dynamic_registration_endpoint(
    config: DynamicRegistrationConfig,
    clients: nazo_postgres::OAuthClientRepository,
    rate_limits: nazo_valkey::RateLimitStore,
    keyset: nazo_key_management::KeyManager,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
) -> DynamicRegistrationEndpoint {
    let security = Arc::new(ServerDynamicRegistrationSecurity::new(keyset));
    let request_guard = Arc::new(ServerDynamicRegistrationRequestGuard::new(
        rate_limits,
        &config,
        runtime_modules,
    ));
    DynamicRegistrationEndpoint::new(
        DynamicRegistrationEndpointConfig {
            issuer: config.issuer,
            default_audience: config.default_audience,
            pairwise_subject_secret: config.pairwise_subject_secret,
            client_secret_pepper: config.client_secret_pepper,
            initial_access_token: config.initial_access_token,
        },
        Arc::new(ServerDynamicRegistrationClientStore::new(clients)),
        security,
        request_guard,
    )
}
