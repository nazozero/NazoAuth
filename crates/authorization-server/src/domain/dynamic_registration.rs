use std::{future::Future, pin::Pin, sync::Arc};

use http::StatusCode;
use nazo_auth::{
    AdminClientError, AdminClientPolicy, DynamicClientRegistrationRequest,
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationError,
    DynamicRegistrationPolicy, OAuthClient, PreparedClientRegistration, RequestRateLimitBucket,
    RequestRateLimitPort, SectorIdentifierResolverPort, parse_client_configuration_update,
    prepare_dynamic_client_registration, response_types_from_client,
};
use nazo_runtime_modules::SnapshotStore;
use serde_json::{Value, json};

use crate::{
    contracts::{
        dynamic_client_registration::{
            DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
            DynamicRegistrationSecurityServices,
        },
        oauth_error::OAuthEndpointError,
    },
    crypto::{blake3_hex, constant_time_eq, random_urlsafe_token},
    ports::audit::{SecurityAudit, audit_fields},
};

#[derive(Clone)]
pub struct DynamicRegistrationConfig {
    pub tenant: nazo_identity::TenantContext,
    pub issuer: String,
    pub default_audience: String,
    pub pairwise_subject_secret: Option<String>,
    pub client_secret_pepper: String,
    pub initial_access_token: Option<String>,
    pub rate_limit_window_seconds: u64,
    pub rate_limit_max_requests: u64,
    pub id_token_signing_algs: Vec<&'static str>,
    pub response_signing_algs: Vec<&'static str>,
    pub request_object_encryption_algs: Vec<&'static str>,
    pub request_object_encryption_encs: Vec<&'static str>,
}

pub struct DynamicRegistrationResponse {
    pub client: OAuthClient,
    pub response_types: Vec<String>,
    pub issued_secret: Option<String>,
    pub issuer: String,
    pub registration_access_token: String,
}

impl std::fmt::Debug for DynamicRegistrationResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicRegistrationResponse")
            .field("client", &self.client)
            .field("response_types", &self.response_types)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("issuer", &self.issuer)
            .field("registration_access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum DynamicRegistrationResult {
    Created(DynamicRegistrationResponse),
    Read(DynamicRegistrationResponse),
    Updated(DynamicRegistrationResponse),
    Deleted,
}

pub struct DynamicRegistrationApplication {
    config: DynamicRegistrationConfig,
    clients: Arc<dyn DynamicRegistrationClientStore>,
    sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
    security: DynamicRegistrationSecurityServices,
    request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
}

impl DynamicRegistrationApplication {
    pub fn new(
        config: DynamicRegistrationConfig,
        clients: Arc<dyn DynamicRegistrationClientStore>,
        sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
        security: DynamicRegistrationSecurityServices,
        request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    ) -> Self {
        Self {
            config,
            clients,
            sector_identifiers,
            security,
            request_guard,
        }
    }

    /// Evaluate admission before parsing a create/update body, once per request.
    pub fn accepts_new_requests(&self) -> bool {
        self.request_guard.accepts_new_requests()
    }

    /// `initial_access_token` is extracted using the transport's Bearer grammar.
    pub async fn create(
        &self,
        payload: DynamicClientRegistrationRequest,
        initial_access_token: Option<&str>,
        source_ip: &str,
    ) -> Result<DynamicRegistrationResult, OAuthEndpointError> {
        self.enforce_rate_limit(source_ip).await?;
        self.authorize_initial_access(initial_access_token)?;
        let prepared = prepare_dynamic_client_registration(payload, self.registration_policy())
            .map_err(registration_error)?;
        let response_types = prepared.response_types.clone();
        let registration_access_token = self.security.registration_tokens.random_token();
        let prepared_insert = match self
            .prepare_insert(prepared, &registration_access_token, None)
            .await
        {
            Ok(prepared) => prepared,
            Err(AdminClientError::InvalidRequest(message)) => {
                return Err(registration_error(map_insert_error(message)));
            }
            Err(_) => return Err(server_error("Dynamic client registration failed.")),
        };
        let issued_secret = prepared_insert.issued_secret.clone();
        let client = self
            .clients
            .insert(&prepared_insert)
            .await
            .map_err(|_| server_error("Dynamic client registration failed."))?;
        self.request_guard
            .audit("dynamic_client_registered", &client, source_ip);
        Ok(DynamicRegistrationResult::Created(
            DynamicRegistrationResponse {
                client,
                response_types,
                issued_secret,
                issuer: self.config.issuer.clone(),
                registration_access_token,
            },
        ))
    }

    pub async fn read(
        &self,
        client_id: &str,
        registration_token: Option<&str>,
        source_ip: &str,
    ) -> Result<DynamicRegistrationResult, OAuthEndpointError> {
        self.enforce_rate_limit(source_ip).await?;
        let (current, _authenticated_token_hash, registration_access_token) = self
            .authenticate_registration_client(registration_token, client_id)
            .await?;
        let response_types = response_types_from_client(&current);
        self.request_guard
            .audit("dynamic_client_configuration_read", &current, source_ip);
        Ok(DynamicRegistrationResult::Read(
            DynamicRegistrationResponse {
                client: current,
                response_types,
                issued_secret: None,
                issuer: self.config.issuer.clone(),
                registration_access_token,
            },
        ))
    }

    pub async fn update(
        &self,
        client_id: &str,
        payload: Value,
        registration_token: Option<&str>,
        source_ip: &str,
    ) -> Result<DynamicRegistrationResult, OAuthEndpointError> {
        self.enforce_rate_limit(source_ip).await?;
        let (current, authenticated_token_hash, _) = self
            .authenticate_registration_client(registration_token, client_id)
            .await?;
        let has_secret = self
            .clients
            .has_client_secret(current.tenant_id, current.id)
            .await
            .map_err(|_| lookup_failed())?;
        let secret_matches = self
            .submitted_secret_matches(&current, &payload)
            .await
            .map_err(|_| lookup_failed())?;
        let payload =
            parse_client_configuration_update(payload, &current, has_secret, secret_matches)
                .map_err(registration_error)?;
        let registration = prepare_dynamic_client_registration(payload, self.registration_policy())
            .map_err(registration_error)?;
        let response_types = registration.response_types.clone();
        let registration_access_token = self.security.registration_tokens.random_token();
        let prepared = match self
            .prepare_insert(
                registration,
                &registration_access_token,
                Some(&current.security_policy),
            )
            .await
        {
            Ok(prepared) => prepared,
            Err(AdminClientError::InvalidRequest(message)) => {
                return Err(registration_error(map_insert_error(message)));
            }
            Err(_) => return Err(server_error("Client configuration update failed.")),
        };
        let issued_secret = prepared.issued_secret.clone();
        let mut registration = prepared.registration.clone();
        registration.security_policy = current.security_policy.clone();
        let updated = OAuthClient {
            id: current.id,
            tenant_id: current.tenant_id,
            realm_id: current.realm_id,
            organization_id: current.organization_id,
            registration,
            require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
            is_active: current.is_active,
        };
        let client = match self
            .clients
            .replace_registration(
                &updated,
                prepared.client_secret_hash.as_deref(),
                &authenticated_token_hash,
                prepared.registration_access_token_blake3.as_deref(),
            )
            .await
        {
            Ok(client) => client,
            Err(DynamicRegistrationDependencyError::StaleCredentials) => {
                return Err(registration_access_denied());
            }
            Err(DynamicRegistrationDependencyError::Unavailable) => {
                return Err(server_error("Client configuration update failed."));
            }
        };
        self.request_guard
            .audit("dynamic_client_configuration_updated", &client, source_ip);
        Ok(DynamicRegistrationResult::Updated(
            DynamicRegistrationResponse {
                client,
                response_types,
                issued_secret,
                issuer: self.config.issuer.clone(),
                registration_access_token,
            },
        ))
    }

    pub async fn delete(
        &self,
        client_id: &str,
        registration_token: Option<&str>,
        source_ip: &str,
    ) -> Result<DynamicRegistrationResult, OAuthEndpointError> {
        self.enforce_rate_limit(source_ip).await?;
        let (current, authenticated_token_hash, _) = self
            .authenticate_registration_client(registration_token, client_id)
            .await?;
        match self
            .clients
            .deactivate(current.tenant_id, current.id, &authenticated_token_hash)
            .await
        {
            Ok(true) => {}
            Err(DynamicRegistrationDependencyError::StaleCredentials) => {
                return Err(registration_access_denied());
            }
            Ok(false) | Err(DynamicRegistrationDependencyError::Unavailable) => {
                return Err(server_error("Client deletion failed."));
            }
        }
        self.request_guard
            .audit("dynamic_client_deleted", &current, source_ip);
        Ok(DynamicRegistrationResult::Deleted)
    }

    fn registration_policy(&self) -> DynamicRegistrationPolicy<'_> {
        DynamicRegistrationPolicy {
            default_audience: &self.config.default_audience,
            pairwise_subject_supported: self.config.pairwise_subject_secret.is_some(),
            id_token_signing_algs: &self.config.id_token_signing_algs,
            response_signing_algs: &self.config.response_signing_algs,
            request_object_encryption_algs: &self.config.request_object_encryption_algs,
            request_object_encryption_encs: &self.config.request_object_encryption_encs,
        }
    }

    async fn enforce_rate_limit(&self, source_ip: &str) -> Result<(), OAuthEndpointError> {
        self.request_guard
            .enforce_rate_limit(source_ip)
            .await
            .map_err(|error| match error {
                DynamicRegistrationRateLimitError::Unavailable => server_error("请求频率校验失败."),
                DynamicRegistrationRateLimitError::Limited {
                    retry_after_seconds,
                } => OAuthEndpointError::RateLimited {
                    retry_after_seconds,
                },
            })
    }

    fn authorize_initial_access(&self, actual: Option<&str>) -> Result<(), OAuthEndpointError> {
        if let (Some(actual), Some(expected)) =
            (actual, self.config.initial_access_token.as_deref())
            && self
                .security
                .registration_tokens
                .constant_time_eq(actual.as_bytes(), expected.as_bytes())
        {
            return Ok(());
        }
        Err(OAuthEndpointError::bearer(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        ))
    }

    async fn authenticate_registration_client(
        &self,
        token: Option<&str>,
        client_id: &str,
    ) -> Result<(OAuthClient, String, String), OAuthEndpointError> {
        let token = token.ok_or_else(registration_access_denied)?;
        let token_hash = self.security.registration_tokens.token_hash(token);
        match self
            .clients
            .by_registration_access_token(
                self.config.tenant.tenant_id.as_uuid(),
                client_id,
                &token_hash,
            )
            .await
        {
            Ok(Some(client)) => Ok((client, token_hash, token.to_owned())),
            Ok(None) => Err(registration_access_denied()),
            Err(_) => Err(lookup_failed()),
        }
    }

    async fn submitted_secret_matches(
        &self,
        current: &OAuthClient,
        payload: &Value,
    ) -> Result<bool, DynamicRegistrationDependencyError> {
        let Some(secret) = payload.get("client_secret").and_then(Value::as_str) else {
            return Ok(false);
        };
        let Some(salt) = self
            .clients
            .client_secret_salt(current.tenant_id, current.id)
            .await?
        else {
            return Ok(false);
        };
        let candidate = self.security.secret_digester.client_secret_digest(
            secret,
            &self.config.client_secret_pepper,
            &salt,
        );
        self.clients
            .client_secret_digest_matches(current.tenant_id, current.id, &candidate)
            .await
    }
    async fn prepare_insert(
        &self,
        mut registration: nazo_auth::PreparedDynamicClientRegistration,
        registration_access_token: &str,
        security_policy_override: Option<&nazo_auth::ClientSecurityPolicy>,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        if let Some(uri) = registration.jwks_uri.as_deref() {
            registration.jwks = Some(self.security.remote_jwks.resolve(uri, None).await.map_err(
                |error| {
                    AdminClientError::InvalidRequest(format!(
                        "jwks_uri could not be resolved: {error}"
                    ))
                },
            )?);
        }
        let mut request = registration.into_create_client_request();
        if let Some(security_policy) = security_policy_override {
            request.security_policy = security_policy.clone();
        }
        // A confidential OIDC authorization-code client can authenticate the
        // code exchange and the baseline OIDC profile permits it to operate
        // without PKCE.  Apply that ordinary protocol policy independently of
        // how the RFC 7591 initial-access token was provisioned; public clients
        // and OAuth-only registrations retain the stricter default.
        if request.client_type == "confidential"
            && request.scopes.iter().any(|scope| scope == "openid")
            && request
                .grant_types
                .iter()
                .any(|grant_type| grant_type == "authorization_code")
        {
            request.security_policy.allow_confidential_oidc_without_pkce = true;
        }
        let policy = AdminClientPolicy {
            tenant: self.config.tenant,
            pairwise_subject_secret: self.config.pairwise_subject_secret.clone(),
            client_secret_pepper: self.config.client_secret_pepper.clone(),
        };
        let mut prepared = nazo_auth::prepare_client_registration(
            request,
            &policy,
            self.sector_identifiers.as_ref(),
            self.security.crypto.as_ref(),
        )
        .await?;
        prepared.registration_access_token_blake3 = Some(
            self.security
                .registration_tokens
                .token_hash(registration_access_token),
        );
        Ok(prepared)
    }
}

fn registration_access_denied() -> OAuthEndpointError {
    OAuthEndpointError::bearer(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token is missing or invalid.",
    )
}

fn lookup_failed() -> OAuthEndpointError {
    server_error("Client configuration lookup failed.")
}

fn server_error(description: &str) -> OAuthEndpointError {
    OAuthEndpointError::json(StatusCode::SERVICE_UNAVAILABLE, "server_error", description)
}

fn registration_error(error: DynamicRegistrationError) -> OAuthEndpointError {
    OAuthEndpointError::json(StatusCode::BAD_REQUEST, error.error, error.description)
}

fn map_insert_error(message: String) -> DynamicRegistrationError {
    let error = if message.contains("redirect_uri") {
        "invalid_redirect_uri"
    } else {
        "invalid_client_metadata"
    };
    DynamicRegistrationError::new(error, message)
}

#[derive(Clone, Copy)]
pub struct ServerDynamicRegistrationTokens;

impl nazo_auth::DynamicRegistrationSecretPort for ServerDynamicRegistrationTokens {
    fn random_token(&self) -> String {
        random_urlsafe_token()
    }

    fn token_hash(&self, token: &str) -> String {
        blake3_hex(token)
    }

    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        constant_time_eq(left, right)
    }
}

#[derive(Clone)]
pub struct ServerDynamicRegistrationRequestGuard {
    rate_limits: Arc<dyn RequestRateLimitPort>,
    window_seconds: u64,
    max_requests: u64,
    runtime_modules: Arc<SnapshotStore>,
    audit: Arc<dyn SecurityAudit>,
}

impl ServerDynamicRegistrationRequestGuard {
    pub fn new(
        rate_limits: Arc<dyn RequestRateLimitPort>,
        config: &DynamicRegistrationConfig,
        runtime_modules: Arc<SnapshotStore>,
        audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            rate_limits,
            window_seconds: config.rate_limit_window_seconds,
            max_requests: config.rate_limit_max_requests,
            runtime_modules,
            audit,
        }
    }
}

impl DynamicRegistrationRequestGuard for ServerDynamicRegistrationRequestGuard {
    fn accepts_new_requests(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.load_full(),
            nazo_runtime_modules::ModuleId::DynamicClientRegistration,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    fn enforce_rate_limit<'a>(
        &'a self,
        source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        Box::pin(async move {
            let count = self
                .rate_limits
                .increment(
                    RequestRateLimitBucket::TokenManagement,
                    source_ip,
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

    fn audit(&self, event: &'static str, client: &nazo_auth::OAuthClient, source_ip: &str) {
        self.audit.record(
            event,
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("client_type", json!(client.client_type)),
                ("grant_types", json!(client.grant_types)),
                (
                    "token_endpoint_auth_method",
                    json!(client.token_endpoint_auth_method),
                ),
                ("source_ip_hash", json!(blake3_hex(source_ip))),
            ]),
        );
    }
}
