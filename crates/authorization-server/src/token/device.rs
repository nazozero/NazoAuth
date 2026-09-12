//! RFC 8628 Device Authorization Grant application operations.
use super::client_auth::{
    ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
    authenticate_client_with_dependencies,
    consume_token_management_client_assertion_with_authorization_service,
};
use super::{DEVICE_CODE_GRANT_TYPE, device_config::DeviceConfig};
use crate::contracts::{
    device::{
        DeviceAuthorizationForm, DeviceAuthorizationResponse, DeviceVerificationData,
        PreparedDeviceAuthorization,
    },
    dynamic_client_registration::RemoteJwksResolverPort,
    oauth_error::OAuthEndpointError,
};
use crate::crypto::{blake3_hex, random_urlsafe_token};
use crate::domain::client_policy::{client_supports_grant, parse_scope};
use crate::domain::rows::ClientRow;
use crate::ports::audit::{SecurityAudit, audit_fields};
use crate::rate_limit::TokenManagementRequestLimiter;
use crate::services::{ServerAuthorizationService, ServerDeviceGrantService};
use crate::sessions::CurrentSession;
use chrono::Utc;
use http::StatusCode;
use nazo_auth::{
    CapabilityAdmission, ClientAuthenticationContext, DeviceAuthorizationApproval,
    DeviceAuthorizationPayload, DeviceAuthorizationRequestError, DeviceAuthorizationRequestPolicy,
    DeviceDecisionFailure, DeviceGrantRepositoryPort,
    PresentedClientCredentials as ClientCredentials,
};
use nazo_runtime_modules::SnapshotStore;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub struct DeviceDecisionHandles {
    authorization_service: Arc<ServerAuthorizationService>,
    device_service: Arc<ServerDeviceGrantService>,
    grant_repository: Arc<dyn DeviceGrantRepositoryPort>,
    config: Arc<DeviceConfig>,
    runtime: Arc<SnapshotStore>,
    remote_jwks: Arc<dyn RemoteJwksResolverPort>,
    limiter: Arc<TokenManagementRequestLimiter>,
    audit: Arc<dyn SecurityAudit>,
}
impl DeviceDecisionHandles {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_service: Arc<ServerAuthorizationService>,
        device_service: Arc<ServerDeviceGrantService>,
        grant_repository: Arc<dyn DeviceGrantRepositoryPort>,
        config: Arc<DeviceConfig>,
        runtime: Arc<SnapshotStore>,
        remote_jwks: Arc<dyn RemoteJwksResolverPort>,
        limiter: Arc<TokenManagementRequestLimiter>,
        audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            authorization_service,
            device_service,
            grant_repository,
            config,
            runtime,
            remote_jwks,
            limiter,
            audit,
        }
    }
    pub fn check_admission(
        &self,
        admission: CapabilityAdmission,
    ) -> Result<(), OAuthEndpointError> {
        if nazo_auth::module_admissible(
            self.runtime.load_full().as_ref(),
            nazo_runtime_modules::ModuleId::DeviceAuthorization,
            admission,
        ) {
            Ok(())
        } else {
            Err(device_authorization_request_error(
                DeviceAuthorizationRequestError::Disabled,
            ))
        }
    }
    pub async fn enforce_creation_rate_limit(
        &self,
        source_ip: &str,
    ) -> Result<(), OAuthEndpointError> {
        self.limiter.enforce(source_ip).await
    }
    pub async fn create(
        &self,
        prepared: PreparedDeviceAuthorization,
        credentials: ClientCredentials,
        auth_request: ClientAuthRequestFacts,
        source_ip: &str,
    ) -> Result<DeviceAuthorizationResponse, OAuthEndpointError> {
        let (form, has_basic) = prepared.into_parts();
        let client_id = form
            .client_id
            .as_deref()
            .expect("prepared request has client_id");
        let authorization_service = self.authorization_service.as_ref();
        let device_service = self.device_service.as_ref();
        let config = self.config.as_ref();
        if has_basic && credentials.method != "client_secret_basic" {
            return Err(OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            ));
        }
        let mut client = match authorization_service.client_by_id(client_id).await {
            Ok(Some(client)) if client.is_active => client,
            Ok(_) => {
                crate::token::client_auth::perform_dummy_client_secret_verification(
                    &credentials,
                    &config.client_secret_pepper,
                );
                return Err(OAuthEndpointError::json(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端认证失败.",
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query device authorization client");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "客户端查询失败.",
                ));
            }
        };
        authenticate_device_authorization_client(
            authorization_service,
            config,
            &auth_request,
            &mut client,
            &credentials,
            self.remote_jwks.as_ref(),
            self.audit.as_ref(),
        )
        .await?;
        if !client.security_policy.allow_cross_device_flows {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "该客户端未授权使用跨设备流程.",
            ));
        }
        let payload = match device_authorization_request_payload(config, &client, &form, true) {
            Ok(payload) => payload,
            Err(error) => return Err(device_authorization_request_error(error)),
        };
        let (device_code, user_code) = match device_service
            .create_unique(
                &payload,
                config.ttl_seconds,
                random_urlsafe_token,
                random_device_user_code,
            )
            .await
        {
            Ok(codes) => codes,
            Err(error) => {
                tracing::warn!(%error, "failed to persist device authorization state");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "设备授权状态写入失败.",
                ));
            }
        };
        self.audit.record(
            "device_authorization_started",
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("scope", json!(payload.scopes.join(" "))),
                ("audience", json!(payload.resource_indicators)),
                ("source_ip_hash", json!(blake3_hex(source_ip))),
            ]),
        );
        let verification_uri = device_verification_uri(config);
        Ok(DeviceAuthorizationResponse {
            device_code,
            verification_uri_complete: format!(
                "{verification_uri}?user_code={}",
                urlencoding::encode(&user_code)
            ),
            user_code,
            verification_uri,
            expires_in: config.ttl_seconds,
            interval: config.poll_interval_seconds,
        })
    }
    pub async fn verification(&self, user_code: &str) -> DeviceVerificationData {
        let normalized_user_code = normalize_user_code(user_code);
        let payload = if normalized_user_code.is_empty() {
            None
        } else {
            match self
                .device_service
                .pending_request_for_user_code(&normalized_user_code, Utc::now)
                .await
            {
                Ok(payload) => payload,
                Err(error) => {
                    tracing::warn!(%error, "failed to read device authorization request");
                    None
                }
            }
        };
        DeviceVerificationData {
            user_code: user_code.to_owned(),
            request: payload,
        }
    }
    pub async fn decide(
        &self,
        user_code: &str,
        decision: &str,
        session: CurrentSession,
        source_ip: &str,
    ) -> Result<(), OAuthEndpointError> {
        let authorization_service = self.authorization_service.as_ref();
        let device_service = self.device_service.as_ref();
        let grant_repository = self.grant_repository.as_ref();
        let config = self.config.as_ref();
        let normalized_user_code = normalize_user_code(user_code);
        if normalized_user_code.is_empty() {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "用户码无效或已过期.",
            ));
        }
        let payload = match device_service
            .pending_request_for_user_code(&normalized_user_code, Utc::now)
            .await
        {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                return Err(OAuthEndpointError::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "用户码无效或已过期.",
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "failed to read device authorization state for user decision");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "设备授权状态读取失败.",
                ));
            }
        };
        let decision_name = match decision {
            "approve" => "approve",
            "deny" => "deny",
            _ => {
                return Err(OAuthEndpointError::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "授权决策无效.",
                ));
            }
        };
        if let Err(error) = self.audit.ensure_storage().await {
            tracing::error!(%error, "device decision audit preflight failed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权审计存储不可用.",
            ));
        }
        if let Err(error) = self
            .audit
            .record_required(
                "device_decision_intent",
                audit_fields(&[
                    ("client_id", json!(payload.client_id.clone())),
                    ("user_id", json!(session.user.id())),
                    ("decision", json!(decision_name)),
                    ("decision_source", json!("user")),
                    ("user_code_hash", json!(blake3_hex(&normalized_user_code))),
                    ("scope", json!(payload.scopes.join(" "))),
                    ("audience", json!(payload.resource_indicators.clone())),
                    ("source_ip_hash", json!(blake3_hex(source_ip))),
                ]),
            )
            .await
        {
            tracing::error!(%error, "device decision audit intent failed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权审计无法持久化.",
            ));
        }
        let result = match decision {
            "deny" => device_service.deny(&normalized_user_code, Utc::now).await,
            "approve" => {
                let client = match authorization_service.client_by_id(&payload.client_id).await {
                    Ok(Some(client)) if client.is_active => client,
                    Ok(_) => {
                        return Err(OAuthEndpointError::json(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "用户码无效或已过期.",
                        ));
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to load device authorization client for approval");
                        return Err(OAuthEndpointError::json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "客户端查询失败.",
                        ));
                    }
                };
                let subject = match device_authorization_subject(config, session.user.id(), &client)
                {
                    Ok(subject) => subject,
                    Err(error) => {
                        tracing::warn!(%error, "failed to compute device authorization subject");
                        return Err(OAuthEndpointError::json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "授权主体计算失败.",
                        ));
                    }
                };
                device_service
                    .approve(
                        &normalized_user_code,
                        DeviceAuthorizationApproval {
                            user_id: session.user.id(),
                            subject,
                            auth_time: session.auth_time,
                            amr: session.amr.clone(),
                            oidc_sid: Some(session.oidc_sid.clone()),
                        },
                        &client,
                        grant_repository,
                        Utc::now,
                    )
                    .await
            }
            _ => unreachable!("validated device decision must be approve or deny"),
        };
        // The required intent is persisted before the transient-state/database decision
        // saga. The committed outcome remains best-effort because those stores
        // cannot atomically include the audit ledger.
        match result {
            Ok(()) => {
                let event = match decision {
                    "approve" => "device_authorization_approved",
                    "deny" => "device_authorization_denied",
                    _ => unreachable!("validated device decision must be approve or deny"),
                };
                self.audit.record(
                    event,
                    audit_fields(&[
                        ("client_id", json!(payload.client_id)),
                        ("user_id", json!(session.user.id())),
                        ("user_code_hash", json!(blake3_hex(&normalized_user_code))),
                        ("scope", json!(payload.scopes.join(" "))),
                        ("audience", json!(payload.resource_indicators)),
                        ("source_ip_hash", json!(blake3_hex(source_ip))),
                    ]),
                );
                Ok(())
            }
            Err(
                DeviceDecisionFailure::Missing
                | DeviceDecisionFailure::AlreadyHandled
                | DeviceDecisionFailure::Expired,
            ) => Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "用户码无效或已过期.",
            )),
            Err(DeviceDecisionFailure::Storage(error)) => {
                tracing::warn!(%error, "failed to persist device authorization decision");
                Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "设备授权状态写入失败.",
                ))
            }
            Err(DeviceDecisionFailure::Repository(error)) => {
                tracing::warn!(%error, "failed to persist device authorization grant");
                Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权记录写入失败.",
                ))
            }
            Err(DeviceDecisionFailure::Contended) => Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态正忙.",
            )),
        }
    }
}
pub fn device_authorization_request_payload(
    config: &DeviceConfig,
    client: &ClientRow,
    form: &DeviceAuthorizationForm,
    enabled: bool,
) -> Result<DeviceAuthorizationPayload, DeviceAuthorizationRequestError> {
    let requested_scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
    nazo_auth::device_authorization_request_payload(DeviceAuthorizationRequestPolicy {
        enabled,
        client_active: client.is_active,
        client_supports_grant: client_supports_grant(client, DEVICE_CODE_GRANT_TYPE),
        client_id: &client.client_id,
        client_name: &client.client_name,
        requested_scopes,
        allowed_scopes: &client.scopes,
        requested_resources: form.resources.clone(),
        allowed_resources: &client.allowed_audiences,
        default_resource: &config.default_audience,
        interval_seconds: config.poll_interval_seconds,
        ttl_seconds: config.ttl_seconds,
        now: Utc::now(),
    })
}

async fn authenticate_device_authorization_client(
    authorization_service: &ServerAuthorizationService,
    config: &DeviceConfig,
    auth_request: &ClientAuthRequestFacts,
    client: &mut ClientRow,
    credentials: &ClientCredentials,
    remote_client_documents: &dyn RemoteJwksResolverPort,
    security_audit: &dyn crate::ports::audit::SecurityAudit,
) -> Result<(), OAuthEndpointError> {
    let assertion = authenticate_client_with_dependencies(
        authorization_service,
        ClientAuthConfig::new(
            &config.issuer,
            &config.client_secret_pepper,
            remote_client_documents,
            security_audit,
        )
        .with_endpoint_audience_aliases(std::slice::from_ref(
            &config.mtls_endpoint_base_url.as_ref(),
        )),
        auth_request,
        client,
        credentials,
        ClientAuthenticationContext::AllowPublicNone,
    )
    .await
    .map_err(token_management_auth_error)?;
    consume_token_management_client_assertion_with_authorization_service(
        authorization_service,
        client,
        assertion.as_ref(),
        security_audit,
    )
    .await
    .map_err(token_management_auth_error)
}

fn device_authorization_request_error(
    error: DeviceAuthorizationRequestError,
) -> OAuthEndpointError {
    match error {
        DeviceAuthorizationRequestError::Disabled => OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Device Authorization Grant is not enabled.",
        ),
        DeviceAuthorizationRequestError::UnauthorizedClient => OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 device_code 授权类型.",
        ),
        DeviceAuthorizationRequestError::InvalidScope => OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "请求的作用域超出客户端允许范围.",
        ),
        DeviceAuthorizationRequestError::InvalidTarget => OAuthEndpointError::json(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
        ),
    }
}

fn device_authorization_subject(
    config: &DeviceConfig,
    user_id: Uuid,
    client: &nazo_auth::OAuthClient,
) -> anyhow::Result<String> {
    let redirect_uri = client
        .redirect_uris
        .first()
        .cloned()
        .unwrap_or_else(|| config.issuer.to_string());
    nazo_auth::oidc_subject_for_client(
        &config.issuer,
        config.pairwise_subject_secret.as_deref(),
        user_id,
        client.subject_type.as_str(),
        client.sector_identifier_host.as_deref(),
        &redirect_uri,
    )
    .map_err(Into::into)
}

fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn random_device_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut out = String::with_capacity(9);
    let bytes = rand::random::<[u8; 8]>();
    for (idx, byte) in bytes.into_iter().enumerate() {
        if idx == 4 {
            out.push('-');
        }
        out.push(ALPHABET[(byte as usize) % ALPHABET.len()] as char);
    }
    out
}

fn token_management_auth_error(error: TokenManagementClientAuthError) -> OAuthEndpointError {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            )
        }
        TokenManagementClientAuthError::StoreUnavailable => OAuthEndpointError::json(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
        ),
    }
}
fn device_verification_uri(config: &DeviceConfig) -> String {
    format!("{}/device", config.frontend_base_url.trim_end_matches('/'))
}

#[cfg(test)]
#[path = "../../tests/unit/token/device.rs"]
mod tests;
