use super::{
    application::CibaApplication,
    policy::{
        ciba_client_assertion_algorithm_supported, ciba_invalid_request,
        validate_ciba_delivery_request, validate_ciba_request_object_presence_with_config,
        validate_ciba_security_profile_client_with_config, validate_ciba_token_request_profile,
    },
    request::{
        ciba_hint_count, ciba_selected_acr,
        validate_and_apply_ciba_request_object_claims_with_config, validate_ciba_binding_message,
    },
    state::{CIBA_GRANT_TYPE, ciba_start_audit_fields},
};
use crate::{
    contracts::{
        ciba::{BackchannelAuthenticationForm, CibaCreationResponse, PreparedCibaCreation},
        oauth_error::OAuthEndpointError,
        token_client_auth::TokenClientAuthTransportFacts,
    },
    crypto::{blake3_hex, random_urlsafe_token},
    domain::{
        client_policy::{client_supports_grant, is_subset, parse_scope, refresh_client_jwks},
        rows::ClientRow,
    },
    ports::audit::audit_fields,
    token::client_auth::{
        ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
        authenticate_client_with_dependencies,
        consume_token_management_client_assertion_with_authorization_service,
    },
};
use chrono::Utc;
use http::StatusCode;
use nazo_auth::{
    CibaCreateFailure, CibaPingNotification, CibaPingNotificationStatus, CibaRequestState,
    CibaStatus, ClientAuthenticationContext, PresentedClientCredentials, ciba_retention_deadline,
    unverified_client_assertion_client_id,
};
use serde_json::json;

pub struct PreparedCibaClient {
    form: BackchannelAuthenticationForm,
    credentials: PresentedClientCredentials,
    client: ClientRow,
}
enum GuardedCibaCreation {
    Created(String),
    ClientAuthentication(TokenManagementClientAuthError),
    RequestObjectReplay,
    RequestObjectStore,
    State(CibaCreateFailure),
}

impl CibaApplication {
    pub async fn prepare_client(
        &self,
        prepared: PreparedCibaCreation,
        transport: &TokenClientAuthTransportFacts,
        mtls_present: bool,
    ) -> Result<PreparedCibaClient, OAuthEndpointError> {
        let form = prepared.into_form();
        let assertion_client_id = transport
            .client_assertion()
            .filter(|_| {
                transport.client_assertion_type()
                    == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            })
            .and_then(unverified_client_assertion_client_id);
        let credentials = transport.presented_credentials(
            assertion_client_id,
            if mtls_present {
                form.client_id.clone()
            } else {
                None
            },
        );
        let authorization_service = &self.authorization;
        let config = &self.handles.config;
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Err(OAuthEndpointError::json(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
            ));
        };
        let client = match authorization_service.client_by_id(client_id).await {
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
                tracing::warn!(%error, "failed to query CIBA client");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "CIBA failed.",
                ));
            }
        };
        Ok(PreparedCibaClient {
            form,
            credentials,
            client,
        })
    }
    pub async fn create(
        &self,
        prepared: PreparedCibaClient,
        auth_request: ClientAuthRequestFacts,
        source_ip: &str,
    ) -> Result<CibaCreationResponse, OAuthEndpointError> {
        let PreparedCibaClient {
            mut form,
            credentials,
            mut client,
        } = prepared;
        let authorization_service = &self.authorization;
        let ciba_service = &self.handles.service;
        let users = &self.handles.users;
        let config = &self.handles.config;
        let remote_jwks = self.remote_jwks.as_ref();
        let security_audit = self.security_audit.as_ref();
        let assertion = match authenticate_client_with_dependencies(
            authorization_service,
            ClientAuthConfig::new(
                &config.issuer,
                &config.client_secret_pepper,
                remote_jwks,
                security_audit,
            )
            .with_endpoint_audience_aliases(std::slice::from_ref(
                &config.mtls_endpoint_base_url.as_ref(),
            )),
            &auth_request,
            &mut client,
            &credentials,
            ClientAuthenticationContext::ConfidentialOnly,
        )
        .await
        {
            Ok(assertion) => assertion,
            Err(error) => return Err(token_management_auth_error(error)),
        };
        if !ciba_client_assertion_algorithm_supported(assertion.as_ref()) {
            return Err(token_management_auth_error(
                TokenManagementClientAuthError::InvalidClient,
            ));
        }
        if !client_supports_grant(&client, CIBA_GRANT_TYPE) {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "该客户端未启用 CIBA 授权类型.",
            ));
        }
        if !client.security_policy.allow_cross_device_flows {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "该客户端未授权使用跨设备流程.",
            ));
        }
        if let Some(request_object) = form.request.as_deref()
            && let Ok(header) = jsonwebtoken::decode_header(request_object)
            && header.kid.is_some()
            && let Err(error) =
                refresh_client_jwks(&mut client, remote_jwks, header.kid.as_deref()).await
        {
            tracing::warn!(%error, "CIBA request object jwks_uri could not be refreshed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA request object key source is unavailable.",
            ));
        }
        validate_ciba_token_request_profile(&client, client.token_endpoint_auth_method.as_str())?;
        validate_ciba_security_profile_client_with_config(
            config,
            &client,
            client.token_endpoint_auth_method.as_str(),
        )?;
        validate_ciba_request_object_presence_with_config(config, &client, &form)?;
        let request_object_replay = match validate_and_apply_ciba_request_object_claims_with_config(
            config, &client, &mut form,
        ) {
            Ok(replay) => replay,
            Err(response) => return Err(response),
        };
        validate_ciba_binding_message(&form)?;
        validate_ciba_delivery_request(&client, &form)?;
        let scopes = parse_scope(form.scope.as_deref().unwrap_or(""));
        if !scopes.iter().any(|scope| scope == "openid") || !is_subset(&scopes, &client.scopes) {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "CIBA requires an allowed openid scope.",
            ));
        }
        if ciba_hint_count(&form) != 1 || form.login_hint.is_none() {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA requires exactly one supported user hint.",
            ));
        }
        let Some(login_hint) = form
            .login_hint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(OAuthEndpointError::json(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "CIBA requires login_hint.",
            ));
        };
        let user = match users
            .by_email(
                nazo_identity::TenantId::new(config.tenant_id)
                    .expect("configured CIBA tenant ID is non-nil"),
                login_hint,
            )
            .await
        {
            Ok(Some(user)) if user.principal.active => user,
            Ok(_) => {
                return Err(OAuthEndpointError::json(
                    StatusCode::BAD_REQUEST,
                    "unknown_user_id",
                    "CIBA login_hint does not identify an active user.",
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query CIBA login_hint user");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "CIBA failed.",
                ));
            }
        };
        let expires_in = form
            .requested_expiry_seconds
            .unwrap_or(config.auth_req_id_ttl_seconds)
            .min(config.auth_req_id_ttl_seconds);
        let acr = match ciba_selected_acr(form.acr_values.as_deref()) {
            Some(acr) => Some(acr),
            None if form.acr_values.is_some() => {
                return Err(OAuthEndpointError::json(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "CIBA acr_values is unsupported.",
                ));
            }
            None => None,
        };
        let now = Utc::now().timestamp();
        let expires_at = now.saturating_add(expires_in.min(i64::MAX as u64) as i64);
        let state_payload = CibaRequestState {
            client_id: client.client_id.clone(),
            user_id: user.id(),
            scopes,
            audiences: vec![config.default_audience.to_string()],
            acr,
            authentication_context: None,
            binding_message: form.binding_message,
            issued_at: now,
            status: CibaStatus::Pending,
            interval_seconds: config.poll_interval_seconds,
            expires_at,
            retention_expires_at: ciba_retention_deadline(expires_at),
            last_poll_at: None,
            ping_notification: if client.backchannel_token_delivery_mode == "ping" {
                Some(CibaPingNotification {
                    auth_req_id: None,
                    endpoint: client
                        .backchannel_client_notification_endpoint
                        .clone()
                        .expect("validated ping clients have a notification endpoint"),
                    client_notification_token: form.client_notification_token,
                    status: CibaPingNotificationStatus::AwaitingDecision,
                    attempts: 0,
                    next_attempt_at: None,
                })
            } else {
                None
            },
        };
        if let Err(error) = security_audit.ensure_storage().await {
            tracing::error!(%error, "CIBA authorization-start audit preflight failed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA audit storage unavailable.",
            ));
        }
        if let Err(error) = security_audit
            .record_required(
                "ciba_authorization_intent",
                audit_fields(&[
                    ("client_id", json!(state_payload.client_id)),
                    ("user_id", json!(state_payload.user_id)),
                    ("scope", json!(state_payload.scopes.join(" "))),
                    ("audience", json!(state_payload.audiences)),
                    ("source_ip_hash", json!(blake3_hex(source_ip))),
                ]),
            )
            .await
        {
            tracing::error!(%error, "CIBA authorization-start audit intent failed");
            return Err(OAuthEndpointError::json(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "CIBA authorization audit unavailable.",
            ));
        }
        let audit_state = state_payload.clone();
        let client_id = client.client_id.clone();
        let client_for_creation = client.clone();
        let authorization_service_for_creation = authorization_service.clone();
        let ciba_service_for_creation = ciba_service.clone();
        let creation = if let Err(error) =
            consume_token_management_client_assertion_with_authorization_service(
                &authorization_service_for_creation,
                &client_for_creation,
                assertion.as_ref(),
                security_audit,
            )
            .await
        {
            GuardedCibaCreation::ClientAuthentication(error)
        } else if let Some(replay) = request_object_replay {
            match authorization_service_for_creation
                .consume_ciba_request_object(&client_id, &replay.jti, replay.ttl_seconds)
                .await
            {
                Ok(true) => match ciba_service_for_creation
                    .create_unique(&state_payload, random_urlsafe_token)
                    .await
                {
                    Ok(auth_req_id) => GuardedCibaCreation::Created(auth_req_id),
                    Err(error) => GuardedCibaCreation::State(error),
                },
                Ok(false) => GuardedCibaCreation::RequestObjectReplay,
                Err(error) => {
                    tracing::warn!(%error, "failed to persist CIBA request object replay state");
                    GuardedCibaCreation::RequestObjectStore
                }
            }
        } else {
            match ciba_service_for_creation
                .create_unique(&state_payload, random_urlsafe_token)
                .await
            {
                Ok(auth_req_id) => GuardedCibaCreation::Created(auth_req_id),
                Err(error) => GuardedCibaCreation::State(error),
            }
        };
        let auth_req_id = match creation {
            GuardedCibaCreation::Created(auth_req_id) => auth_req_id,
            GuardedCibaCreation::ClientAuthentication(error) => {
                return Err(token_management_auth_error(error));
            }
            GuardedCibaCreation::RequestObjectReplay => {
                return Err(ciba_invalid_request(
                    "CIBA request object has already been used.",
                ));
            }
            GuardedCibaCreation::RequestObjectStore => {
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "CIBA failed.",
                ));
            }
            GuardedCibaCreation::State(error) => {
                tracing::warn!(%error, "failed to create CIBA auth_req_id");
                return Err(OAuthEndpointError::json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "CIBA failed.",
                ));
            }
        };
        security_audit.record(
            "ciba_authorization_started",
            ciba_start_audit_fields(&audit_state, &auth_req_id, Some(blake3_hex(source_ip))),
        );
        Ok(CibaCreationResponse {
            auth_req_id,
            expires_in,
            interval: config.poll_interval_seconds,
        })
    }
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
