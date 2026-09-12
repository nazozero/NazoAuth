//! Token application dispatcher.
use crate::contracts::dynamic_client_registration::RemoteJwksResolverPort;
use crate::contracts::oauth_error::OAuthEndpointError;
use crate::contracts::token_endpoint::{
    PreparedTokenRequest, TokenEndpointSuccess, TokenRequestFacts,
};
use crate::domain::client_policy::refresh_client_jwks;
use crate::services::{ServerAuthorizationService, ServerDeviceGrantService, ServerTokenService};
use crate::token::authorization_code::token_authorization_code_with_service;
use crate::token::ciba::{CIBA_GRANT_TYPE, CibaTokenContext, CibaTokenHandles, token_ciba};
use crate::token::client_auth::{
    ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
    authenticate_client_with_dependencies,
    consume_token_client_assertion_with_authorization_service,
    perform_dummy_client_secret_verification,
};
use crate::token::client_credentials::token_client_credentials_with_service;
use crate::token::device_issuance::token_device_code_with_service;
use crate::token::issue::{TokenIssuanceConfig, TokenIssuanceContext};
use crate::token::jwt_bearer::{JWT_BEARER_GRANT_TYPE, token_jwt_bearer_with_service};
use crate::token::refresh::token_refresh_with_service;
use crate::token::token_exchange::token_exchange;
use crate::token::{DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};
use http::StatusCode;
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthenticationContext,
    PresentedClientCredentials as ClientCredentials, token_client_authentication_context,
    unverified_client_assertion_client_id,
};
use nazo_runtime_modules::SnapshotStore;
use std::sync::Arc;
mod client_auth;
mod errors;
mod pre_authorized;
mod rate_limit;
pub use client_auth::validate_token_request_profile;
use client_auth::{
    attestation_client_id_matches_form_hint, missing_client_authorization_code_holder_error,
    validate_token_client_enabled,
};
use errors::client_credentials_holder_missing_client_error;
use pre_authorized::pre_authorized_parameters;

pub struct TokenEndpointHandles {
    core: TokenCoreHandles,
    ciba: CibaTokenHandles,
    issuance_config: Arc<TokenIssuanceConfig>,
    runtime_modules: Arc<SnapshotStore>,
    remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
    openid4vc: Openid4vcTokenHandles,
}
pub struct TokenCoreHandles {
    pub token_service: Arc<ServerTokenService>,
    pub authorization_service: Arc<ServerAuthorizationService>,
    pub device_service: Arc<ServerDeviceGrantService>,
    pub security_audit: Arc<dyn crate::ports::audit::SecurityAudit>,
}
#[derive(Default)]
pub struct Openid4vcTokenHandles {
    pub credential_issuer:
        Option<Arc<dyn nazo_openid4vci::application::CredentialIssuerOperations>>,
    pub client_attestation: Option<
        Arc<crate::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator>,
    >,
}
impl TokenEndpointHandles {
    pub fn new(
        core: TokenCoreHandles,
        ciba: CibaTokenHandles,
        issuance_config: Arc<TokenIssuanceConfig>,
        runtime_modules: Arc<SnapshotStore>,
        remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
        openid4vc: Openid4vcTokenHandles,
    ) -> Self {
        Self {
            core,
            ciba,
            issuance_config,
            runtime_modules,
            remote_client_documents,
            openid4vc,
        }
    }
    pub async fn enforce_rate_limit(&self, source_ip: &str) -> Result<(), OAuthEndpointError> {
        rate_limit::enforce_token_rate_limit(
            self.core.authorization_service.as_ref(),
            self.issuance_config.as_ref(),
            source_ip,
        )
        .await
    }
    pub async fn execute(
        &self,
        prepared: PreparedTokenRequest,
        facts: TokenRequestFacts<'_>,
    ) -> Result<TokenEndpointSuccess, OAuthEndpointError> {
        let token_service = self.core.token_service.as_ref();
        let authorization_service = self.core.authorization_service.as_ref();
        let issuance_config = self.issuance_config.as_ref();
        let device_service = self.core.device_service.as_ref();
        let runtime_modules = self.runtime_modules.as_ref();
        let form = prepared.parsed.form;
        let mut pre_authorized = prepared.parsed.pre_authorized;
        let auth_facts = prepared.auth;
        let client_auth_context = token_client_authentication_context(auth_facts.presentation())
            .expect("prepared token authentication sources were validated");
        let has_client_attestation_material = facts.client_attestation.any_header_present;
        let has_mtls_material = facts.certificate.is_some();

        if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {
            let preauth_has_authenticated_client_material = client_auth_context
                .has_any_client_auth_material
                || has_client_attestation_material
                || has_mtls_material;
            if preauth_has_authenticated_client_material {
                // Authenticated OpenID4VCI pre-authorized-code clients must flow
                // through the shared token endpoint client-authentication path below
                // so private_key_jwt, mTLS, and client-attestation identities are
                // verified before they become the issuance client_id.
            } else {
                let Some(endpoint) = self.openid4vc.credential_issuer.as_ref() else {
                    return Err(OAuthEndpointError::token(
                        StatusCode::BAD_REQUEST,
                        "unsupported_grant_type",
                        "OpenID4VCI pre-authorized issuance is not configured.",
                        false,
                    ));
                };
                let (pre_authorized_code, tx_code) =
                    match pre_authorized_parameters(&mut pre_authorized) {
                        Ok(parameters) => parameters,
                        Err(response) => return Err(response),
                    };
                let response = endpoint
                    .pre_authorized_token(nazo_openid4vci::application::PreAuthorizedTokenRequest {
                        pre_authorized_code,
                        tx_code,
                        client_id: form.client_id.clone(),
                        dpop_proof: facts.first_dpop_header.map(ToOwned::to_owned),
                        client_attestation: facts
                            .client_attestation
                            .first_attestation
                            .map(ToOwned::to_owned),
                        client_attestation_pop: facts
                            .client_attestation
                            .first_pop
                            .map(ToOwned::to_owned),
                        request_url: format!(
                            "{}{}",
                            issuance_config.issuer().trim_end_matches('/'),
                            facts.request_target
                        ),
                    })
                    .await;
                return match response {
                    Ok(response) => Ok(TokenEndpointSuccess::PreAuthorized(response)),
                    Err(error) => Err(OAuthEndpointError::PreAuthorized(error)),
                };
            }
        }

        if form.grant_type == "password" {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Resource owner password credentials are not supported.",
                false,
            ));
        }
        let attestation_headers = match facts.client_attestation.strict_pair {
            Ok(headers) => headers,
            Err(()) => {
                return Err(OAuthEndpointError::token(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Exactly one of each client attestation header is required.",
                    false,
                ));
            }
        };
        if attestation_headers.is_some()
            && (client_auth_context.http_basic
                || client_auth_context.has_assertion
                || form.client_secret.is_some())
        {
            return Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Client attestation cannot be combined with another client authentication method.",
                false,
            ));
        }
        let has_basic = client_auth_context.http_basic;
        let has_client_auth_material = client_auth_context.has_any_client_auth_material;
        let assertion_client_id = auth_facts
            .client_assertion()
            .filter(|_| {
                auth_facts.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
            })
            .and_then(unverified_client_assertion_client_id);
        let form_mtls_client_id =
            if !has_basic && !client_auth_context.has_assertion && form.client_secret.is_none() {
                form.client_id
                    .as_ref()
                    .filter(|_| facts.certificate.is_some())
                    .cloned()
            } else {
                None
            };
        let mut credentials =
            auth_facts.presented_credentials(assertion_client_id, form_mtls_client_id);
        if let Some((attestation, _)) = attestation_headers {
            credentials = ClientCredentials {
            client_id: crate::domain::openid4vc::client_attestation::Openid4vcClientAttestationValidator::unverified_client_id(
                attestation,
            ),
            client_secret: None,
            client_assertion: None,
            method: "attest_jwt_client_auth".to_owned(),
        };
        }
        let Some(client_id) = credentials.client_id.as_deref() else {
            if !has_client_auth_material {
                if let Some(response) =
                    client_credentials_holder_missing_client_error(&form, facts.dpop.proof_present)
                {
                    return Err(response);
                }
                if let Some(response) = missing_client_authorization_code_holder_error(
                    token_service,
                    authorization_service,
                    &form,
                )
                .await
                {
                    return Err(response);
                }
            }
            return Err(OAuthEndpointError::token(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "客户端认证失败.",
                has_basic,
            ));
        };
        let mut client = match authorization_service.client_by_id(client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                perform_dummy_client_secret_verification(
                    &credentials,
                    issuance_config.client_secret_pepper(),
                );
                return Err(OAuthEndpointError::token(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端不存在或已停用.",
                    has_basic,
                ));
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query oauth client for token request");
                return Err(OAuthEndpointError::token(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "客户端查询失败.",
                    false,
                ));
            }
        };
        if form.grant_type == nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT {
            if !client.is_active {
                return Err(OAuthEndpointError::token(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "客户端不存在或已停用.",
                    has_basic,
                ));
            }
        } else {
            validate_token_client_enabled(&client, &form.grant_type)?;
        }
        let auth_request = ClientAuthRequestFacts::new(facts.dpop.path, facts.certificate.clone());
        let mut client_attestation_jkt = None;
        let client_assertion = if let Some((attestation, proof)) = attestation_headers {
            if client.token_endpoint_auth_method != "attest_jwt_client_auth" {
                return Err(OAuthEndpointError::token(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation is not registered for this client.",
                    false,
                ));
            }
            let Some(validator) = self.openid4vc.client_attestation.as_ref() else {
                return Err(OAuthEndpointError::token(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client_attestation",
                    "Client attestation is not configured.",
                    false,
                ));
            };
            let validated = match validator
                .validate_for_client(
                    attestation,
                    proof,
                    issuance_config.issuer(),
                    chrono::Utc::now().timestamp(),
                )
                .await
            {
                Ok(validated) if validated.client_id == client.client_id => validated,
                _ => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client_attestation",
                        "Client attestation validation failed.",
                        false,
                    ));
                }
            };
            if !attestation_client_id_matches_form_hint(
                form.client_id.as_deref(),
                &validated.client_id,
            ) {
                return Err(OAuthEndpointError::token(
                    StatusCode::UNAUTHORIZED,
                    "invalid_client",
                    "Token request client_id does not match the client attestation.",
                    false,
                ));
            }
            client_attestation_jkt = Some(validated.client_instance_key_thumbprint.clone());
            let replay_key = format!("client-attestation:{}", validated.client_id);
            match authorization_service
                .consume_private_key_jwt(
                    &replay_key,
                    &validated.replay_id,
                    validated.replay_ttl_seconds,
                )
                .await
            {
                Ok(true) => None,
                Ok(false) => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client_attestation",
                        "Client attestation proof was replayed.",
                        false,
                    ));
                }
                Err(_) => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "Client attestation replay state is unavailable.",
                        false,
                    ));
                }
            }
        } else {
            match authenticate_client_with_dependencies(
                authorization_service,
                ClientAuthConfig::new(
                    issuance_config.issuer(),
                    issuance_config.client_secret_pepper(),
                    self.remote_client_documents.as_ref(),
                    self.core.security_audit.as_ref(),
                )
                .with_endpoint_audience_aliases(std::slice::from_ref(
                    &issuance_config.mtls_endpoint_base_url(),
                )),
                &auth_request,
                &mut client,
                &credentials,
                ClientAuthenticationContext::AllowPublicNone,
            )
            .await
            {
                Ok(assertion) => assertion,
                Err(TokenManagementClientAuthError::PublicClientCredentialsForbidden) => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "public 客户端不能使用 client_secret.",
                        has_basic,
                    ));
                }
                Err(TokenManagementClientAuthError::InvalidClient) => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::UNAUTHORIZED,
                        "invalid_client",
                        "客户端认证失败.",
                        has_basic && credentials.method != "private_key_jwt",
                    ));
                }
                Err(TokenManagementClientAuthError::StoreUnavailable) => {
                    return Err(OAuthEndpointError::token(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "客户端认证状态不可用.",
                        false,
                    ));
                }
            }
        };
        validate_token_request_profile(&client, client.token_endpoint_auth_method.as_str())?;
        if matches!(
            form.grant_type.as_str(),
            "authorization_code" | "refresh_token"
        ) && (client.id_token_encrypted_response_alg.is_some()
            || client.id_token_encrypted_response_enc.is_some())
            && let Err(error) =
                refresh_client_jwks(&mut client, self.remote_client_documents.as_ref(), None).await
        {
            tracing::warn!(%error, "id_token encryption jwks_uri could not be refreshed");
            return Err(OAuthEndpointError::token(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端加密密钥不可用.",
                false,
            ));
        }
        let modules = runtime_modules.load_full();
        let issuance = TokenIssuanceContext {
            config: issuance_config,
            modules: &modules,
            authorization: authorization_service,
            security_audit: self.core.security_audit.as_ref(),
            remote_client_documents: self.remote_client_documents.as_ref(),
        };
        match form.grant_type.as_str() {
            "authorization_code" => {
                token_authorization_code_with_service(
                    token_service,
                    &issuance,
                    &facts,
                    &client,
                    &form,
                    client_assertion.as_ref(),
                    client_attestation_jkt.as_deref(),
                )
                .await
            }
            "refresh_token" => {
                token_refresh_with_service(
                    token_service,
                    &issuance,
                    &facts,
                    &client,
                    &form,
                    client_assertion.as_ref(),
                    client_attestation_jkt.as_deref(),
                )
                .await
            }
            "client_credentials" => {
                token_client_credentials_with_service(
                    token_service,
                    authorization_service,
                    &issuance,
                    &facts,
                    &client,
                    &form,
                    client_assertion.as_ref(),
                )
                .await
            }
            JWT_BEARER_GRANT_TYPE => {
                token_jwt_bearer_with_service(
                    token_service,
                    &issuance,
                    &facts,
                    &mut client,
                    &form,
                    client_assertion.as_ref(),
                )
                .await
            }
            DEVICE_CODE_GRANT_TYPE => {
                token_device_code_with_service(
                    token_service,
                    &issuance,
                    device_service,
                    &facts,
                    &client,
                    &form,
                    client_assertion.as_ref(),
                )
                .await
            }
            CIBA_GRANT_TYPE => {
                token_ciba(
                    CibaTokenContext {
                        token_service,
                        issuance: &issuance,
                        handles: &self.ciba,
                        request: &facts,
                    },
                    &client,
                    &form,
                    client_assertion.as_ref(),
                    client.token_endpoint_auth_method.as_str(),
                )
                .await
            }
            nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT => {
                let Some(endpoint) = self.openid4vc.credential_issuer.as_ref() else {
                    return Err(OAuthEndpointError::token(
                        StatusCode::BAD_REQUEST,
                        "unsupported_grant_type",
                        "OpenID4VCI pre-authorized issuance is not configured.",
                        false,
                    ));
                };
                let (pre_authorized_code, tx_code) =
                    match pre_authorized_parameters(&mut pre_authorized) {
                        Ok(parameters) => parameters,
                        Err(response) => return Err(response),
                    };
                if let Err(error) = consume_token_client_assertion_with_authorization_service(
                    authorization_service,
                    &client,
                    client_assertion.as_ref(),
                    issuance.security_audit,
                )
                .await
                {
                    return Err(crate::token::token_client_assertion_error(error));
                }
                match endpoint
                    .pre_authorized_token(nazo_openid4vci::application::PreAuthorizedTokenRequest {
                        pre_authorized_code,
                        tx_code,
                        client_id: Some(client.client_id.clone()),
                        dpop_proof: facts.first_dpop_header.map(ToOwned::to_owned),
                        client_attestation: facts
                            .client_attestation
                            .first_attestation
                            .map(ToOwned::to_owned),
                        client_attestation_pop: facts
                            .client_attestation
                            .first_pop
                            .map(ToOwned::to_owned),
                        request_url: format!(
                            "{}{}",
                            issuance_config.issuer().trim_end_matches('/'),
                            facts.request_target
                        ),
                    })
                    .await
                {
                    Ok(response) => Ok(TokenEndpointSuccess::PreAuthorized(response)),
                    Err(error) => Err(OAuthEndpointError::PreAuthorized(error)),
                }
            }
            TOKEN_EXCHANGE_GRANT_TYPE => {
                token_exchange(
                    token_service,
                    authorization_service,
                    &issuance,
                    &facts,
                    &client,
                    &form,
                    client_assertion.as_ref(),
                )
                .await
            }
            _ => Err(OAuthEndpointError::token(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "不支持的 grant_type.",
                false,
            )),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/token/dispatch_policy.rs"]
mod policy_tests;
