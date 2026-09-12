use std::{future::Future, pin::Pin, sync::Arc};

use crate::contracts::token_client_auth::TokenClientAuthTransportFacts;
use crate::contracts::token_forms::TokenOnlyForm;
use crate::contracts::token_management::{
    TokenIntrospectionRepresentation, TokenManagementError, TokenManagementFuture,
    TokenManagementOperations, TokenManagementRateLimitError, TokenManagementRequestFacts,
    TokenManagementRequestGuard,
};
use chrono::Utc;
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthenticationContext, IntrospectionSignInput,
    OAuthClient, unverified_client_assertion_client_id,
};
use serde_json::json;

use crate::authorization::config::AuthorizationConfig;
use crate::contracts::dynamic_client_registration::RemoteJwksResolverPort;
use crate::crypto::blake3_hex;
use crate::domain::client_jwe::JwePayloadKind;
use crate::domain::client_jwe::client_jwe_key;
use crate::domain::client_jwe::encrypt_compact_jwe;
use crate::domain::client_policy::refresh_client_jwks_for_encryption;
use crate::ports::audit::SecurityAudit;
use crate::ports::audit::audit_fields;
use crate::services::ServerAuthorizationService;
use crate::services::ServerTokenService;
use crate::token::client_auth::ClientAuthConfig;
use crate::token::client_auth::ClientAuthRequestFacts;
use crate::token::client_auth::TokenManagementClientAuthError;
use crate::token::client_auth::authenticate_introspection_client_with_dependencies;
use crate::token::client_auth::authenticate_revocation_client_with_dependencies;
use crate::token::client_auth::perform_dummy_client_secret_verification;

#[derive(Clone)]
pub struct ServerTokenManagementRequestGuard {
    token_service: Arc<ServerTokenService>,
    config: Arc<AuthorizationConfig>,
}

impl ServerTokenManagementRequestGuard {
    pub fn new(token_service: Arc<ServerTokenService>, config: Arc<AuthorizationConfig>) -> Self {
        Self {
            token_service,
            config,
        }
    }
}

impl TokenManagementRequestGuard for ServerTokenManagementRequestGuard {
    fn enforce<'a>(
        &'a self,
        request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>> {
        let subject = request.source_ip.clone();
        Box::pin(async move {
            let count = self
                .token_service
                .increment_token_management_rate(&subject, self.config.rate_limit_window_seconds)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "token management rate limit increment failed");
                    TokenManagementRateLimitError::Unavailable
                })?;
            if count > self.config.token_management_max_requests {
                return Err(TokenManagementRateLimitError::Limited {
                    retry_after_seconds: self.config.rate_limit_window_seconds,
                });
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct ServerTokenManagementOperations {
    token_service: Arc<ServerTokenService>,
    authorization_service: Arc<ServerAuthorizationService>,
    config: Arc<AuthorizationConfig>,
    remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
    audit: Arc<dyn SecurityAudit>,
}

impl ServerTokenManagementOperations {
    pub fn new(
        token_service: Arc<ServerTokenService>,
        authorization_service: Arc<ServerAuthorizationService>,
        config: Arc<AuthorizationConfig>,
        remote_client_documents: Arc<dyn RemoteJwksResolverPort>,
        audit: Arc<dyn SecurityAudit>,
    ) -> Self {
        Self {
            token_service,
            authorization_service,
            config,
            remote_client_documents,
            audit,
        }
    }

    async fn authenticate(
        &self,
        request: &TokenManagementRequestFacts,
        client_auth: &TokenClientAuthTransportFacts,
        form: &TokenOnlyForm,
        context: ClientAuthenticationContext,
    ) -> Result<OAuthClient, TokenManagementError> {
        let has_basic = client_auth.basic_challenge();
        let presentation = client_auth.presentation();
        let assertion_client_id = client_auth
            .client_assertion()
            .filter(|_| {
                client_auth.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
            })
            .and_then(unverified_client_assertion_client_id);
        let mtls_client_id = if !presentation.http_basic
            && !presentation.client_assertion_type
            && !presentation.client_assertion
            && !presentation.form_client_secret
            && request.client_certificate.is_some()
        {
            form.client_id.clone()
        } else {
            None
        };
        let credentials = client_auth.presented_credentials(assertion_client_id, mtls_client_id);
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Err(TokenManagementError::InvalidClient {
                basic_challenge: has_basic,
            });
        };
        let mut client = match self.authorization_service.client_by_id(client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                perform_dummy_client_secret_verification(
                    &credentials,
                    &self.config.client_secret_pepper,
                );
                return Err(TokenManagementError::InvalidClient {
                    basic_challenge: has_basic,
                });
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query oauth token-management client");
                return Err(TokenManagementError::ClientLookupUnavailable);
            }
        };
        let config = ClientAuthConfig::new(
            &self.config.issuer,
            &self.config.client_secret_pepper,
            self.remote_client_documents.as_ref(),
            self.audit.as_ref(),
        );
        let auth_request =
            ClientAuthRequestFacts::new(&request.endpoint_path, request.client_certificate.clone());
        let result = match context {
            ClientAuthenticationContext::ConfidentialOnly => {
                authenticate_introspection_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    &auth_request,
                    &mut client,
                    &credentials,
                )
                .await
            }
            ClientAuthenticationContext::AllowPublicNone => {
                authenticate_revocation_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    &auth_request,
                    &mut client,
                    &credentials,
                )
                .await
            }
        };
        result.map_err(|error| map_auth_error(error, has_basic))?;
        Ok(client)
    }

    async fn protected_introspection(
        &self,
        client: &OAuthClient,
        inspection: &nazo_auth::TokenInspection,
    ) -> Result<String, TokenManagementError> {
        let body = inspection.clone().into_document();
        let token = self
            .token_service
            .sign_introspection_response(IntrospectionSignInput {
                issuer: &self.config.issuer,
                audience: &client.client_id,
                body: &body,
                signing_algorithm: client.introspection_signed_response_alg.as_deref(),
            })
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to sign token introspection response");
                TokenManagementError::ResponseProtectionFailed
            })?;
        let key = client_jwe_key(
            client.jwks.as_ref(),
            client.introspection_encrypted_response_alg.as_deref(),
            client.introspection_encrypted_response_enc.as_deref(),
            "introspection",
        )
        .map_err(|error| {
            tracing::warn!(%error, "failed to resolve introspection encryption key");
            TokenManagementError::ResponseProtectionFailed
        })?;
        match key {
            Some(key) => encrypt_compact_jwe(&key, token.as_bytes(), JwePayloadKind::NestedJwt)
                .map_err(|error| {
                    tracing::warn!(%error, "failed to encrypt introspection response");
                    TokenManagementError::ResponseProtectionFailed
                }),
            None => Ok(token),
        }
    }
}

impl TokenManagementOperations for ServerTokenManagementOperations {
    fn introspect<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
        Box::pin(async move {
            let mut client = self
                .authenticate(
                    &request,
                    &client_auth,
                    &form,
                    ClientAuthenticationContext::ConfidentialOnly,
                )
                .await?;
            let inspection = self
                .token_service
                .inspect_token(&self.config.issuer, &form.token, &client, Utc::now())
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to inspect token state");
                    TokenManagementError::InspectionUnavailable
                })?;
            let response_requires_signature = signed_response_requested
                || client.security_policy.require_signed_introspection_response;
            if response_requires_signature {
                let response_encryption_configured =
                    client.introspection_encrypted_response_alg.is_some()
                        || client.introspection_encrypted_response_enc.is_some();
                refresh_client_jwks_for_encryption(
                    &mut client,
                    self.remote_client_documents.as_ref(),
                    response_encryption_configured,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "introspection encryption jwks_uri could not be refreshed");
                    TokenManagementError::ResponseProtectionFailed
                })?;
                return self
                    .protected_introspection(&client, &inspection)
                    .await
                    .map(TokenIntrospectionRepresentation::Jwt);
            }
            Ok(TokenIntrospectionRepresentation::Inspection(inspection))
        })
    }

    fn revoke<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()> {
        Box::pin(async move {
            let client = self
                .authenticate(
                    &request,
                    &client_auth,
                    &form,
                    ClientAuthenticationContext::AllowPublicNone,
                )
                .await?;
            let updated = self
                .token_service
                .revoke_token(&self.config.issuer, &form.token, &client)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to revoke token");
                    TokenManagementError::RevocationUnavailable
                })?;
            self.audit.record(
                "token_revoked",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("token_hash", json!(blake3_hex(&form.token))),
                    ("updated", json!(updated)),
                    ("source_ip_hash", json!(blake3_hex(&request.source_ip))),
                ]),
            );
            Ok(())
        })
    }
}

fn map_auth_error(
    error: TokenManagementClientAuthError,
    basic_challenge: bool,
) -> TokenManagementError {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementError::InvalidClient { basic_challenge }
        }
        TokenManagementClientAuthError::StoreUnavailable => {
            TokenManagementError::AuthenticationStoreUnavailable
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/token_management.rs"]
mod tests;
