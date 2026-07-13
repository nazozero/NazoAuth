use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::HttpRequest;
use chrono::Utc;
use nazo_auth::{ClientAuthenticationContext, IntrospectionSignInput, OAuthClient};
use nazo_http_actix::{
    TokenIntrospectionRepresentation, TokenManagementError, TokenManagementFuture,
    TokenManagementOperations, TokenManagementRateLimitError, TokenManagementRequestGuard,
    TokenOnlyForm,
};
use serde_json::json;

use crate::{
    http::{
        authorization::{AuthorizationHttpConfig, ServerAuthorizationService},
        token::{
            ServerTokenService,
            client_auth::{
                ClientAuthConfig, TokenManagementClientAuthError,
                authenticate_introspection_client_with_dependencies,
                authenticate_revocation_client_with_dependencies,
                perform_dummy_client_secret_verification,
            },
        },
    },
    support::{
        audit::{audit_event, audit_fields},
        client_ip::client_ip_with_config,
        jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe},
        security::{
            blake3_hex, extract_client_credentials_with_trusted_proxies,
            has_basic_authorization_scheme,
        },
    },
};

#[derive(Clone)]
pub(crate) struct ServerTokenManagementRequestGuard {
    token_service: Arc<ServerTokenService>,
    config: Arc<AuthorizationHttpConfig>,
}

impl ServerTokenManagementRequestGuard {
    pub(crate) fn new(
        token_service: Arc<ServerTokenService>,
        config: Arc<AuthorizationHttpConfig>,
    ) -> Self {
        Self {
            token_service,
            config,
        }
    }
}

impl TokenManagementRequestGuard for ServerTokenManagementRequestGuard {
    fn enforce<'a>(
        &'a self,
        request: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>> {
        let subject = client_ip_with_config(request, &self.config.client_ip);
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
pub(crate) struct ServerTokenManagementOperations {
    token_service: Arc<ServerTokenService>,
    authorization_service: Arc<ServerAuthorizationService>,
    config: Arc<AuthorizationHttpConfig>,
}

impl ServerTokenManagementOperations {
    pub(crate) fn new(
        token_service: Arc<ServerTokenService>,
        authorization_service: Arc<ServerAuthorizationService>,
        config: Arc<AuthorizationHttpConfig>,
    ) -> Self {
        Self {
            token_service,
            authorization_service,
            config,
        }
    }

    async fn authenticate(
        &self,
        request: &HttpRequest,
        form: &TokenOnlyForm,
        context: ClientAuthenticationContext,
    ) -> Result<OAuthClient, TokenManagementError> {
        let has_basic = has_basic_authorization_scheme(request.headers());
        let credentials = extract_client_credentials_with_trusted_proxies(
            request,
            &self.config.trusted_proxy_cidrs,
            form.client_id.as_deref(),
            form.client_secret.as_deref(),
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
        );
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Err(TokenManagementError::InvalidClient {
                basic_challenge: has_basic,
            });
        };
        let client = match self.authorization_service.client_by_id(client_id).await {
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
            &self.config.trusted_proxy_cidrs,
        );
        let result = match context {
            ClientAuthenticationContext::ConfidentialOnly => {
                authenticate_introspection_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    request,
                    &client,
                    &credentials,
                )
                .await
            }
            ClientAuthenticationContext::AllowPublicNone => {
                authenticate_revocation_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    request,
                    &client,
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
        request: &'a HttpRequest,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
        Box::pin(async move {
            let client = self
                .authenticate(
                    request,
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
            if signed_response_requested && self.config.profile.requires_signed_introspection() {
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
        request: &'a HttpRequest,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()> {
        Box::pin(async move {
            let client = self
                .authenticate(request, &form, ClientAuthenticationContext::AllowPublicNone)
                .await?;
            let updated = self
                .token_service
                .revoke_token(&self.config.issuer, &form.token, &client)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to revoke token");
                    TokenManagementError::RevocationUnavailable
                })?;
            audit_event(
                "token_revoked",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("token_hash", json!(blake3_hex(&form.token))),
                    ("updated", json!(updated)),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(
                            request,
                            &self.config.client_ip,
                        ))),
                    ),
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
