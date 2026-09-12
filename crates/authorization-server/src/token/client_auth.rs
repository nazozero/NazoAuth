//! token 管理端点复用的客户端认证。
use crate::crypto::blake3_hex;
use crate::crypto::client_secret_digest;
use crate::domain::client_policy::refresh_client_jwks;
use crate::domain::rows::ClientRow;
use crate::security::client_assertion::ClientAssertionError;
use crate::security::client_assertion::verify_private_key_jwt_claims_for_issuer;
use nazo_auth::PresentedClientCredentials as ClientCredentials;
use nazo_auth::ValidatedClientAssertion;

use crate::contracts::token_client_auth::ClientCertificateFacts;
use crate::security::mtls::client_mtls_certificate_matches;

use jsonwebtoken::decode_header;

use crate::contracts::dynamic_client_registration::RemoteJwksResolverPort;
use nazo_auth::{
    ClientAuthenticationContext, ClientAuthenticationPolicyError, ClientAuthenticationRequirement,
    client_authentication_requirement,
};

pub enum TokenManagementClientAuthError {
    InvalidClient,
    PublicClientCredentialsForbidden,
    StoreUnavailable,
}

#[derive(Clone, Debug)]
pub struct ClientAuthRequestFacts {
    endpoint_path: String,
    client_certificate: Option<ClientCertificateFacts>,
}

impl ClientAuthRequestFacts {
    pub fn new(
        endpoint_path: impl Into<String>,
        client_certificate: Option<ClientCertificateFacts>,
    ) -> Self {
        Self {
            endpoint_path: endpoint_path.into(),
            client_certificate,
        }
    }

    pub fn endpoint_path(&self) -> &str {
        &self.endpoint_path
    }
}

#[derive(Clone, Copy)]
pub struct ClientAuthConfig<'a> {
    issuer: &'a str,
    client_secret_pepper: &'a str,
    endpoint_audience_aliases: &'a [&'a str],
    remote_jwks: &'a dyn RemoteJwksResolverPort,
    audit: &'a dyn crate::ports::audit::SecurityAudit,
}

impl<'a> ClientAuthConfig<'a> {
    pub fn new(
        issuer: &'a str,
        client_secret_pepper: &'a str,
        remote_jwks: &'a dyn RemoteJwksResolverPort,
        audit: &'a dyn crate::ports::audit::SecurityAudit,
    ) -> Self {
        Self {
            issuer,
            client_secret_pepper,
            endpoint_audience_aliases: &[],
            remote_jwks,
            audit,
        }
    }

    pub fn with_endpoint_audience_aliases(mut self, aliases: &'a [&'a str]) -> Self {
        self.endpoint_audience_aliases = aliases;
        self
    }
}

fn dummy_client_secret_salt(client_id: Option<&str>) -> String {
    blake3_hex(client_id.unwrap_or(""))
}

/// Equalizes the CPU work for an unknown secret-authenticated client without touching storage.
/// The result is deliberately consumed so release optimization cannot remove the calculation.
pub fn perform_dummy_client_secret_verification(
    credentials: &ClientCredentials,
    client_secret_pepper: &str,
) {
    if matches!(
        credentials.method.as_str(),
        "client_secret_basic" | "client_secret_post"
    ) && let Some(secret) = credentials.client_secret.as_deref()
    {
        let dummy_salt = dummy_client_secret_salt(credentials.client_id.as_deref());
        drop(std::hint::black_box(client_secret_digest(
            secret,
            client_secret_pepper,
            &dummy_salt,
        )));
    }
}

#[allow(dead_code)]
pub async fn authenticate_introspection_client_with_dependencies(
    service: &crate::services::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &mut ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        request,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
        config.audit,
    )
    .await
    .map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

#[allow(dead_code)]
pub async fn authenticate_revocation_client_with_dependencies(
    service: &crate::services::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &mut ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        request,
        client,
        credentials,
        ClientAuthenticationContext::AllowPublicNone,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
        config.audit,
    )
    .await
}

pub async fn authenticate_client_with_dependencies(
    service: &crate::services::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &mut ClientRow,
    credentials: &ClientCredentials,
    context: ClientAuthenticationContext,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let requirement =
        client_authentication_requirement(client, credentials, context).map_err(|error| {
            log_client_auth_rejection(request, client, credentials, "policy");
            match error {
                ClientAuthenticationPolicyError::InvalidClient => {
                    TokenManagementClientAuthError::InvalidClient
                }
                ClientAuthenticationPolicyError::PublicClientCredentialsForbidden => {
                    TokenManagementClientAuthError::PublicClientCredentialsForbidden
                }
            }
        })?;

    match requirement {
        ClientAuthenticationRequirement::PublicClient => Ok(None),
        ClientAuthenticationRequirement::PrivateKeyJwt { assertion } => {
            // The registered URI determines the key source; kid is only a
            // hint to the resolver, including when it is absent. Signature
            // and claim validation still happen below. Malformed
            // assertions are rejected by the existing verifier without a
            // network request.
            if let Ok(header) = decode_header(assertion) {
                refresh_client_jwks(client, config.remote_jwks, header.kid.as_deref())
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "dynamic client jwks_uri could not be refreshed");
                        TokenManagementClientAuthError::StoreUnavailable
                    })?;
            }
            verify_private_key_jwt_claims_for_issuer(
                config.issuer,
                request.endpoint_path(),
                config.endpoint_audience_aliases,
                client,
                assertion,
            )
            .map(Some)
            .map_err(|error| {
                log_client_auth_rejection(
                    request,
                    client,
                    credentials,
                    client_assertion_error_reason(&error),
                );
                token_management_client_assertion_error(error)
            })
        }
        ClientAuthenticationRequirement::ClientSecret { secret, .. } => {
            let secret_match = match service.client_secret_salt(client.id).await {
                Ok(Some(salt)) => {
                    let candidate_digest =
                        client_secret_digest(secret, config.client_secret_pepper, &salt);
                    service
                        .client_secret_digest_matches(client.id, &candidate_digest)
                        .await
                }
                Ok(None) => {
                    perform_dummy_client_secret_verification(
                        credentials,
                        config.client_secret_pepper,
                    );
                    Ok(false)
                }
                Err(error) => Err(error),
            };
            if client_secret_auth_result(secret_match)? {
                Ok(None)
            } else {
                log_client_auth_rejection(request, client, credentials, "client_secret");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
        ClientAuthenticationRequirement::MutualTls { .. } => {
            let Some(certificate) = request.client_certificate.as_ref() else {
                log_client_auth_rejection(request, client, credentials, "missing_mtls_certificate");
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            if client.token_endpoint_auth_method == "self_signed_tls_client_auth" {
                refresh_client_jwks(client, config.remote_jwks, None)
                    .await
                    .map_err(|error| {
                        tracing::warn!(%error, "dynamic client mTLS jwks_uri could not be refreshed");
                        TokenManagementClientAuthError::StoreUnavailable
                    })?;
            }
            if !client_mtls_certificate_matches(client, certificate) {
                log_client_auth_rejection(request, client, credentials, "mtls_certificate");
                return Err(TokenManagementClientAuthError::InvalidClient);
            }
            if client.token_endpoint_auth_method == "tls_client_auth"
                && !certificate.deployment_trusted_chain
            {
                let anchors =
                    service
                        .mtls_trust_anchor_bundle(client.id)
                        .await
                        .map_err(|error| {
                            tracing::warn!(%error, "failed to read tenant mTLS trust anchors");
                            TokenManagementClientAuthError::StoreUnavailable
                        })?;
                if !crate::security::mtls::certificate_chain_trusted(certificate, &anchors) {
                    log_client_auth_rejection(request, client, credentials, "mtls_trust");
                    return Err(TokenManagementClientAuthError::InvalidClient);
                }
            }
            Ok(None)
        }
    }
}

fn client_secret_auth_result<E: std::fmt::Display>(
    result: Result<bool, E>,
) -> Result<bool, TokenManagementClientAuthError> {
    result.map_err(|error| {
        tracing::warn!(%error, "failed to verify management client secret");
        TokenManagementClientAuthError::StoreUnavailable
    })
}

fn client_assertion_error_reason(error: &ClientAssertionError) -> &'static str {
    match error {
        ClientAssertionError::Invalid => "client_assertion",
        ClientAssertionError::ReplayDetected => "client_assertion_replay",
        ClientAssertionError::StoreUnavailable => "client_assertion_store",
    }
}

fn log_client_auth_rejection(
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
    reason: &'static str,
) {
    tracing::warn!(
        target: "client_auth",
        "client_auth_rejected reason={} path={} client_id_hash={} expected_method={} presented_method={}",
        reason,
        request.endpoint_path(),
        blake3_hex(&client.client_id),
        client.token_endpoint_auth_method,
        credentials.method
    );
}

pub async fn consume_token_management_client_assertion_with_authorization_service(
    service: &crate::services::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
    audit: &dyn crate::ports::audit::SecurityAudit,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::security::client_assertion::consume_private_key_jwt_with_authorization_service(
        service, client, assertion, audit,
    )
    .await
    .map_err(token_management_client_assertion_error)
}

fn token_management_client_assertion_error(
    error: ClientAssertionError,
) -> TokenManagementClientAuthError {
    match error {
        ClientAssertionError::StoreUnavailable => TokenManagementClientAuthError::StoreUnavailable,
        ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => {
            TokenManagementClientAuthError::InvalidClient
        }
    }
}

pub async fn consume_token_client_assertion_with_authorization_service(
    service: &crate::services::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
    audit: &dyn crate::ports::audit::SecurityAudit,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::security::client_assertion::consume_private_key_jwt_with_authorization_service(
        service, client, assertion, audit,
    )
    .await
    .map_err(token_management_client_assertion_error)
}

#[cfg(test)]
#[path = "../../tests/unit/token/client_auth.rs"]
mod tests;
