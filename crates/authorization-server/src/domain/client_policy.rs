//! Database-row and client-key adapters for framework-independent OAuth policy.
use crate::contracts::dynamic_client_registration::RemoteJwksResolverPort;
use crate::domain::rows::ClientRow;

pub use nazo_auth::{
    RedirectUriError, is_subset, is_valid_pkce_value, parse_resource_indicators, parse_scope,
    string_array_values as json_array_to_strings,
};
pub fn client_supports_grant(client: &ClientRow, grant_type: &str) -> bool {
    client.grant_types.iter().any(|grant| grant == grant_type)
}

pub fn audiences_allowed(client: &ClientRow, audiences: &[String]) -> bool {
    !audiences.is_empty() && nazo_auth::is_subset(audiences, &client.allowed_audiences)
}

pub fn registered_redirect_uri(
    client: &ClientRow,
    requested_redirect_uri: Option<&str>,
) -> Result<String, RedirectUriError> {
    nazo_auth::resolve_registered_redirect_uri(
        &client.client_type,
        &client.redirect_uris,
        requested_redirect_uri,
    )
}

/// Refresh a request-local client snapshot from its registered JWKS URI.
///
/// A client without a registered URI keeps its persisted JWKS and never
/// invokes the resolver.  The caller remains responsible for mapping resolver
/// failures to the endpoint-specific protocol error.
pub async fn refresh_client_jwks(
    client: &mut ClientRow,
    resolver: &dyn RemoteJwksResolverPort,
    expected_kid: Option<&str>,
) -> Result<(), String> {
    let Some(uri) = client.jwks_uri.as_deref() else {
        return Ok(());
    };
    client.jwks = Some(resolver.resolve(uri, expected_kid).await?);
    Ok(())
}

/// Refresh response-encryption keys when the selected response is configured
/// for JWE. Callers may invoke this unconditionally after computing the
/// selected response's predicate, so unrelated response policies never cause
/// a resolver call.
pub async fn refresh_client_jwks_for_encryption(
    client: &mut ClientRow,
    resolver: &dyn RemoteJwksResolverPort,
    response_encryption_configured: bool,
) -> Result<(), String> {
    if !response_encryption_configured {
        return Ok(());
    }
    refresh_client_jwks(client, resolver, None).await
}

#[cfg(test)]
#[path = "../../tests/unit/domain/client_policy/oauth_client_jwks.rs"]
mod oauth_client_jwks_tests;
