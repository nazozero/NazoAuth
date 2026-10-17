use std::{future::Future, pin::Pin, sync::Arc};

use serde_json::Value;
use uuid::Uuid;

use crate::OAuthClient;

pub type AdminClientFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AdminClientPortError>> + Send + 'a>>;
pub type SectorIdentifierFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminClientPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for AdminClientPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "admin client repository unavailable",
            Self::Conflict => "admin client repository conflict",
            Self::CorruptData => "admin client repository returned corrupt data",
            Self::Unexpected => "unexpected admin client repository failure",
        })
    }
}

impl std::error::Error for AdminClientPortError {}

/// Persistence boundary used by administrative client use cases.
pub trait AdminClientRepositoryPort: Send + Sync {
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)>;

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>>;

    /// Administrative creation accepts only a current active administrator in
    /// the client context. Client insertion and canonical Required outcome share
    /// one owner; a secret-bearing receipt requires the complete commit ACK.
    fn insert_with_required_audit<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient>;

    /// A confidential-to-public change atomically invalidates refresh families.
    /// Compare current metadata with the preparation snapshot under the same
    /// client lock used by issuance; a mismatch returns Conflict. Current admin
    /// authority, metadata, invalidation and canonical audit commit together.
    fn update_with_required_audit<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient>;
}

impl<T> AdminClientRepositoryPort for Arc<T>
where
    T: AdminClientRepositoryPort + ?Sized,
{
    fn page(
        &self,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        self.as_ref().page(tenant_id, offset, limit)
    }

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        self.as_ref().by_client_id(tenant_id, client_id)
    }

    fn insert_with_required_audit<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.as_ref().insert_with_required_audit(
            client,
            client_secret_hash,
            registration_access_token_blake3,
            actor_id,
            source_ip_hash,
        )
    }

    fn update_with_required_audit<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.as_ref()
            .update_with_required_audit(expected, client, actor_id, source_ip_hash)
    }
}

/// External sector identifier document lookup boundary.
pub trait SectorIdentifierResolverPort: Send + Sync {
    fn resolve<'a>(&'a self, uri: &'a str) -> SectorIdentifierFuture<'a>;
}

/// Cryptographic operations are isolated from protocol validation and use-case policy.
pub trait AdminClientCryptoPort: Send + Sync {
    fn response_signing_algorithms(&self) -> Vec<String>;
    fn id_token_signing_algorithms(&self) -> Vec<String> {
        self.response_signing_algorithms()
    }
    fn issue_client_secret(&self, pepper: &str) -> (String, String);
    /// Inspect key material once. Certificate-only entries are allowed only for
    /// self_signed_tls_client_auth; signing/encryption capabilities still require
    /// usable public JWK material.
    fn inspect_jwks(
        &self,
        jwks: &Value,
        certificate_auth: bool,
    ) -> Result<ClientJwksCapabilities, String>;
    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String>;
}

/// Facts derived by the crypto adapter, reused by registration metadata and policy.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientJwksCapabilities {
    pub signing_algorithms: std::collections::BTreeSet<&'static str>,
    pub encryption_key_counts: std::collections::BTreeMap<&'static str, usize>,
    pub has_current_mtls_certificate: bool,
}
