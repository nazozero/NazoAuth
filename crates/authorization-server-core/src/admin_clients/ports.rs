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

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient>;

    /// Administrative creation accepts only a current active administrator in
    /// the client context. Client insertion and canonical Required outcome share
    /// one owner; a secret-bearing receipt requires the complete commit ACK.
    /// Unsupported adapters fail before mutation and never call bare insert.
    fn insert_with_required_audit<'a>(
        &'a self,
        _client: &'a OAuthClient,
        _client_secret_hash: Option<&'a str>,
        _registration_access_token_blake3: Option<&'a str>,
        _actor_id: Uuid,
        _source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unavailable) })
    }

    /// A confidential-to-public authentication-class change must atomically
    /// invalidate every existing refresh family of this client. Issuance and
    /// mutation serialize on the same client authority before family state;
    /// discarded confidential replay proofs cannot become public authority.
    /// Retain revoked rows and durable revocation evidence; failure rolls back
    /// both the class change and the invalidation.
    /// Atomically compare all current semantic metadata with the snapshot used
    /// to prepare this patch before applying it; return Conflict on mismatch.
    /// This port carries no current admin principal or hierarchy proof.
    fn update<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
    ) -> AdminClientFuture<'a, OAuthClient>;

    /// Retains the exact snapshot CAS and dependent invalidation contract of
    /// update while holding current admin authority through canonical audit ACK.
    fn update_with_required_audit<'a>(
        &'a self,
        _expected: &'a OAuthClient,
        _client: &'a OAuthClient,
        _actor_id: Uuid,
        _source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async { Err(AdminClientPortError::Unavailable) })
    }
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

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.as_ref()
            .insert(client, client_secret_hash, registration_access_token_blake3)
    }

    fn update<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.as_ref().update(expected, client)
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
            client, client_secret_hash, registration_access_token_blake3,
            actor_id, source_ip_hash,
        )
    }

    fn update_with_required_audit<'a>(
        &'a self,
        expected: &'a OAuthClient,
        client: &'a OAuthClient,
        actor_id: Uuid,
        source_ip_hash: &'a str,
    ) -> AdminClientFuture<'a, OAuthClient> {
        self.as_ref().update_with_required_audit(expected, client, actor_id, source_ip_hash)
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
    fn validate_jwks(&self, jwks: &Value) -> Result<(), String>;
    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String>;
    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize;
    fn contains_signing_key(&self, jwks: &Value) -> bool;
    fn contains_signing_key_for_algorithm(&self, jwks: &Value, algorithm: &str) -> bool {
        let _ = algorithm;
        self.contains_signing_key(jwks)
    }
    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool;
}
