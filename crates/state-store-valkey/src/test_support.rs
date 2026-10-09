//! Raw Valkey harness for application contract tests.
//!
//! Production code must use focused stores rather than these raw inspection
//! primitives.

pub use fred::interfaces::{ClientLike, KeysInterface};
pub use fred::prelude::{
    Builder, Client, Config, ConnectionConfig, Error, Expiration, LuaInterface, PerformanceConfig,
};

use nazo_identity::TenantId;
use std::time::Duration;
use uuid::Uuid;

const TEST_DEPLOYMENT_ID: &str = "test";
const TEST_STATE_EPOCH: Uuid = Uuid::from_u128(0x019c_8ca2_30a6_7000_8000_0000_0000_0001);
const TEST_TENANT_ID: Uuid = Uuid::from_u128(1);

fn test_tenant_id() -> TenantId {
    TenantId::new(TEST_TENANT_ID).expect("fixed test tenant is non-nil")
}

/// Prefix an inspected business key with the fixed explicit test namespace.
/// Raw test clients never receive an unscoped business key.
#[must_use]
pub fn state_storage_key(key: impl AsRef<str>) -> String {
    storage_key(TEST_DEPLOYMENT_ID, TEST_STATE_EPOCH, test_tenant_id(), key)
        .expect("fixed test state namespace is valid")
}

/// Derive a physical key for a raw inspector from the same namespace boundary
/// production construction uses. This is test-only evidence, not a second
/// key-building API for application code.
pub fn storage_key(
    deployment_id: &str,
    state_epoch: Uuid,
    tenant_id: TenantId,
    key: impl AsRef<str>,
) -> Result<String, crate::Error> {
    Ok(format!(
        "{}{}",
        crate::connection::state_namespace(deployment_id, state_epoch, tenant_id)?,
        key.as_ref()
    ))
}

/// Derive a deployment-scoped, non-tenant cache key for raw contract tests.
pub fn deployment_storage_key(
    deployment_id: &str,
    state_epoch: Uuid,
    key: impl AsRef<str>,
) -> Result<String, crate::Error> {
    Ok(format!(
        "{}{}",
        crate::connection::deployment_namespace(deployment_id, state_epoch)?,
        key.as_ref()
    ))
}

/// Inspect the exact production attestation replay key without duplicating
/// its namespace or digest format in an application test.
#[must_use]
pub fn client_attestation_replay_storage_key(client_id: &str, jti: &str) -> String {
    state_storage_key(crate::keys::client_attestation_replay(client_id, jti))
}

/// Inspect the production JAR replay key without repeating its derivation.
#[must_use]
pub fn jar_replay_storage_key(client_id: &str, jti: &str) -> String {
    state_storage_key(crate::keys::jar_replay(client_id, jti))
}

/// Inspect the production CIBA request-object replay key.
#[must_use]
pub fn ciba_request_object_replay_storage_key(client_id: &str, jti: &str) -> String {
    state_storage_key(crate::keys::ciba_request_object_replay(client_id, jti))
}

/// Returns the actual storage key used for a PAR request URI.
///
/// This is intentionally exposed only through the raw test harness so
/// corruption and atomic-consumption contract tests do not duplicate key
/// derivation logic.
#[must_use]
pub fn par_storage_key(request_uri: &str) -> String {
    state_storage_key(crate::keys::par(request_uri))
}

/// Returns the production consent key for raw-version and corruption tests.
#[must_use]
pub fn consent_storage_key(request_id: &str) -> String {
    state_storage_key(crate::keys::consent(request_id))
}

/// Returns the actual storage key used for an OIDC federation state token.
///
/// Raw cross-crate tests use this to inject malformed or legacy state without
/// copying production key derivation.
#[must_use]
pub fn oidc_federation_storage_key(state: &str) -> String {
    state_storage_key(crate::keys::oidc_federation(state))
}

/// Inspect social callback state using the owning key and namespace derivation.
#[must_use]
pub fn social_federation_storage_key(state: &str) -> String {
    state_storage_key(crate::keys::social_federation(state))
}

/// Returns the actual storage key used for a CIBA authentication request.
///
/// Raw cross-crate tests use this to inspect or inject state without copying
/// the production hashing and namespace contract.
#[must_use]
pub fn ciba_request_storage_key(auth_req_id: &str) -> String {
    state_storage_key(crate::keys::ciba(auth_req_id))
}

/// Inspect device state without duplicating its hash or namespace derivation.
#[must_use]
pub fn device_code_storage_key(device_code: &str) -> String {
    state_storage_key(crate::keys::device_code(device_code))
}

/// Inspect the normalized user-code mapping used by the device store.
#[must_use]
pub fn device_user_code_storage_key(user_code: &str) -> String {
    state_storage_key(crate::keys::device_user_code(user_code))
}

/// Returns the actual storage key used for an authorization code.
///
/// Raw cross-crate tests use this to inspect state transitions without
/// duplicating the production hashing and namespace contract.
#[must_use]
pub fn authorization_code_storage_key(code: &str) -> String {
    state_storage_key(crate::keys::authorization_code(code))
}

pub async fn connect(url: &str, timeout: Duration) -> Result<Client, Error> {
    let mut builder = Builder::from_config(Config::from_url(url)?);
    builder.with_performance_config(|config: &mut PerformanceConfig| {
        config.default_command_timeout = timeout;
    });
    builder.with_connection_config(|config: &mut ConnectionConfig| {
        config.connection_timeout = timeout;
        config.internal_command_timeout = timeout;
        config.max_command_attempts = 1;
    });
    let client = builder.build()?;
    client.init().await?;
    Ok(client)
}

/// Construct a scoped store connection for tests. Production construction has
/// no test fallback and always receives the deployment epoch from startup.
pub fn scoped_connection(client: Client) -> crate::ValkeyConnection {
    tenant_scoped_connection(client, test_tenant_id())
}

/// Construct a connection in the fixed test deployment and epoch for an
/// explicit tenant. Cross-tenant contract tests use this without duplicating
/// production namespace construction.
pub fn tenant_scoped_connection(client: Client, tenant_id: TenantId) -> crate::ValkeyConnection {
    crate::ValkeyConnection::from_existing_client(
        client,
        TEST_DEPLOYMENT_ID,
        TEST_STATE_EPOCH,
        tenant_id,
    )
    .expect("fixed test state namespace is valid")
}

pub async fn scoped_connect(
    url: &str,
    timeout: Duration,
) -> Result<crate::ValkeyConnection, crate::Error> {
    let client = connect(url, timeout)
        .await
        .map_err(crate::Error::from_fred)?;
    Ok(scoped_connection(client))
}

/// Exact scoped key for testing legacy reauthentication-state migration.
pub fn reauth_nonce_storage_key(nonce: &str) -> String {
    state_storage_key(crate::keys::reauth_nonce(nonce))
}
