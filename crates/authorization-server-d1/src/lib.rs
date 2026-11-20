#![forbid(unsafe_code)]
//! D1 primary-database adapters for one NazoAuth tenant.

mod access_requests;
mod accounts;
mod admin_clients;
mod admin_users;
mod audit;
mod avatars;
mod ciba;
mod clients;
mod db;
mod dcr;
mod delivery;
mod device;
mod digital_credentials;
mod email_verification;
mod federation;
mod grants;
mod keys;
mod logout;
mod maintenance;
mod mdoc_publication;
mod mfa;
mod modules;
mod mtls_trust;
mod passkeys;
mod persistence;
mod profile;
mod provider;
mod rows;
mod scim;
mod scim_events;
mod state;
mod tokens;
mod unavailable;

pub use db::Database;
use uuid::Uuid;

/// Prepared bindings are shared by requests; the D1 database owns atomic state.
#[derive(Clone)]
pub struct D1Provider {
    pub(crate) database: Database,
    pub(crate) tenant_id: Uuid,
    pub(crate) data_encryption_key: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
}

impl D1Provider {
    pub fn new(database: Database, tenant_id: nazo_identity::TenantId) -> Self {
        Self {
            database,
            tenant_id: tenant_id.as_uuid(),
            data_encryption_key: None,
        }
    }

    /// Supply the persistent data root used for purpose-separated TOTP encryption.
    /// Without it, seed enrollment and verification fail before any mutation.
    #[must_use]
    pub fn with_data_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.data_encryption_key = Some(std::sync::Arc::new(zeroize::Zeroizing::new(key)));
        self
    }
}
