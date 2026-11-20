#![forbid(unsafe_code)]
//! D1 primary-database adapters for one NazoAuth tenant.

mod audit;
mod clients;
mod db;
mod keys;
mod maintenance;
mod modules;
mod passkeys;
mod persistence;
mod profile;
mod provider;
mod rows;
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
}

impl D1Provider {
    pub fn new(database: Database, tenant_id: nazo_identity::TenantId) -> Self {
        Self {
            database,
            tenant_id: tenant_id.as_uuid(),
        }
    }
}
