#![forbid(unsafe_code)]

//! PostgreSQL repository adapters for NazoAuth.
//!
//! Persistence records and Diesel schema are intentionally private:
//!
//! ```compile_fail
//! use nazo_postgres::schema::users;
//! ```
//!
//! ```compile_fail
//! use nazo_postgres::rows::identity::UserRow;
//! ```

mod convert;
mod pool;
mod repositories;
pub(crate) mod rows;
pub(crate) mod schema;

pub use pool::{
    DbConnection, DbPool, DbPoolMetrics, cleanup_expired_security_state, create_pool,
    db_pool_metrics, get_conn, run_pending_migrations,
};
pub use repositories::{
    AccessRequestRepository, AuditRepository, AuthorizationRepository, FederationRepository,
    GrantAuthorization, GrantPage, GrantProjection, GrantRepository, GrantRevocation,
    MfaRepository, OAuthClientApplication, OAuthClientRepository, PasskeyRepository,
    RuntimeModuleRepository, ScimRepository, TokenRepository, UserRepository,
};
