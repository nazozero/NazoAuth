#![forbid(unsafe_code)]
//! Tokio scheduling for the same NazoAuth runtime in standalone and embedded hosts.
//!
//! Hosts supply configured I/O ports and own their listeners. This adapter owns
//! tenant and process task lifetimes; it has no HTTP framework or storage driver.

mod backchannel_logout;
mod ciba_ping;
mod directory;
mod key_lifecycle;
mod runtime;
mod runtime_modules;
mod security_state;
mod tenant;

pub use runtime::{ProcessWorkers, Runtime};
pub use runtime_modules::StoredTransactionLifecycle;
pub use tenant::TenantTasks;
