#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
#[path = "../tests/support/macros.rs"]
mod test_macros;

mod adapters;
pub mod bootstrap;
pub mod cli;
pub mod config;
mod control_discovery;
pub mod controller_registry;
#[cfg(test)]
#[path = "../tests/unit/domain.rs"]
mod domain;
mod http;
mod jobs;
mod keyctl;
pub mod operator_task;
pub mod recovery_root;
mod runtime_modules;
#[cfg(test)]
#[path = "../tests/support/schema.rs"]
mod schema;
mod settings;
mod tenant_resource_preparation;

pub mod launchers;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;
