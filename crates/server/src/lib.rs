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
#[cfg(test)]
#[path = "../tests/unit/domain.rs"]
mod domain;
mod keyctl;
pub mod operator_task;
#[cfg(test)]
#[path = "../tests/support/schema.rs"]
mod schema;
mod settings;
mod tenant_resource_preparation;

pub mod launchers;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../tests/unit/facade_conformance.rs"]
mod facade_conformance;

#[cfg(test)]
#[path = "../tests/support/endpoint_tests/mod.rs"]
mod http;

#[cfg(test)]
#[path = "../tests/support/recovery_root.rs"]
mod recovery_root;
