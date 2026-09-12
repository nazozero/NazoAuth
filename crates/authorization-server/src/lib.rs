#![forbid(unsafe_code)]

//! Host-independent application capabilities.

pub mod authorization;
pub mod contracts;
pub mod crypto;
pub mod domain;
pub mod policy;
pub mod ports;
pub mod rate_limit;
pub mod security;
pub mod services;
pub mod sessions;
pub mod token;

pub mod workers;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
