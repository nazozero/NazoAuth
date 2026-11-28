#![forbid(unsafe_code)]
// Return the standard HTTP response directly; boxing errors would add an allocation.
#![allow(clippy::result_large_err)]
//! Framework-neutral NazoAuth embedding and HTTP integration.

pub mod capabilities;
mod composition;
pub mod config;
#[cfg(feature = "deployment-control")]
mod control;
#[cfg(feature = "deployment-control")]
mod control_discovery;
mod endpoints;
mod http;
pub mod integration;
mod openid4vc;
pub mod runtime;
mod well_known;

pub use composition::{NazoAuth, NazoAuthBuilder};
pub use integration::ConnectionFacts;

mod routes;
mod runtime_modules;

/// Focused host regression access to the production neutral implementation.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
